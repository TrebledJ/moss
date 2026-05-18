"""
ext/example.py

Comprehensive extension exercising every major MOSS extension API.
Serves as both a functional test fixture and reference documentation.

Covers:
- Mixin: CLI flags, __post_init__, server state, injected utilities
- Processor: GET/POST/fallback dispatch, push_event, response helpers
- Handler: custom event consumption
- All req.* response methods and req.server.* attributes

Usage:
    moss -e example -p 9999
    moss -e example --exercise-flag hello --exercise-count 3 --exercise-toggle
"""

from dataclasses import dataclass, field
import json

GROUP = "example (ext/example.py)"


def _field(default, group=None, doc="", metadata={}, flags=[], choices=[], **kwargs):
    dwargs = {}
    if type(default).__name__ in ("function", "type"):
        dwargs["default_factory"] = default
    else:
        dwargs["default"] = default
    return field(**dwargs, metadata=metadata | dict(group=group, doc=doc, flags=flags, choices=choices, **kwargs))


# ── Mixin ───────────────────────────────────────────────────────────────────
# A Mixin adds CLI flags, server lifecycle hooks, and shared state.
# Every Mixin must be a @dataclass. Fields declared here become CLI arguments.
# The __post_init__ chain runs in MRO order; call super().__post_init__() at the end.

@dataclass
class ExerciseMixin:
    exercise_flag: str = _field("default", group=GROUP, flags=["--exercise-flag"],
                                doc="A string flag for the exercise extension")
    exercise_count: int = _field(1, group=GROUP, flags=["--exercise-count"],
                                 doc="An integer flag")
    exercise_toggle: bool = _field(False, group=GROUP, flags=["--exercise-toggle"],
                                   doc="A boolean toggle")
    exercise_items: list[str] = _field(list, group=GROUP, flags=["--exercise-items"],
                                       doc="Repeatable list flag, e.g. --exercise-items a --exercise-items b")

    def __post_init__(self):
        # ── Injected utilities ──────────────────────────────────────────
        # self.logger        → Python logging.Logger instance
        # self.printe(msg)   → print to stderr
        # self.printerr(msg) → print red to stderr
        # self.printstatus   → print cyan to stderr
        # self.warning(msg)  → print yellow to stderr
        # self.c             → colour constants (c.CYN, c.GRN, c.YLW, c.BLU, c.RED, c.RST)
        self.logger.info(f"ExerciseMixin initialising: flag={self.exercise_flag}, "
                         f"count={self.exercise_count}, toggle={self.exercise_toggle}")

        if self.exercise_count < 0:
            self.printerr("exercise-count must be non-negative")
            import sys
            sys.exit(1)

        # ── Server state ─────────────────────────────────────────────────
        # The merged object is both the mixin AND the ThreadingHTTPServer.
        # All HttpMossServer fields are directly accessible via self.*:
        #   self.host, self.port, self.hostname
        #   self.queue, self.processors, self.running
        #   self.supports_https, self.https_only
        #   self.filter_regex, self.correlation_regex
        #   self.enable_blocking, self.ratelimiter
        self._seen_requests = []

        if self.hostname:
            self.printstatus(f"ExerciseMixin bound to hostname: {self.hostname}")

        # ── Chain ────────────────────────────────────────────────────────
        # MUST call super().__post_init__() so the next MRO entry runs.
        super().__post_init__()


# ── Processor ───────────────────────────────────────────────────────────────
# A Processor handles incoming HTTP requests. Dispatch is by method name:
#   do_GET(req)   — handles GET requests
#   do_POST(req)  — handles POST requests
#   do_*/do_ANY   — handles ANY method
#   handle_fallback(req)  — called when no do_METHOD matches
#   get_services(server)  — returns [(path, description)] for the index page
#
# Each handler returns True if the request was fully handled, None otherwise.
# Processors are tried in order; the first one that returns True wins.

class ExerciseProcessor:
    def get_services(self, server):
        return [
            (server.exercise_flag or "/exercise", "exercise extension demo"),
        ]

    # ── GET ──────────────────────────────────────────────────────────────
    # Available response helpers on req:
    #   req.send_response_full(code, *, content=b"", mime="text/html", headers={})
    #   req.send_json(code, *, data={})
    #   req.send_error(code, message=None, explain=None)

    def do_GET(self, req):
        if req.path == "/exercise/responses":
            return self._demo_responses(req)
        if req.path == "/exercise/state":
            return self._demo_state(req)
        if req.path.startswith("/exercise/"):
            return self._handle_exercise(req)
        # Return None → let the next processor try

    def _demo_responses(self, req):
        # send_response_full with custom content, mime, extra headers
        req.send_response_full(200, content=b"<h1>Exercise</h1>", mime="text/html",
                               headers={"X-Exercise": "true"})
        return True

    def _demo_state(self, req):
        req.send_json(200, data={
            "path": req.path,
            "method": req.command,
            "client": req.client_address[0],
            "host": req.server.host,
            "port": req.server.port,
            "exercise_flag": req.server.exercise_flag,
            "exercise_count": req.server.exercise_count,
            "exercise_toggle": req.server.exercise_toggle,
            "seen": len(req.server._seen_requests),
            "supports_https": req.server.supports_https,
            "has_filter": req.server.filter_regex is not None,
            "has_correlation": req.server.correlation_regex is not None,
        })
        return True

    def _handle_exercise(self, req):
        # ── Mark IP ──────────────────────────────────────────────────────
        # req.mark_ip_bad(weight) / req.mark_ip_ok()
        # These interact with the server's BadnessRateLimiter.
        if req.server.enable_blocking:
            req.mark_ip_bad(0.5)

        # ── Matching & correlation ───────────────────────────────────────
        # req.is_match(requestline, body)     → bool (checks filter regex)
        # req.extract_correlation_id(...)      → str | None
        # These are available on every request (set during HTTP parsing).

        # ── push_event ───────────────────────────────────────────────────
        # Custom events flow through the queue to all registered Handlers.
        # The LoggingEventHandler will silently discard unknown fields;
        # register a custom Handler to consume them.
        req.push_event(
            exercise_event=True,
            exercise_path=req.path,
            exercise_body=req.body,
        )

        req.send_response_full(200, content=json.dumps({
            "seen": len(req.server._seen_requests),
            "flag": req.server.exercise_flag,
            "count": req.server.exercise_count,
        }).encode(), mime="application/json")
        return True

    # ── POST ─────────────────────────────────────────────────────────────

    def do_POST(self, req):
        if req.path == "/exercise/echo":
            # req.body contains the raw POST body (bytes)
            req.send_response_full(200, content=req.body, mime="application/octet-stream",
                                   headers={"X-Body-Length": str(len(req.body))})
            return True

        if req.path == "/exercise/submit":
            try:
                data = json.loads(req.body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                req.send_json(400, data={"error": "invalid JSON"})
                return True
            req.server._seen_requests.append(data)
            req.send_json(201, data={"accepted": True, "count": len(req.server._seen_requests)})
            return True

    # ── Fallback ─────────────────────────────────────────────────────────

    def handle_fallback(self, req):
        # Called when no do_METHOD matched.
        # req.command holds the HTTP method string.
        if req.command in ("PUT", "PATCH", "DELETE"):
            req.send_response_full(200, content=b"fallback ok")
            return True


# ── Handler ─────────────────────────────────────────────────────────────────
# A Handler consumes events pushed from Processors via req.push_event().
# Handlers receive ALL events (both built-in and custom).
# Multiple handlers can be registered; each one's handle_event() is called.

class ExerciseHandler:
    def __init__(self):
        self.events = []

    def get_events(self, event_type=None):
        if event_type is None:
            return list(self.events)
        return [e for e in self.events if e.get("event_type") == event_type]

    def clear(self):
        self.events.clear()

    def handle_event(self, data):
        # `data` is the dict passed to req.push_event()
        # plus the auto-added fields: connect_timestamp, request_timestamp,
        # proto, event_timestamp, client.
        self.events.append(data)

        # Only print for our custom exercise events
        if data.get("exercise_event"):
            self.printstatus(
                f"ExerciseHandler got event: {data.get('exercise_path')} "
                f"from {data.get('client')} [{data.get('proto')}]"
            )
