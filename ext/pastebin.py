"""
ext/pastebin.py

---

Simple in-memory pastebin.
"""

from dataclasses import dataclass, field
from pathlib import Path
import random
import re
import json

GROUP = "pastebin (ext/pastebin.py)"

def _field(default, group=None, doc="", metadata={}, flags=[], choices=[], **kwargs):
    """Simple wrapper to express fields more conveniently."""
    dwargs = {}
    if type(default).__name__ in ['function', 'type']:
        dwargs["default_factory"] = default
    else:
        dwargs["default"] = default
    return field(**dwargs, metadata=metadata | dict(group=group, doc=doc, flags=flags, choices=choices, **kwargs))

@dataclass
class PastebinMixin:
    pastebin_path: str = _field("/pastebin", group=GROUP, doc="HTTP path which accepts pastebin payloads")
    pastebin_max_size: int = _field(16 * 1024**2, group=GROUP, doc="Max file size accepted for files stored on disk. Defaults to 16 MiB")
    def __post_init__(self):
        self.pastebin_files = {}
        super().__post_init__()

    def list_pastebin(self):
        return list(self.pastebin_files)
    
    def get_pastebin(self, id):
        return self.pastebin_files.get(id, None)

class PastebinProcessor:
    def send_response(self, req, status, content=b"", mime="text/html"):
        req.send_response(status)
        req.send_header('Content-Type', mime)
        req.send_header('Content-Length', len(content))
        req.end_headers()
        req.wfile.write(content)

    def send_json(self, req, status, data):
        content = json.dumps(data).encode()
        self.send_response(req, status, content, "application/json")

    def do_GET(self, req):
        if req.path.strip("/") == req.server.pastebin_path.strip("/"):
            content = PASTEBIN_FORM_HTML.replace(b"{{PATH}}", req.server.pastebin_path.encode('utf-8'))
            self.send_response(req, 200, content)
            return True
        
        elif match := re.match(rf"^{req.server.pastebin_path}/(\w+)$", req.path):
            id = match.group(1)
            data = req.server.pastebin_files.get(id, None)
            if data is None:
                self.send_response(req, 404)
                return True
            # TODO: make this more secure by enforcing data structure???
            content = PASTEBIN_VIEW_HTML.replace(b"{{PAYLOAD}}", data)
            self.send_response(req, 200, content)
            return True
        
    def do_POST(self, req):
        if req.path != req.server.pastebin_path:
            return
        
        length = len(req.body)
        if length > req.server.pastebin_max_size:
            self.printerr(f"Incoming data exceeded max pastebin size ({length} > {req.server.pastebin_max_size})")
            self.send_json(req, 413, {
                "message": "Error: content length too large.",
            })
            return True
        
        path = None
        while (path is None) or (path in req.server.pastebin_files):
            path = random_id(6)

        req.server.pastebin_files[path] = req.body
        self.send_json(req, 201, {
            "message": "Success!",
            "url": f"{req.server.pastebin_path}/{path}",
        })
        return True

def random_id(n: int):
    return "".join(random.sample("abcdefghijkmnopqrstuvwxyz0123456789", n))

with open(Path(__file__).parent / "pastebin" / "pastebin.html", "rb") as f:
    PASTEBIN_FORM_HTML = f.read()

with open(Path(__file__).parent / "pastebin" / "decrypt.html", "rb") as f:
    PASTEBIN_VIEW_HTML = f.read()

