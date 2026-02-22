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
    pastebin_fixed: str = _field(None, group=GROUP, doc="Write the pastebin to a fixed path")
    pastebin_max_size: int = _field(16 * 1024**2, group=GROUP, doc="Max file size accepted for files stored on disk. Defaults to 16 MiB")
    pastebin_local_store: str = _field("", group=GROUP, doc="Save the encryption password to browser localStorage in PLAIN TEXT. Mainly for convenience. The string passed to this argument will be used as the localStorage key.")
    
    def __post_init__(self):
        self.pastebin_files = {}
        super().__post_init__()

    def list_pastebin(self):
        return list(self.pastebin_files)
    
    def get_pastebin(self, id):
        return self.pastebin_files.get(id, None)

class PastebinProcessor:
    BASE64_REGEX = re.compile(r'^[A-Za-z0-9\+/=]+$')

    def do_GET(self, req):
        if req.path.strip("/") == req.server.pastebin_path.strip("/"):
            content = PASTEBIN_FORM_HTML.replace(b"{{PATH}}", req.server.pastebin_path.encode("utf-8"))
            content = content.replace(b"{{SAVE_PSWD}}", req.server.pastebin_local_store.encode("utf-8"))
            req.send_response_full(200, content=content)
            return True
        
        elif match := re.match(rf"^{req.server.pastebin_path}/(\w+)$", req.path):
            id = match.group(1)
            data = req.server.pastebin_files.get(id, None)
            if data is None:
                req.send_response_full(404)
                return True
            # TODO: make this more secure by enforcing data structure???
            content = PASTEBIN_VIEW_HTML.replace(b"{{PAYLOAD}}", data)
            content = content.replace(b"{{SAVE_PSWD}}", req.server.pastebin_local_store.encode("utf-8"))
            req.send_response_full(200, content=content)
            return True
        
    def do_POST(self, req):
        if req.path != req.server.pastebin_path:
            return
        
        length = len(req.body)
        if length > req.server.pastebin_max_size:
            self.printerr(f"Incoming data exceeded max pastebin size ({length} > {req.server.pastebin_max_size})")
            req.send_json(413, data={
                "message": "Error: content length too large.",
            })
            return True
        
        if req.server.pastebin_fixed:
            path = req.server.pastebin_fixed
        else:
            path = None
            while (path is None) or (path in req.server.pastebin_files):
                path = random_id(6)

        if msg := self.validate_payload(req.body):
            req.send_json(403, data={
                "message": msg,
            })
            return True
        
        req.server.pastebin_files[path] = req.body
        req.send_json(201, data={
            "message": "Success!",
            "url": f"{req.server.pastebin_path}/{path}",
        })
        return True
    
    def validate_payload(self, body):
        try:
            payload = json.loads(body)
            if payload.keys() - {"iv", "salt", "data"}: raise Exception(f"excessive keys")
            if not self.BASE64_REGEX.match(payload["iv"]): raise Exception(f"iv is not base64")
            if not self.BASE64_REGEX.match(payload["salt"]): raise Exception(f"salt is not base64")
            if not self.BASE64_REGEX.match(payload["data"]): raise Exception(f"data is not base64")
        except Exception as e:
            return str(e)

def random_id(n: int):
    return "".join(random.sample("abcdefghijkmnopqrstuvwxyz0123456789", n))

with open(Path(__file__).parent / "pastebin" / "pastebin.html", "rb") as f:
    PASTEBIN_FORM_HTML = f.read()

with open(Path(__file__).parent / "pastebin" / "decrypt.html", "rb") as f:
    PASTEBIN_VIEW_HTML = f.read()

