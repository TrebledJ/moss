"""
ext/pastebin.py

E2E-encrypted in-memory pastebin for MOSS.

Pastes are encrypted in the browser using AES (via a bundled JS library)
before being sent to the server. The server never sees plaintext content
unless --pastebin-password is used (which bypasses E2EE).

Supports fixed IDs, optional localStorage password persistence, and
headless browser decryption.

Usage:
    moss -e pastebin
    moss -e pastebin --pastebin-password mysecret
    moss -e pastebin --pastebin-fixed mypaste --pastebin-store-password-in-browser key

CLI flags:
    --pastebin-path PATH            HTTP path for the pastebin (default: /pastebin)
    --pastebin-fixed ID             Write pastes to a fixed ID instead of random
    --pastebin-store-password-in-browser KEY
                                    Save encryption password to browser localStorage
    --pastebin-password PASS        Hardcode a password (disables E2EE)
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
    pastebin_store_password_in_browser: str = _field("", group=GROUP, doc="Save the encryption password to browser localStorage in PLAIN TEXT. The string passed to this argument will be used as the localStorage key. NOTE: This option has been provided for convenience.")
    pastebin_password: str = _field(None, group=GROUP, doc="Hardcode a password for pastebin encryption. NOTE: This option has been provided for convenience and essentially nullifies end-to-end encryption.")
    
    def __post_init__(self):
        self.pastebin_items = {}
        super().__post_init__()

    def list_pastebin(self):
        return list(self.pastebin_items)
    
    def get_pastebin(self, id):
        return self.pastebin_items.get(id, None)

class PastebinProcessor:
    BASE64_REGEX = re.compile(r'^[A-Za-z0-9\+/=]+$')

    def get_services(self, server):
        return [(server.pastebin_path, "pastebin")]

    def do_GET(self, req):
        if req.path.strip("/") == req.server.pastebin_path.strip("/"):
            https_link = self._get_https_url(req) if req.server.supports_https and not req.is_ssl else ""
            content = PASTEBIN_FORM_HTML.replace(b"{{HTTPS_LINK}}", https_link.encode("utf-8"))
            content = content.replace(b"{{PATH}}", req.server.pastebin_path.encode("utf-8"))
            content = content.replace(b"{{SAVE_PSWD}}", req.server.pastebin_store_password_in_browser.encode("utf-8"))
            content = content.replace(b"{{HARDCODED_PSWD}}", (req.server.pastebin_password or "").encode("utf-8"))
            req.send_response_full(200, content=content)
            return True
        
        elif req.path.strip("/") == (req.server.pastebin_path.strip("/") + "/aes.js"):
            req.send_response_full(200, content=AES_JS, mime="text/javascript")
            return True
        
        elif match := re.match(rf"^{req.server.pastebin_path}/(\w+)$", req.path):
            id = match.group(1)
            data = req.server.pastebin_items.get(id, None)
            if data is None:
                req.send_response_full(404)
                return True
            
            payload = json.loads(data)
            enc_type = payload.get("type", "aes-cbc")
            
            if (enc_type == "aes-gcm" and req.server.supports_https and not req.is_ssl):
                https_url = self._get_https_url(req)
                req.send_response_full(302, content=b"", headers={"Location": https_url})
                return True
            
            aes_script = self._get_aes_script(req, enc_type)
            content = PASTEBIN_VIEW_HTML.replace(b"{{PAYLOAD}}", data.encode("utf-8") if isinstance(data, str) else data)
            content = content.replace(b"{{AES_SCRIPT}}", aes_script.encode("utf-8"))
            content = content.replace(b"{{PATH}}", req.server.pastebin_path.encode("utf-8"))
            content = content.replace(b"{{SAVE_PSWD}}", req.server.pastebin_store_password_in_browser.encode("utf-8"))
            content = content.replace(b"{{HARDCODED_PSWD}}", (req.server.pastebin_password or "").encode("utf-8"))
            req.send_response_full(200, content=content)
            return True
        
        elif req.path.startswith(req.server.pastebin_path + "/"):
            req.send_response_full(404)
            return True
    
    def _get_https_url(self, req):
        host = req.headers.get("Host", f"localhost:{req.server.port}")
        return f"https://{host}{req.path}"
    
    def _get_aes_script(self, req, enc_type):
        if enc_type == "aes-cbc" and (req.is_ssl or not req.server.supports_https):
            return f'<script src="{req.server.pastebin_path}/aes.js"></script>'
        return ""
        
    def do_POST(self, req):
        if req.path != req.server.pastebin_path:
            return
        
        # Validate JSON payload
        try:
            payload = json.loads(req.body)
        except json.JSONDecodeError:
            req.send_json(400, data={"message": "Invalid JSON"})
            return True
        
        if msg := self.validate_payload(req.body):
            req.send_json(403, data={
                "message": msg,
            })
            return True
        
        if req.server.pastebin_fixed:
            path = req.server.pastebin_fixed
        else:
            path = None
            while (path is None) or (path in req.server.pastebin_items):
                path = random_id(6)

        req.server.pastebin_items[path] = req.body
        req.send_json(201, data={
            "message": "Success!",
            "url": f"{req.server.pastebin_path}/{path}",
        })
        return True
    
    def validate_payload(self, body):
        try:
            payload = json.loads(body)
            valid_keys = {"iv", "salt", "data", "type", "tag"}
            if payload.keys() - valid_keys: raise Exception(f"excessive keys")
            if not self.BASE64_REGEX.match(payload["iv"]): raise Exception(f"iv is not base64")
            if not self.BASE64_REGEX.match(payload["salt"]): raise Exception(f"salt is not base64")
            if not self.BASE64_REGEX.match(payload["data"]): raise Exception(f"data is not base64")
            if "type" in payload and payload["type"] not in ("aes-gcm", "aes-cbc"): raise Exception(f"invalid type")
            if payload.get("type") == "aes-gcm" and "tag" not in payload: raise Exception(f"missing tag for aes-gcm")
            if payload.get("type") == "aes-gcm" and not self.BASE64_REGEX.match(payload["tag"]): raise Exception(f"tag is not base64")
        except Exception as e:
            return str(e)

def random_id(n: int):
    return "".join(random.sample("abcdefghijkmnopqrstuvwxyz0123456789", n))

with open(Path(__file__).parent / "pastebin" / "pastebin.html", "rb") as f:
    PASTEBIN_FORM_HTML = f.read()

with open(Path(__file__).parent / "pastebin" / "decrypt.html", "rb") as f:
    PASTEBIN_VIEW_HTML = f.read()

with open(Path(__file__).parent / "pastebin" / "aes.js", "rb") as f:
    AES_JS = f.read()

