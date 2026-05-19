"""
ext/auth.py

Authentication middleware for MOSS. Protects all downstream processors
with HTTP Basic or Bearer token authentication.

NOTE: Order matters. Specify `-e auth ...` before the extensions you want
to protect. For example, `-e auth upload` protects the upload endpoint;
`-e upload auth` does NOT.

Usage:
    moss -e auth --basic-auth admin:secret
    moss -e auth --token-auth s3cr3t

CLI flags:
    --basic-auth USER:PASS  Basic authentication credentials
    --token-auth TOKEN      Bearer token (use "generate" for a random token)
"""

from dataclasses import dataclass, field
import random
import sys
import base64

GROUP = "auth (ext/auth.py)"

def _field(default, group=None, doc="", metadata={}, flags=[], choices=[], **kwargs):
    """Simple wrapper to express fields more conveniently."""
    dwargs = {}
    if type(default).__name__ in ["function", "type"]:
        dwargs["default_factory"] = default
    else:
        dwargs["default"] = default
    return field(**dwargs, metadata=metadata | dict(group=group, doc=doc, flags=flags, choices=choices, **kwargs))

def random_id(n: int):
    return "".join(random.sample("abcdefghijkmnopqrstuvwxyz0123456789", n))

@dataclass
class AuthMixin:
    token_auth: str = _field(None, group=GROUP, doc="Use the provided bearer token. Special values: generate (generates a token which will be printed to console or can be programmatically fetched via a method)")
    basic_auth: str = _field(None, group=GROUP, doc="Basic authentication in the format username:password")

    def __post_init__(self):
        if not self.token_auth and not self.basic_auth:
            self.logger.warning(f"auth module was enabled but no auth settings were provided")
        if self.token_auth and self.basic_auth:
            self.printerr(f"[auth] expected one of token_auth or basic_auth, but both were provided")
            sys.exit(1)

        if self.basic_auth and ":" not in self.basic_auth:
            self.printerr(f"[auth] expected basic auth to contain colon but got ({self.basic_auth})")
            sys.exit(1)
        
        if (self.token_auth or "").strip() == "generate":
            self.token_auth = random_id(32)
            self.printstatus(f"[auth] Authorization: Bearer {self.token_auth}")

        self.expect_header = f"Bearer {self.token_auth}"
        if self.basic_auth:
            self.expect_header = f"Basic {base64.b64encode(self.basic_auth.encode("utf-8")).decode()}"

        super().__post_init__()

    def get_authorization(self):
        """Retrieves the token in the format of the header value. e.g. Bearer {token}, Basic {token}."""
        return self.expect_header

@dataclass
class AuthProcessor:
    def handle_fallback(self, req):
        auth = req.headers["authorization"]
        if not auth or auth.strip() != req.server.expect_header:
            req.mark_ip_bad()
            
            headers = {}
            if req.server.basic_auth:
                headers["WWW-Authenticate"] = "Basic realm=\"Protected Area\""
            elif req.server.token_auth:
                headers["WWW-Authenticate"] = "Bearer realm=\"Protected Area\""
            req.send_response_full(401, headers=headers)
            return True

        # Passes auth.
        req.mark_ip_ok()
        