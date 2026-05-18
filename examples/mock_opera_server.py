"""
Mock internal HTTPS server for cve_2026_21967.py SSRF probing.

Simulates an internal service vulnerable to SSRF. When it receives a
probe at GET /OperaLogin/OperaServlet, it extracts the urladdress
parameter and makes a POST callback containing userid=admin (simulating
credential exfiltration from the internal network).

Usage (terminal 1, generates cert and starts mock):
    python examples/mock_ssrf_server.py --port 8443

Usage (terminal 2):
    python examples/cve_2026_21967.py --hostname localhost --target https://localhost:8443

Note: The mock generates a self-signed cert on first run. The cve_2026_21967
example uses httpx with verify=False so it will accept it.
"""

import sys
import os
import ssl
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


CERT_DIR = os.path.join(os.path.dirname(__file__), "..", "tests", "data")
CERT_FILE = os.path.join(CERT_DIR, "server.crt")
KEY_FILE = os.path.join(CERT_DIR, "server.key")


class OperaRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        urladdress = params.get("urladdress", [None])[0]

        print(f"[mock] GET {self.path} from {self.client_address[0]}")
        if urladdress:
            print(f"[mock] Extracted urladdress: {urladdress}")
            self._simulate_ssrf(urladdress)
        else:
            print(f"[mock] No urladdress param found")

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>OK</body></html>")
        print(f"[mock] Responded 200 OK")

    def _simulate_ssrf(self, callback_url):
        """Simulate the SSRF by making a POST callback with credential data."""
        body = b"userid=OPERA/password123@opera"
        print(f"[mock] Simulating SSRF callback to {callback_url}")
        print(f"[mock] Callback body: {body.decode()}")
        try:
            req = urllib.request.Request(
                callback_url,
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=10)
            resp.read()  # drain
            print(f"[mock] SSRF callback sent successfully")
        except Exception as e:
            print(f"[mock] SSRF callback failed: {e}")

    def log_message(self, fmt, *args):
        pass


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Mock SSRF internal HTTPS server",
    )
    parser.add_argument("--port", type=int, default=8443, help="Listen port")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--certfile", default=CERT_FILE, help="Server cert file")
    parser.add_argument("--keyfile", default=KEY_FILE, help="Server key file")
    args = parser.parse_args()

    httpd = HTTPServer((args.bind, args.port), OperaRequestHandler)

    if not os.path.exists(args.certfile):
        print(f"[mock] Cert not found at {args.certfile}")
        print(f"[mock] Generate one with tests/data/generate.sh or provide --certfile/--keyfile")
        sys.exit(1)

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(args.certfile, args.keyfile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"[mock] SSRF target listening on https://{args.bind}:{args.port}")
    print(f"[mock] Endpoint: GET /OperaLogin/OperaServlet?urladdress=...")
    print(f"[mock] Press Ctrl+C to stop")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        httpd.server_close()
        print("[mock] Stopped")


if __name__ == "__main__":
    main()
