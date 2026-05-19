"""
Mock vulnerable XML endpoint for xxe_exfil.py.

Simulates a server that processes XML with external DTD loading.
When it receives an XXE payload at POST /product/stock, it:
  1. Extracts the DTD URL from <!DOCTYPE SYSTEM "...">
  2. Fetches the DTD (simulating the parser loading it)
  3. Parses the DTD for parameter entity SYSTEM URLs and fetches those too

Usage (terminal 1):
    python examples/mock_xxe_server.py --port 9000

Usage (terminal 2):
    python examples/xxe_exfil.py --hostname localhost --target http://localhost:9000
"""

import re
import json
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler


class XxeHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        print(f"[mock] POST {self.path} from {self.client_address[0]}")
        print(f"[mock] Content-Type: {self.headers.get('Content-Type', '?')}")
        print(f"[mock] Body ({len(body)} bytes)")

        # Extract SYSTEM URL from DOCTYPE
        match = re.search(rb'<!DOCTYPE\s+\w+\s+SYSTEM\s+"([^"]+)"', body)
        if match:
            dtd_url = match.group(1).decode()
            print(f"[mock] Extracted DTD URL: {dtd_url}")
            self._fetch_url(dtd_url)
        else:
            print(f"[mock] No external DTD reference found in body")

        # Respond 200 to the XXE request
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = json.dumps({"status": "ok", "productId": 1}).encode()
        self.wfile.write(resp)
        print(f"[mock] Responded 200 OK")

    def _fetch_url(self, url):
        """Fetch a URL to simulate XML parser resolving external entities."""
        print(f"[mock] Fetching: {url}")
        try:
            resp = urllib.request.urlopen(url, timeout=10)
            content = resp.read()
            print(f"[mock] Fetched {len(content)} bytes from {url}")

            # If the fetched content is a DTD, look for more SYSTEM URLs
            # inside parameter entity declarations
            dtd = content.decode("utf-8", errors="replace")
            for m in re.finditer(r'<!ENTITY\s+%\s+\w+\s+SYSTEM\s+"([^"]+)"', dtd):
                sub_url = m.group(1)
                print(f"[mock] DTD references entity URL: {sub_url}")
                self._fetch_url(sub_url)
        except Exception as e:
            print(f"[mock] Failed to fetch {url}: {e}")

    def log_message(self, fmt, *args):
        pass  # suppress default HTTP server log output


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Mock XXE-vulnerable XML endpoint")
    parser.add_argument("--port", type=int, default=9000, help="Listen port")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    args = parser.parse_args()

    server = HTTPServer((args.bind, args.port), XxeHandler)
    print(f"[mock] XXE target listening on http://{args.bind}:{args.port}/product/stock")
    print(f"[mock] Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()
        print("[mock] Stopped")


if __name__ == "__main__":
    main()
