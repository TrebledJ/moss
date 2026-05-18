"""
HTTP server that executes received commands via os.system — simulating RCE.

POST a shell command as the request body, and the mock runs it like
an attacker who just gained remote code execution.

Usage (terminal 1 — start the mock compromised target):
    python examples/mock_rce_target.py 9000

Usage (terminal 2):
    python examples/rce_curl.py --hostname localhost --port 8000 --target http://localhost:9000
"""

import os
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler


class RceHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        cmd = self.rfile.read(length).decode("utf-8", errors="replace")
        print(f"[mock] RCE: {cmd}")
        ret = os.system(cmd)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(str(ret).encode())

    def log_message(self, fmt, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=9000)
    args = parser.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), RceHandler)
    print(f"[mock] RCE target listening on http://0.0.0.0:{args.port}")
    print(f"[mock] Send commands via POST to /")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
