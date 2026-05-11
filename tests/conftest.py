# conftest.py
import pytest
import socket
import time
from moss import moss
import httpx


def get_free_port() -> int:
    """Find a free port quickly"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


@pytest.fixture(scope="class")
def moss_runner(request):
    marker = request.node.get_closest_marker("moss_args")
    args = []
    port = None

    # Check for port in moss_args
    if marker is not None and ("-p" in marker.args or "--port" in marker.args):
        # Get the custom port.
        try:
            index = marker.args.index("-p")
        except ValueError:
            index = marker.args.index("--port")
        port = int(marker.args[index + 1])
    else:
        # Otherwise grab an unoccupied port
        port = get_free_port()
        # Note: override_moss_port is not intended to affect the server's port, but rather the client's.

    args.extend(["-p", port])

    if marker is not None:
        args.extend(marker.args)
    
    moss_https = request.node.get_closest_marker("moss_https")
    if moss_https is not None:
        print('enabling https')
        args.extend(["--https", "--certfile", "tests/data/server.crt", "--keyfile", "tests/data/server.key"])

    builder = moss.MossBuilder(args)
    runner = builder.cli()
    runner.serve()

    no_tcp_check = request.node.get_closest_marker("no_tcp_check")
    if not no_tcp_check:
        # Wait until server is actually listening (very important!)
        for _ in range(20):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except (ConnectionRefusedError, OSError):
                time.sleep(0.2)
        else:
            raise RuntimeError("Custom HTTP server failed to start in time")

    yield runner

    runner.shutdown()


@pytest.fixture(scope="class")
def moss_port(request, moss_runner):
    marker = request.node.get_closest_marker("override_moss_port")
    if marker is not None and len(marker.args) == 1:
        yield marker.args[0]
    else:
        s = moss_runner.servers[0]
        yield s.port


@pytest.fixture(scope="class")
def moss_url(request, moss_port):
    marker = request.node.get_closest_marker("override_moss_port")
    if marker is not None and len(marker.args) == 1:
        moss_port = marker.args[0]

    scheme = 'http'
    marker = request.node.get_closest_marker("moss_https")
    if marker is not None:
        scheme = 'https'

    yield f"{scheme}://127.0.0.1:{moss_port}"


@pytest.fixture
def http_client(moss_url):
    with httpx.Client(base_url=moss_url, timeout=5.0, verify=False) as client:
        yield client


@pytest.fixture(scope="session")
def _playwright():
    """Session-scoped Playwright instance."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("playwright not installed")
    pw = sync_playwright().start()
    yield pw
    pw.stop()


@pytest.fixture(scope="session")
def browser_http(_playwright):
    """Session-scoped browser for HTTP tests."""
    browser = _playwright.chromium.launch(headless=True)
    yield browser
    browser.close()


@pytest.fixture(scope="session")
def browser_https(_playwright):
    """Session-scoped browser for HTTPS tests.
    Context with ignore_https_errors=True is needed for self-signed test certs."""
    browser = _playwright.chromium.launch(headless=True)
    context = browser.new_context(ignore_https_errors=True)
    yield context
    context.close()
    browser.close()
