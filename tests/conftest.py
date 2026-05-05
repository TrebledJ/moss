# conftest.py
import pytest
import pytest_asyncio
import socket
import time
from moss import moss


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
    if marker is not None and ("-p" in marker.args or "--port" in marker.args):
        # Get the custom port.
        try:
            index = marker.args.index("-p")
        except ValueError:
            index = marker.args.index("--port")
        port = int(marker.args[index + 1])
    else:
        port = get_free_port()
        args.extend(["-p", port]) # default to a free port

    if marker is not None:
        args.extend(marker.args)
    
    moss_https = request.node.get_closest_marker("moss_https")
    if moss_https is not None:
        print('enabling https')
        args.extend(["--https", "--certfile", "tests/data/server.crt", "--keyfile", "tests/data/server.key"])


    print(f"Running moss version {moss.__version__}")
    builder = moss.MossBuilder(args)
    runner = builder.cli()
    runner.serve()

    no_tcp_check = request.node.get_closest_marker("no_tcp_check")
    if not no_tcp_check:
        # Wait until server is actually listening (very important!)
        # base_url = f"http://127.0.0.1:{port}"
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
def moss_port(moss_runner):
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
    """Convenient httpx client pointed at the live server"""
    import httpx
    with httpx.Client(base_url=moss_url, timeout=5.0, verify=False) as client:
        yield client


@pytest_asyncio.fixture
async def async_http_client(moss_url):
    import httpx
    async with httpx.AsyncClient(base_url=moss_url, timeout=5.0, verify=False) as client:
        yield client
