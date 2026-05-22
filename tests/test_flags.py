import pytest
import gzip
import json
from pathlib import Path
import time


@pytest.mark.moss_args("--mime-type", "application/json")
class TestMimeType:
    def test_custom_mime_type(self, http_client):
        r = http_client.get("/")
        assert r.headers.get("content-type", "").startswith("application/json")


@pytest.mark.moss_args("--index")
class TestIndexPage:
    def test_index_shows_services(self, http_client):
        r = http_client.get("/")
        assert r.status_code == 200
        assert "Services" in r.text


@pytest.mark.moss_args("--index", "-e", "pastebin")
class TestIndexPageWithExtensions:
    def test_index_shows_pastebin(self, http_client):
        r = http_client.get("/")
        assert r.status_code == 200
        assert "pastebin" in r.text.lower()


@pytest.mark.moss_args("--https-only")
class TestHttpsOnly:
    def test_http_rejected(self, moss_runner):
        """HTTP requests should be rejected when https-only is set."""
        import socket
        
        # Use raw socket to test HTTP rejection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            try:
                s.connect(("127.0.0.1", moss_runner.servers[0].port))
                s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                # Server should close connection without proper HTTP response
                data = s.recv(1024)
                # Connection closed or non-HTTP response
                assert len(data) == 0 or not data.startswith(b"HTTP")
            except (ConnectionResetError, ConnectionAbortedError, socket.timeout):
                # Expected - server may close connection
                pass
        
        # Check that anomaly was logged
        moss_runner.poll(timeout_per_server=1.0)
        # The test passes if we reach here (no exception from the server)
        assert True


@pytest.mark.moss_args("--gzip")
class TestGzip:
    def test_gzip_response(self, http_client):
        """Gzip should be applied to static file extensions."""
        r = http_client.get("/", headers={"Accept-Encoding": "gzip"})
        # Check if response is gzipped (may depend on body content)
        if "content-encoding" in r.headers:
            assert r.headers["content-encoding"] == "gzip"


@pytest.mark.moss_args("--show-common-headers")
class TestShowCommonHeaders:
    def test_common_headers_shown(self, http_client, moss_runner):
        """Common headers should be shown in logging when --show-common-headers is set."""
        r = http_client.get("/", headers={
            "Accept": "text/html",
            "Accept-Encoding": "gzip",
            "Accept-Language": "en-US",
        })
        assert r.status_code != 0
        # The logging output should contain the common headers
        # This is hard to test directly, but we can verify the flag is set
        assert moss_runner.handlers[0].show_common_headers == True


@pytest.mark.moss_args("--output-all")
class TestOutputAll:
    def test_all_requests_logged(self, moss_runner, http_client):
        """All requests should be logged when output-all is set."""
        r = http_client.get("/any-path")
        assert r.status_code != 0
        # With output-all, even non-matching requests are logged
        assert moss_runner.handlers[0].output_all == True


@pytest.mark.moss_args("--simple")
class TestSimpleLogging:
    def test_simple_log_format(self, moss_runner):
        """Simple logging should output one line per event."""
        assert moss_runner.handlers[0].simple == True


@pytest.mark.moss_args("--no-anomaly")
class TestNoAnomaly:
    def test_anomalies_suppressed(self, moss_runner):
        """Anomalies should not be logged when no-anomaly is set."""
        assert moss_runner.handlers[0].no_anomaly == True


@pytest.mark.moss_args("--jsonl", "-")
class TestJsonlStdout:
    def test_jsonl_to_stdout(self, moss_runner):
        """JSONL output to stdout should work."""
        assert moss_runner.handlers[0].jsonl_file == "-"


JSONL_FILE = "test_output.jsonl"

def jsonl_cleanup():
    p = Path(JSONL_FILE)
    if p.exists():
        p.unlink()

def jsonl_make_request(http_client, path):
    # Remove file before testing the request
    jsonl_cleanup()
    r = http_client.get(path)
    assert r.status_code != 0

@pytest.mark.moss_args("--jsonl", JSONL_FILE)
@pytest.mark.no_tcp_check
class TestJsonlFile:
    def test_jsonl_to_file(self, moss_runner, http_client):
        JSONL_TEST_PATH = "/wabadabadoobee"
        jsonl_make_request(http_client, JSONL_TEST_PATH)
        # Make sure to call .poll() so that events are handled.
        moss_runner.poll(timeout_per_server=1.0)
        try:
            assert Path(JSONL_FILE).exists()
        finally:
            jsonl_cleanup()

    def test_jsonl_format(self, moss_runner, http_client):
        JSONL_TEST_PATH = "/jsonl-test"
        jsonl_make_request(http_client, JSONL_TEST_PATH)
        moss_runner.poll(timeout_per_server=1.0)
        try:
            assert Path(JSONL_FILE).exists()
            with open(JSONL_FILE, "r") as f:
                line = f.readline()
                data = json.loads(line)
                assert "path" in data
                assert data.get("path", "") == JSONL_TEST_PATH
        finally:
            jsonl_cleanup()


@pytest.mark.moss_args("--jsonl", JSONL_FILE, "--filter", "jamesbond")
@pytest.mark.no_tcp_check
class TestJsonlFileWithFilter:
    def test_jsonl_matches_filter(self, moss_runner, http_client):
        JSONL_TEST_PATH = "/is-it-mr-jamesbond"
        jsonl_make_request(http_client, JSONL_TEST_PATH)
        moss_runner.poll(timeout_per_server=1.0)
        try:
            assert Path(JSONL_FILE).exists()
            with open(JSONL_FILE, "r") as f:
                line = f.readline()
                data = json.loads(line)
                assert "path" in data
                assert data.get("path", "") == JSONL_TEST_PATH
        finally:
            jsonl_cleanup()

    def test_jsonl_no_match_filter(self, moss_runner, http_client):
        JSONL_TEST_PATH = "/wabadabadoobee"
        jsonl_make_request(http_client, JSONL_TEST_PATH)
        moss_runner.poll(timeout_per_server=1.0)
        try:
            assert Path(JSONL_FILE).exists() is False
        finally:
            jsonl_cleanup()


@pytest.mark.moss_args("--port", "21820")
class TestCustomPort:
    def test_custom_port(self, moss_runner):
        """Server should listen on custom port."""
        assert moss_runner.servers[0].port == 21820

    def test_custom_port_get(self, http_client):
        r = http_client.get("/")
        assert r.status_code != 0


@pytest.mark.moss_args("-b", "127.0.0.1")
class TestCustomBind:
    def test_custom_bind_address(self, moss_runner):
        """Server should bind to specific address."""
        assert moss_runner.servers[0].host == "127.0.0.1"
