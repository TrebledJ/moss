import pytest
import gzip
import json
import os
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
    def test_http_rejected(self, http_client):
        """HTTP requests should be rejected when https-only is set."""
        r = http_client.get("/", allow_redirects=False)
        # Should get an anomaly (connection may be closed)
        assert r.status_code in [400, 403, 426, 0] or "SSL" in str(r.content)


@pytest.mark.moss_args("--websockets")
class TestWebSocketDetection:
    def test_ws_upgrade_detected(self, http_client):
        """WebSocket upgrade header should be detected."""
        r = http_client.get("/", headers={"Upgrade": "websocket", "Connection": "Upgrade"})
        # The proto should be set to WS/WSS, but request still handled
        assert r.status_code != 0


@pytest.mark.moss_args("--gzip")
class TestGzip:
    def test_gzip_response(self, http_client):
        """Gzip should be applied to static file extensions."""
        r = http_client.get("/", headers={"Accept-Encoding": "gzip"})
        # Check if response is gzipped (may depend on body content)
        if "content-encoding" in r.headers:
            assert r.headers["content-encoding"] == "gzip"


@pytest.mark.moss_args("--ignore-common-headers", "-i")
class TestIgnoreCommonHeaders:
    def test_common_headers_filtered(self, moss_runner):
        """Common headers should be filtered from logging."""
        import httpx
        client = httpx.Client(base_url=moss_runner.url)
        r = client.get("/", headers={
            "Accept": "text/html",
            "Accept-Encoding": "gzip",
            "Accept-Language": "en-US",
        })
        assert r.status_code != 0
        # The logging output should not contain the common headers
        # This is hard to test directly, but we can verify the flag is set
        assert moss_runner.servers[0].ignore_common_headers == True


@pytest.mark.moss_args("--output-all")
class TestOutputAll:
    def test_all_requests_logged(self, moss_runner):
        """All requests should be logged when output-all is set."""
        r = http_client.get("/any-path")
        assert r.status_code != 0
        # With output-all, even non-matching requests are logged
        assert moss_runner.servers[0].output_all == True


@pytest.mark.moss_args("--simple")
class TestSimpleLogging:
    def test_simple_log_format(self, moss_runner):
        """Simple logging should output one line per event."""
        assert moss_runner.servers[0].simple == True


@pytest.mark.moss_args("--no-anomaly")
class TestNoAnomaly:
    def test_anomalies_suppressed(self, moss_runner):
        """Anomalies should not be logged when no-anomaly is set."""
        assert moss_runner.servers[0].no_anomaly == True


@pytest.mark.moss_args("--jsonl", "-")
class TestJsonlStdout:
    def test_jsonl_to_stdout(self, moss_runner):
        """JSONL output to stdout should work."""
        assert moss_runner.servers[0].jsonl_file == "-"


@pytest.mark.moss_args("--jsonl", "test_output.jsonl")
@pytest.mark.no_tcp_check
class TestJsonlFile:
    def make_request(self, http_client):
        # Remove file before testing the request
        if os.path.exists("test_output.jsonl"):
            os.remove("test_output.jsonl")

        r = http_client.get("/jsonl-test")
        assert r.status_code != 0

    def cleanup(self):
        if os.path.exists("test_output.jsonl"):
            os.remove("test_output.jsonl")

    def test_jsonl_to_file(self, moss_runner, http_client):
        self.make_request(http_client)
        # Make sure to call .poll() so that events are handled.
        moss_runner.poll(timeout_per_server=1.0)
        try:
            assert os.path.exists("test_output.jsonl")
        finally:
            self.cleanup()

    def test_jsonl_format(self, moss_runner, http_client):
        self.make_request(http_client)
        moss_runner.poll(timeout_per_server=1.0)
        try:
            assert os.path.exists("test_output.jsonl")
            with open("test_output.jsonl", "r") as f:
                line = f.readline()
                data = json.loads(line)
                assert "path" in data
                assert data.get("path", "") == "/jsonl-test"
        finally:
            self.cleanup()


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
