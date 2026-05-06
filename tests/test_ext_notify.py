import pytest
import json
import threading
import socket
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

CAPTURED_REQUESTS = []

class MockDiscordHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        CAPTURED_REQUESTS.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        })
        # print(f"MOCK: Got webhook request: {len(body)} bytes")
        self.send_response(204)
        self.end_headers()

    def log_message(self, format, *args):
        pass


def get_free_port():
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


PINNED_PORT = get_free_port()
WEBHOOK_URL = f"http://127.0.0.1:{PINNED_PORT}/webhook"


@pytest.fixture(scope="module")
def mock_discord():
    server = HTTPServer(("127.0.0.1", PINNED_PORT), MockDiscordHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield
    server.shutdown()


@pytest.fixture(scope="class")
def moss_runner_with_loop(request, moss_runner):
    """Start the event loop in a separate thread."""
    loop_thread = threading.Thread(target=moss_runner.loop, daemon=True)
    loop_thread.start()
    yield moss_runner
    # loop will stop when server shuts down


@pytest.mark.moss_args("-e", "notify", "--notify", "discord", "--webhook-url", WEBHOOK_URL)
@pytest.mark.no_tcp_check
class TestNotifyExtension:
    def test_notification_sent_on_request(self, http_client, mock_discord, moss_runner, moss_runner_with_loop):
        CAPTURED_REQUESTS.clear()
        r = http_client.get("/test-path")
        assert r.status_code != 0
        time.sleep(3)
        assert len(CAPTURED_REQUESTS) == 1
        payload = json.loads(CAPTURED_REQUESTS[0]["body"])
        assert "content" in payload

    def test_payload_contains_client_ip(self, http_client, mock_discord, moss_runner, moss_runner_with_loop):
        CAPTURED_REQUESTS.clear()
        r = http_client.get("/")
        assert r.status_code != 0
        time.sleep(3)
        payload = json.loads(CAPTURED_REQUESTS[0]["body"])
        assert "127.0.0.1" in payload["content"]


@pytest.mark.moss_args("-e", "notify", "--notify", "discord", "--webhook-url", WEBHOOK_URL, "--filter", ".*", "--id", "test-instance-123")
@pytest.mark.no_tcp_check
class TestNotifyWithId:
    def test_custom_identifier_in_payload(self, http_client, mock_discord, moss_runner, moss_runner_with_loop):
        CAPTURED_REQUESTS.clear()
        r = http_client.get("/")
        assert r.status_code != 0
        time.sleep(3)
        payload = json.loads(CAPTURED_REQUESTS[0]["body"])
        assert "test-instance-123" in payload["content"]


@pytest.mark.moss_args("-e", "notify", "--notify", "discord", "--webhook-url", WEBHOOK_URL, "--filter", "secret", "--notify-on", "match")
@pytest.mark.no_tcp_check
class TestNotifyOnSpecific:
    def test_non_matching_request_no_notification(self, http_client, mock_discord, moss_runner, moss_runner_with_loop):
        CAPTURED_REQUESTS.clear()
        r = http_client.get("/?q=nomatch")
        assert r.status_code != 0
        time.sleep(2)
        assert len(CAPTURED_REQUESTS) == 0

    def test_matching_request_triggers_notification(self, http_client, mock_discord, moss_runner, moss_runner_with_loop):
        CAPTURED_REQUESTS.clear()
        r = http_client.get("/?secret=yes")
        assert r.status_code != 0
        time.sleep(2)
        assert len(CAPTURED_REQUESTS) == 1

        payload = json.loads(CAPTURED_REQUESTS[0]["body"])
        assert "/?secret=yes" in payload["content"]
