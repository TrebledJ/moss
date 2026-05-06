import pytest
import socket


WEBDAV_METHODS = [
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
]


@pytest.mark.moss_args("--status-code", 200, "--body", "default body")
@pytest.mark.no_tcp_check
class TestWebDAVMethods:
    """Test WebDAV HTTP methods — should return 405 but with WebDAV proto."""

    def _send_raw(self, port, data: bytes) -> bytes:
        """Send raw bytes and read response."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", port))
            s.sendall(data)
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            return response

    @pytest.mark.parametrize("method", WEBDAV_METHODS)
    def test_webdav_returns_405(self, moss_port, method):
        """WebDAV methods should return 405."""
        response = self._send_raw(moss_port, f"{method} / HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        assert b"HTTP/1.1 405" in response

    @pytest.mark.parametrize("method", WEBDAV_METHODS)
    def test_propfind_sets_webdav_proto(self, moss_port, moss_runner, method):
        self._send_raw(moss_port, f"{method} / HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        srv = moss_runner.servers[0]
        evt = srv.wait(5.0)
        assert evt is not None
        print(evt)
        assert evt.get("proto", None) == "WEBDAV/HTTP"

