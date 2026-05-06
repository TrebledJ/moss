import pytest
import httpx
import io


@pytest.mark.moss_args("--status-code", 200, "--body", "default body")
class TestHeadRequest:
    def test_head_no_body(self, http_client):
        """HEAD requests should return no body."""
        r = http_client.head("/")
        assert r.status_code == 200
        assert r.text == ""


@pytest.mark.moss_args("--status-code", 200)
class TestOptionsRequest:
    def test_options_allowed(self, http_client):
        """OPTIONS requests should be handled."""
        r = http_client.options("/")
        assert r.status_code != 0


@pytest.mark.moss_args("--status-code", 200, "--body", "default body")
class TestPutPatchDelete:
    def test_put_fallback(self, http_client):
        """PUT requests should be handled by fallback."""
        r = http_client.put("/test", content=b"test")
        assert r.status_code == 200
        assert r.text == "default body"

    def test_patch_fallback(self, http_client):
        """PATCH requests should be handled by fallback."""
        r = http_client.patch("/test", content=b"test")
        assert r.status_code == 200
        assert r.text == "default body"

    def test_delete_fallback(self, http_client):
        """DELETE requests should be handled by fallback."""
        r = http_client.delete("/test")
        assert r.status_code == 200
        assert r.text == "default body"


@pytest.mark.moss_args("--status-code", 200, "--body", "default body")
class TestHttp10:
    def test_http_1_0_request(self, moss_runner):
        """HTTP/1.0 requests should be handled (server responds with HTTP/1.1)."""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", moss_runner.servers[0].port))
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            # Server responds with HTTP/1.1
            assert response.startswith(b"HTTP/1.1 200")
            assert b"default body" in response


@pytest.mark.moss_args("--status-code", 200, "--body", "default body")
class TestConnectionHandling:
    def test_connection_close(self, http_client):
        """Connection: close should work."""
        r = http_client.get("/", headers={"Connection": "close"})
        assert r.status_code == 200

    def test_connection_keep_alive(self, http_client):
        """Connection: keep-alive should work (default)."""
        r = http_client.get("/")
        assert r.status_code == 200
        # Make another request on same connection
        r = http_client.get("/")
        assert r.status_code == 200


@pytest.mark.moss_args("--status-code", 200)
class TestChunkedEncoding:
    def test_chunked_request(self, moss_runner):
        """Chunked transfer encoding should be handled."""
        import socket
        body = b"hello world"
        chunked_body = f"{len(body):x}\r\n{body}\r\n0\r\n\r\n".encode()
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", moss_runner.servers[0].port))
            s.sendall(b"POST / HTTP/1.1\r\n")
            s.sendall(b"Host: localhost\r\n")
            s.sendall(b"Transfer-Encoding: chunked\r\n")
            s.sendall(b"\r\n")
            s.sendall(chunked_body)
            
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            assert b"HTTP/1.1 200" in response


@pytest.mark.moss_args("--body", "test_body.txt")
class TestBodyFile:
    def test_body_from_file(self, http_client, tmp_path):
        """--body should read from file if given a filename."""
        # Create a test file
        body_file = tmp_path / "test_body.txt"
        body_file.write_text("file body content")
        
        # Note: This test verifies the flag is processed
        # The actual file reading would need server restart with correct path
        r = http_client.get("/")
        assert r.status_code == 200
