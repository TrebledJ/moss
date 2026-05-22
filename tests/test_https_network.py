import pytest
import socket
import ssl
import time
from contextlib import contextmanager

# ────────────────────────────────────────────────
#   Configuration
# ────────────────────────────────────────────────

from moss.moss import TIMEOUT_FOR_HEADERS as MAX_HEADER_READ_DURATION
from moss.moss import TIMEOUT_FOR_BODY as MAX_BODY_READ_DURATION

# ────────────────────────────────────────────────
#   Helpers
# ────────────────────────────────────────────────

@contextmanager
def ssl_socket_connection(host: str = "127.0.0.1", port: int = 8443, timeout: float = 15.0):
    """Context manager for an SSL-wrapped raw socket – auto-closes"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        # Wrap with SSL context
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssl_sock = ctx.wrap_socket(sock, server_hostname=host)
        ssl_sock.setblocking(False)
        yield ssl_sock
    finally:
        try:
            sock.close()
        except:
            pass

def wait_until_closed(sock: socket.socket, max_wait: float = 15.0) -> bool:
    """Poll until the socket is closed by remote (server)"""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        try:
            if not sock.recv(1):
                return True
            time.sleep(0.2)
        except ssl.SSLWantReadError:
            time.sleep(0.2)
        except ssl.SSLWantWriteError:
            time.sleep(0.2)
        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as e:
            pass
    return False

def expect_anomaly(srv, anomaly_description, with_tags=[]):
    while (event := srv.wait(1)) is not None:
        tags_ok = len(set(with_tags) - set(event.get("tags", []))) == 0
        if anomaly_description in event.get("anomaly", "") and tags_ok:
            return
    else:
        assert False, f"expected anomaly containing '{anomaly_description}'"

def expect_anomaly_detail(srv, payload):
    while (event := srv.wait(1)) is not None:
        if "anomaly" in event and len(details := event.get("details", b"")) != 0:
            assert details == payload
            return
    else:
        assert False, "expected anomaly"

# ────────────────────────────────────────────────
#   Test Cases - HTTPS variants of network tests
#   Not applicable: raw TCP byte tests (SSL handshake required)
#   Applicable: idle timeout, slow headers (Slowloris), slow body (R.U.D.Y.)
# ────────────────────────────────────────────────

@pytest.mark.slow
@pytest.mark.moss_https
class TestSlowHeadersHTTPS:
    """Slowloris-style attacks over HTTPS"""

    def test_partial_header_no_newline_timeout(cls, moss_port):
        """Server should timeout & close HTTPS connection if no newline arrives for too long"""
        PAYLOAD = b"GET /very/long/path HTTP/1.1\r\nHost: test.local\r\nX-Delay: "
        with ssl_socket_connection(port=moss_port) as sock:
            sock.sendall(PAYLOAD)
            closed = wait_until_closed(sock, max_wait=MAX_HEADER_READ_DURATION + 5)
            assert closed, "HTTPS Connection with partial header (no newline) was not closed"

    def test_partial_header_no_newline_anomaly(cls, moss_runner, moss_port):
        """Server should log anomaly for HTTPS timeout"""
        PAYLOAD = b"GET /very/long/path HTTP/1.1\r\nHost: test.local\r\nX-Delay: "
        with ssl_socket_connection(port=moss_port) as sock:
            sock.sendall(PAYLOAD)
            wait_until_closed(sock, max_wait=MAX_HEADER_READ_DURATION + 5)

        srv = moss_runner.servers[0]
        expect_anomaly_detail(srv, PAYLOAD)

    def test_header_trickle_timeout(cls, moss_port):
        """Slowloris: trickle header bytes slowly over HTTPS"""
        with ssl_socket_connection(port=moss_port) as sock:
            sock.sendall(b"GET /very/long/path HTTP/1.1\r\n")
            sock.sendall(b"Host: test.local\r\n")
            sock.sendall(b"X-Delay: ")

            try:
                for _ in range(int(MAX_HEADER_READ_DURATION + 5)):
                    sock.sendall(b"x")
                    time.sleep(1)
            except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as e:
                return
            else:
                assert False, "HTTPS Connection slow trickle bytes in header not closed"

    def test_header_trickle_anomaly(cls, moss_runner, moss_port):
        """Slowloris anomaly detection over HTTPS"""
        PAYLOAD = b"GET /very/long/path HTTP/1.1\r\nHost: test.local\r\nX-Delay: "
        with ssl_socket_connection(port=moss_port) as sock:
            sock.sendall(PAYLOAD)

            try:
                for _ in range(int(MAX_HEADER_READ_DURATION + 5)):
                    sock.sendall(b"x")
                    time.sleep(1)
            except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
                pass

            srv = moss_runner.servers[0]
            while (event := srv.wait(0.1)) is not None:
                if "anomaly" in event and len(details := event.get("details", b"")) != 0:
                    assert details.startswith(PAYLOAD)
                    return
            else:
                assert False, "expected anomaly"

    def test_requestline_trickle_timeout(cls, moss_port):
        """Slowloris on request line over HTTPS"""
        with ssl_socket_connection(port=moss_port) as sock:
            sock.sendall(b"GET /very/long/path")

            try:
                for _ in range(int(MAX_HEADER_READ_DURATION + 5)):
                    sock.sendall(b"x")
                    time.sleep(1)
            except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as e:
                return
            else:
                assert False, "HTTPS Connection slow trickle bytes in requestline not closed"


@pytest.mark.slow
@pytest.mark.moss_https
class TestSlowBodyHTTPS:
    """Slow POST body (R.U.D.Y.) attacks over HTTPS"""

    def test_body_trickle_timeout(cls, moss_port):
        """R.U.D.Y.: slow POST body after headers over HTTPS"""
        with ssl_socket_connection(port=moss_port) as sock:
            sock.sendall(b"GET /very/long/path HTTP/1.1\r\n")
            sock.sendall(b"Content-Length: 100000\r\n")
            sock.sendall(b"Host: test.local\r\n\r\n")
            sock.sendall(b"abc")

            try:
                for _ in range(int(MAX_BODY_READ_DURATION + 5)):
                    sock.sendall(b"x")
                    time.sleep(1)
            except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as e:
                return
            else:
                assert False, "HTTPS Connection slow trickle bytes in body not closed"

    def test_body_trickle_then_pause_should_timeout(cls, moss_port):
        """Send bytes below timeout threshold, then pause - should timeout (HTTPS)"""
        with ssl_socket_connection(port=moss_port) as sock:
            sock.sendall(b"GET /very/long/path HTTP/1.1\r\n")
            sock.sendall(b"Content-Length: 100000\r\n")
            sock.sendall(b"Host: test.local\r\n\r\n")
            sock.sendall(b"abc")

            COUNT_TRICKLE = MAX_BODY_READ_DURATION - 2
            for _ in range(int(COUNT_TRICKLE)):
                sock.sendall(b"x")
                time.sleep(1)

            closed = wait_until_closed(sock, 7)
            assert closed, "HTTPS Connection should have closed"

    def test_slow_post_body(cls, moss_port):
        """R.U.D.Y.-like: slow POST body after headers (HTTPS)"""
        with ssl_socket_connection(port=moss_port) as sock:
            headers = (
                b"POST /upload HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Content-Length: 100000\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"\r\n"
            )
            sock.sendall(headers)

            try:
                sent = 0
                while sent < 100000:
                    chunk = min(8, 100000 - sent)
                    sock.sendall(b"A" * chunk)
                    sent += chunk
                    time.sleep(0.1)
            except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as e:
                pass
            else:
                assert False, "HTTPS Server allowed very slow large POST body"


@pytest.mark.slow
@pytest.mark.moss_https
@pytest.mark.moss_args("-vv", "--status-code", 201)
class TestNormalAfterAdversarialHTTPS:
    """Ensure normal requests work after adversarial attempts over HTTPS"""

    def test_normal_request_still_works_after_slow_attempts(cls, http_client):
        """Sanity: after adversarial attempts, normal clients should still succeed (HTTPS)"""
        for _ in range(5):
            r = http_client.get("/")
            assert r.status_code in (201,), "Normal HTTPS request failed after stress"
            time.sleep(0.4)
