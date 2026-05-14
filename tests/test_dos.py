import pytest
import socket
import time
import threading
from contextlib import contextmanager

# ────────────────────────────────────────
#   Configuration – adjust according to your mitigations
# ────────────────────────────────────────

MIN_ACCEPTABLE_FIRST_BYTE_TIMEOUT = 5.0
MAX_ACCEPTABLE_FIRST_BYTE_TIMEOUT = 10.0       # seconds – how long we allow the server to tolerate bad clients
MAX_ACCEPTABLE_CONNECTION_TIMEOUT = 30.0       # seconds – the maximum duration the connection should last
SLOW_BYTE_INTERVAL = 4.5          # seconds between bytes
LINE_TIMEOUT_EXPECTED = 10.0      # how long to allow tolerate bad lines
# MAX_BODY_READ_DURATION = 5.0      # how long to allow tolerate bad lines
from moss.moss import TIMEOUT_FOR_BODY as MAX_BODY_READ_DURATION

# ────────────────────────────────────────
#   Helpers
# ────────────────────────────────────────

@contextmanager
def socket_connection(host: str = "127.0.0.1", port: int = 8000, timeout: float = 15.0):
    """Context manager for a raw socket – auto-closes"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.setblocking(False)
        yield sock
    finally:
        try:
            sock.close()
        except:
            pass

@contextmanager
def timeout_as_error():
    try:
        yield None
    except TimeoutError:
        assert False, "got client timeout; this means the server did not timeout in time"
    
def wait_until_closed(sock: socket.socket, max_wait: float = 15.0) -> bool:
    """Poll until the socket is closed by remote (server)"""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        try:
            if not sock.recv(1):
                # Client has disconnected
                return True
            time.sleep(0.2)
        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as e:
            pass
    return False

def expect_anomaly(srv, anomaly_description, with_tags=[]):
    while (event := srv.wait(1)) is not None:
        tags_ok = len(set(with_tags) - set(event.get("tags", []))) == 0
        if anomaly_description in event.get("anomaly", "") and tags_ok:
            return  # Assert ok! Return early.
    else:
        assert False, f"expected anomaly containing '{anomaly_description}'"

def expect_anomaly_detail(srv, payload):
    while (event := srv.wait(1)) is not None:
        if "anomaly" in event and len(details := event.get("details", b"")) != 0:
            assert details == payload
            return  # Assert ok! Return early.
    else:
        assert False, "expected anomaly"

# ────────────────────────────────────────
#   Tests
# ────────────────────────────────────────

@pytest.mark.slow
@pytest.mark.moss_args("-vv", "--status-code", 201)
class TestDOS:
    def test_partial_header_sanity_check(cls, moss_port):
        """Server should stay open for a little bit even when new line hasn't arrived"""
        with socket_connection(port=moss_port) as sock:
            sock.sendall(b"GET /very/long/path HTTP/1.1\r\n")
            sock.sendall(b"Host: test.local\r\n")
            sock.sendall(b"X-Delay: ") # no newline
            closed = wait_until_closed(sock, 2) # Does it timeout within a few seconds?
            assert not closed, "Connection should remain open for a while"

    def test_partial_header_no_newline_timeout(cls, moss_port):
        """Server should timeout & close connection if no newline arrives for too long"""
        PAYLOAD = b"GET /very/long/path HTTP/1.1\r\nHost: test.local\r\nX-Delay: "
        with socket_connection(port=moss_port) as sock:
            sock.sendall(PAYLOAD)
            closed = wait_until_closed(sock, LINE_TIMEOUT_EXPECTED + 5)
            assert closed, "Connection with partial header (no newline) was not closed"
        
    def test_partial_header_no_newline_anomaly(cls, moss_runner, moss_port):
        """Server should timeout & close connection if no newline arrives for too long"""
        PAYLOAD = b"GET /very/long/path HTTP/1.1\r\nHost: test.local\r\nX-Delay: "
        with socket_connection(port=moss_port) as sock:
            sock.sendall(PAYLOAD)
        
        srv = moss_runner.servers[0]
        expect_anomaly_detail(srv, PAYLOAD)

    def test_header_trickle_timeout(cls, moss_port):
        with socket_connection(port=moss_port) as sock:
            # Send partial request line + some header bytes, but never a \n
            sock.sendall(b"GET /very/long/path HTTP/1.1\r\n")
            sock.sendall(b"Host: test.local\r\n")
            sock.sendall(b"X-Delay: ")
            
            # Trickle a few more bytes very slowly
            
            try:
                for _ in range(int(LINE_TIMEOUT_EXPECTED + 10)):
                    sock.sendall(b"x")
                    time.sleep(1)
            except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as e:
                return # Timeout is expected
            else:
                assert False, "Connection slow trickly bytes in header not closed"

    def test_header_trickle_anomaly(cls, moss_runner, moss_port):
        PAYLOAD = b"GET /very/long/path HTTP/1.1\r\nHost: test.local\r\nX-Delay: "
        with socket_connection(port=moss_port) as sock:
            # Send partial request line + some header bytes, but never a \n
            sock.sendall(PAYLOAD)
            
            # Trickle a few more bytes very slowly
            try:
                for _ in range(int(LINE_TIMEOUT_EXPECTED + 10)):
                    sock.sendall(b"x")
                    time.sleep(1)
            except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as e:
                # return # Timeout is expected
                pass
            else:
                assert False, "Connection slow trickly bytes in header not closed"
            
            srv = moss_runner.servers[0]
            while (event := srv.wait(0.1)) is not None:
                if "anomaly" in event and len(details := event.get("details", b"")) != 0:
                    assert details.startswith(PAYLOAD)
                    return # Assert ok! Return early.
            else:
                assert False, "expected anomaly"
    
    def test_requestline_trickle_timeout(cls, moss_port):
        with socket_connection(port=moss_port) as sock:
            # Send partial request line, but never a \n
            sock.sendall(b"GET /very/long/path")
            
            # Trickle a few more bytes very slowly
            try:
                for _ in range(int(LINE_TIMEOUT_EXPECTED + 10)):
                    sock.sendall(b"x")
                    time.sleep(1)
            except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as e:
                return # Timeout is expected
            else:
                assert False, "Connection slow trickly bytes in requestline not closed"

    def test_body_trickle_timeout(cls, moss_port):
        with socket_connection(port=moss_port) as sock:
            # Send partial request line, but never a \n
            sock.sendall(b"GET /very/long/path HTTP/1.1\r\n")
            sock.sendall(b"Content-Length: 100000\r\n")
            sock.sendall(b"Host: test.local\r\n\r\n")
            sock.sendall(b"abc")
            
            # Trickle a few more bytes very slowly
            try:
                for _ in range(int(MAX_BODY_READ_DURATION + 10)):
                    sock.sendall(b"x")
                    time.sleep(1)
            except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as e:
                return # Timeout is expected
            else:
                assert False, "Connection slow trickly bytes in requestline not closed"

    def test_body_trickle_then_pause_should_timeout(cls, moss_port):
        with socket_connection(port=moss_port) as sock:
            # Send partial request line, but never a \n
            sock.sendall(b"GET /very/long/path HTTP/1.1\r\n")
            sock.sendall(b"Content-Length: 100000\r\n")
            sock.sendall(b"Host: test.local\r\n\r\n")
            sock.sendall(b"abc")
            
            # Trickle a few bytes slowly, below the maximum read duration, then pause
            COUNT_TRICKLE = MAX_BODY_READ_DURATION - 2
            for _ in range(int(COUNT_TRICKLE)):
                sock.sendall(b"x")
                time.sleep(1)
            
            closed = wait_until_closed(sock, 10)
            assert closed, "Connection should have closed"

    
    def test_slow_post_body(cls, moss_port):
        """R.U.D.Y.-like: slow POST body after headers"""
        with socket_connection(port=moss_port) as sock:
            headers = (
                b"POST /upload HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Content-Length: 100000\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"\r\n"
            )
            sock.sendall(headers)

            
            try:
                # Now trickle body very slowly
                sent = 0
                while sent < 100000:
                    chunk = min(8, 100000 - sent)
                    sock.sendall(b"\x00" * chunk)
                    sent += chunk
                    time.sleep(0.1)  # tune to be just below your body timeout
            except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as e:
                # Ok, expected close
                pass
            else:
                assert False, "Server allowed very slow large POST body"

    
    def test_normal_request_still_works_after_slow_attempts(cls, http_client):
        """Sanity: after adversarial attempts, normal clients should still succeed"""
        for _ in range(5):
            r = http_client.get("/")
            assert r.status_code in (201,), "Normal request failed after stress"
            time.sleep(0.4)
