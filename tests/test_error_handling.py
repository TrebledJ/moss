import pytest
import socket
import time
import queue
from contextlib import contextmanager

@contextmanager
def socket_connection(host: str = "127.0.0.1", port: int = 8000, timeout: float = 15.0):
    """Context manager for a raw socket – auto-closes"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        sock.setblocking(False)
        yield sock
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


class TestInvalidSSL:
    """Test invalid SSL connection handling."""

    @pytest.mark.moss_args("-vv")
    def test_invalid_ssl_to_non_https(self, moss_runner, moss_port):
        """Send invalid SSL data to non-HTTPS server."""
        server = moss_runner.servers[0]

        # Send invalid SSL/TLS handshake
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(('127.0.0.1', moss_port))
            # Send invalid TLS hello (wrong version)
            sock.send(b'\x16\x03\x00\x00\x00')  # SSL 3.0 instead of TLS 1.0+
            time.sleep(0.5)
            sock.close()
        except:
            pass

        time.sleep(1)

        # Should detect SSL error or port scan
        try:
            event = server.wait(timeout=2)
            assert 'ssl' in event.get('anomaly', '').lower() or \
                   'portscan' in event.get('tags', []), \
                f"Expected SSL-related anomaly: {event}"
        except queue.Empty:
            pytest.fail("No anomaly detected for invalid SSL")

    @pytest.mark.moss_args("-vv", "--https", "--certfile", "tests/data/server.crt", "--keyfile", "tests/data/server.key")
    def test_invalid_ssl_to_https(self, moss_runner, moss_port):
        """Send invalid SSL data to HTTPS server."""
        server = moss_runner.servers[0]

        # Send garbage data (not SSL handshake)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(('127.0.0.1', moss_port))
            sock.send(b'GET / HTTP/1.1\r\n\r\n')  # Plain HTTP to HTTPS port
            time.sleep(0.5)
            sock.close()
        except:
            pass

        time.sleep(1)

        # Should detect SSL error
        try:
            event = server.wait(timeout=2)
            assert 'ssl' in event.get('anomaly', '').lower() or \
                   'ssl' in str(event.get('tags', [])), \
                f"Expected SSL-related anomaly: {event}"
        except queue.Empty:
            pytest.fail("No anomaly detected for invalid SSL to HTTPS")


class TestMalformedRequests:
    """Test malformed HTTP request handling."""

    @pytest.mark.moss_args("-vv")
    def test_invalid_http_version(self, moss_runner, moss_port):
        """Send request with invalid HTTP version."""
        server = moss_runner.servers[0]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(('127.0.0.1', moss_port))
            # Send invalid HTTP version
            sock.send(b'GET / HTTP/99.99\r\nHost: 127.0.0.1\r\n\r\n')
            time.sleep(0.5)
            sock.close()
        except:
            pass

        time.sleep(1)

        # Should detect non-HTTP request or timeout
        try:
            event = server.wait(timeout=2)
            assert 'non-http' in event.get('anomaly', '').lower() or \
                   'portscan' in event.get('tags', []) or \
                   'timeout' in event.get('anomaly', '').lower(), \
                f"Expected non-HTTP or timeout anomaly: {event}"
        except queue.Empty:
            pytest.fail("No anomaly detected for malformed request")

    @pytest.mark.moss_args("-vv")
    def test_garbage_request(self, moss_runner, moss_port):
        """Send garbage data instead of HTTP request."""
        server = moss_runner.servers[0]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(('127.0.0.1', moss_port))
            # Send garbage
            sock.send(b'GARBAGE DATA !@#$%^&*()\r\n\r\n')
            time.sleep(0.5)
            sock.close()
        except:
            pass

        time.sleep(1)

        # Should detect non-HTTP request
        try:
            event = server.wait(timeout=2)
            assert 'non-http' in event.get('anomaly', '').lower() or \
                   'invalid http' in event.get('anomaly', '').lower() or \
                   'portscan' in event.get('tags', []), \
                f"Expected non-HTTP anomaly: {event}"
        except queue.Empty:
            pytest.fail("No anomaly detected for garbage request")

    @pytest.mark.moss_args("-vv")
    def test_no_request_line(self, moss_runner, moss_port):
        """Send only headers without request line."""
        server = moss_runner.servers[0]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(('127.0.0.1', moss_port))
            # Send only headers (no request line)
            sock.send(b'Host: 127.0.0.1\r\nContent-Length: 0\r\n\r\n')
            time.sleep(0.5)
            sock.close()
        except:
            pass

        time.sleep(1)

        # Should detect non-HTTP request
        try:
            event = server.wait(timeout=2)
            assert 'non-http' in event.get('anomaly', '').lower() or \
                   'invalid http' in event.get('anomaly', '').lower() or \
                   'portscan' in event.get('tags', []), \
                f"Expected non-HTTP anomaly: {event}"
        except queue.Empty:
            pytest.fail("No anomaly detected for missing request line")


class TestTimeoutHandling:
    """Test timeout handling (SOCKET_TIMEOUT, TIMEOUT_FOR_FIRST_BYTE, etc.)."""

    @pytest.mark.moss_args("-vv")
    def test_first_byte_timeout(self, moss_runner, moss_port):
        """Test timeout waiting for first byte."""
        server = moss_runner.servers[0]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(('127.0.0.1', moss_port))
            # Send one byte and wait (trigger first byte timeout)
            sock.send(b'G')  # Start request but don't complete
            time.sleep(11)  # Wait longer than TIMEOUT_FOR_FIRST_BYTE
            sock.close()
        except:
            pass

        time.sleep(1)

        # Should detect timeout
        try:
            event = server.wait(timeout=2)
            assert 'timeout' in event.get('anomaly', '').lower() or \
                   'portscan' in event.get('tags', []) or \
                   'dos' in event.get('tags', []), \
                f"Expected timeout anomaly: {event}"
        except queue.Empty:
            pytest.fail("No anomaly detected for first byte timeout")

    @pytest.mark.moss_args("-vv")
    def test_line_timeout(self, moss_runner, moss_port):
        """Test timeout waiting for complete line."""
        server = moss_runner.servers[0]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(('127.0.0.1', moss_port))
            # Send partial request line (no \r\n)
            sock.send(b'GET / ')
            time.sleep(11)  # Wait longer than LINE_TIMEOUT_EXPECTED
            sock.close()
        except:
            pass

        time.sleep(1)

        # Should detect timeout
        try:
            event = server.wait(timeout=2)
            assert 'request timed out' in event.get('anomaly', '').lower() or \
                   'portscan' in event.get('tags', []) or \
                   'dos' in event.get('tags', []), \
                f"Expected timeout anomaly: {event}"
        except queue.Empty:
            pytest.fail("No anomaly detected for line timeout")


class TestIdle:
    def test_idle_connection_regression_is_open(cls, moss_port):
        """Server should remain open when the connection was recently opened"""
        with socket_connection(port=moss_port) as sock:
            # send nothing
            closed = wait_until_closed(sock, max_wait=max(2, 5.0 - 1))
            assert not closed, "Server unexpected closed shortly after connection was initiated"

    def test_idle_connection_is_closed(cls, moss_port):
        """Server should eventually close idle connections (no bytes sent)"""
        with socket_connection(port=moss_port) as sock:
            # send nothing
            closed = wait_until_closed(sock, max_wait=10.0 + 2)
            assert closed, "Server did not close truly idle connection in reasonable time"

    def test_anomaly_portscan(cls, moss_runner, moss_port):
        with socket_connection(port=moss_port):
            pass
        srv = moss_runner.servers[0]
        expect_anomaly(srv, "socket open", with_tags=["portscan"])


class TestIncomplete:
    def test_partial_request_line_no_newline_is_closed(cls, moss_runner, moss_port):
        PAYLOAD = b"GET /endpoint HTTP/1.1"
        with socket_connection(port=moss_port) as sock:
            sock.sendall(PAYLOAD)
            closed = wait_until_closed(sock, 10.0 + 2)
            assert closed, "Connection with partial bytes (no newline) was not closed"
        
        srv = moss_runner.servers[0]
        expect_anomaly_detail(srv, PAYLOAD)

    def test_raw_tcp(cls, moss_runner, moss_port):
        assert moss_runner.servers[0].port == moss_port, "expected same port"
        PAYLOAD = b"bytes\x01\x02\x03\x04"
        with socket_connection(port=moss_port) as sock:
            sock.sendall(PAYLOAD)
            closed = wait_until_closed(sock, 10.0 + 2)
            assert closed, "Connection with raw tcp (no newline) was not closed"
        
        srv = moss_runner.servers[0]
        expect_anomaly_detail(srv, PAYLOAD)
        
    def test_raw_tcp_with_newline(cls, moss_runner, moss_port):
        PAYLOAD = b"HELLO whatchamacallit xyz 0.1\r\nDo you have a moment\x01\x02\x03\x04?\nAnswer: yes\n"
        with socket_connection(port=moss_port) as sock:
            sock.sendall(PAYLOAD)
            closed = wait_until_closed(sock, 10.0 + 2)
            assert closed, "Connection with raw tcp (with newline) was not closed"
        
        srv = moss_runner.servers[0]
        expect_anomaly_detail(srv, PAYLOAD)
        
    def test_raw_tcp_00_ff_bytes(cls, moss_runner, moss_port):
        PAYLOAD = bytes(range(0, 256))
        with socket_connection(port=moss_port) as sock:
            sock.sendall(PAYLOAD)
            closed = wait_until_closed(sock, 10.0 + 2)
            assert closed, "Connection with raw tcp (with newline and bytes) was not closed"
        
        srv = moss_runner.servers[0]
        expect_anomaly_detail(srv, PAYLOAD)
        
    def test_http_09(cls, moss_runner, moss_port):
        PAYLOAD = b"GET /test\r\n\r\n"
        with socket_connection(port=moss_port) as sock:
            sock.sendall(PAYLOAD)
            closed = wait_until_closed(sock, 10.0 + 2)
            assert closed, "Connection was not closed"
        
        srv = moss_runner.servers[0]
        expect_anomaly_detail(srv, PAYLOAD)
        
    def test_looks_like_http_09(cls, moss_runner, moss_port):
        PAYLOAD = b"HELLO /test\r\nHost: example.com\r\n"
        with socket_connection(port=moss_port) as sock:
            sock.sendall(PAYLOAD)
            closed = wait_until_closed(sock, 10.0 + 2)
            assert closed, "Connection was not closed"
        
        srv = moss_runner.servers[0]
        expect_anomaly_detail(srv, PAYLOAD)
