import pytest
import socket
import time


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
