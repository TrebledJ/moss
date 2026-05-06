import pytest
import socket
import time
import queue
import subprocess
import sys


class TestPortScanDetection:
    """Test port scan detection (anomaly: 'portscan')."""

    @pytest.mark.moss_args("-vv")
    def test_connection_reset_detection(self, moss_runner, moss_port):
        """Connection reset should be logged as port scan anomaly."""
        # Open and immediately reset connection (simulate nmap -sT)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(('127.0.0.1', moss_port))
            sock.close()  # Reset connection
        except:
            pass

        time.sleep(0.5)

        # Check for anomaly in server queue
        server = moss_runner.servers[0]
        try:
            anomaly = server.wait(timeout=2)
            assert 'portscan' in anomaly.get('tags', []), f"Expected 'portscan' tag in {anomaly}"
        except queue.Empty:
            pytest.fail("No anomaly detected for connection reset")

    @pytest.mark.moss_args("-vv")
    def test_empty_connection_detection(self, moss_runner, moss_port):
        """Empty connection (nc then ^C) should be logged as port scan."""
        # Open connection and wait (simulate nc $host $port then wait)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(('127.0.0.1', moss_port))
            time.sleep(11)  # Wait longer than timeout
        except socket.timeout:
            pass
        except:
            pass
        finally:
            try:
                sock.close()
            except:
                pass

        # Check for anomaly in server queue
        server = moss_runner.servers[0]
        try:
            anomaly = server.wait(timeout=2)
            assert 'portscan' in anomaly.get('tags', []), f"Expected 'portscan' tag in {anomaly}"
        except queue.Empty:
            pytest.fail("No anomaly detected for empty connection")


class TestSSLErrors:
    """Test SSL error logging as anomalies."""

    @pytest.mark.moss_args("-vv")
    def test_ssl_error_logged(self, moss_runner, moss_port):
        """Invalid SSL connections should be logged as anomalies."""
        # Send invalid SSL data to non-HTTPS server
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(('127.0.0.1', moss_port))
            # Send some random bytes (not valid SSL/TLS)
            sock.send(b'\x16\x03\x01\x00\x00\x01\x00')
            time.sleep(0.5)
            sock.close()
        except:
            pass

        time.sleep(0.5)

        # Check for SSL-related anomaly (may be 'socket opened, but no incoming bytes' with portscan tag)
        server = moss_runner.servers[0]
        try:
            anomaly = server.wait(timeout=2)
            # The server may log this as 'socket opened, but no incoming bytes' with portscan tag
            # or it may detect it as an SSL error
            anomaly_text = anomaly.get('anomaly', '').lower()
            tags = anomaly.get('tags', [])
            assert 'ssl' in anomaly_text or 'portscan' in tags or 'ssl' in str(tags), \
                f"Expected SSL-related anomaly: {anomaly}"
        except queue.Empty:
            pytest.fail("No anomaly detected for SSL error")


class TestTimeoutHandling:
    """Test timeout handling and anomaly detection."""

    @pytest.mark.moss_args("-vv")
    def test_timeout_anomaly(self, moss_runner, moss_port):
        """Connection timeout should be logged as anomaly (portscan/dos)."""
        # Open connection but don't send any data
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(('127.0.0.1', moss_port))
            # Don't send anything, just wait
            time.sleep(11)  # Wait for timeout
        except socket.timeout:
            pass
        except:
            pass
        finally:
            try:
                sock.close()
            except:
                pass

        # Check for timeout anomaly
        server = moss_runner.servers[0]
        try:
            anomaly = server.wait(timeout=2)
            assert 'timeout' in anomaly.get('anomaly', '').lower() or \
                   'portscan' in anomaly.get('tags', []) or \
                   'dos' in anomaly.get('tags', []), \
                f"Expected timeout/portscan/dos anomaly: {anomaly}"
        except queue.Empty:
            pytest.fail("No anomaly detected for timeout")
