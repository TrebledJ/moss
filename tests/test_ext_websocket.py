import pytest
import socket
import ssl
import struct
import hashlib
import base64
import time
import random
import select
import json
from pathlib import Path
from contextlib import contextmanager

WS_MAGIC = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

WS_CONTINUATION = 0x0
WS_TEXT = 0x1
WS_BINARY = 0x2
WS_CLOSE = 0x8
WS_PING = 0x9
WS_PONG = 0xA


def _encode_frame(opcode, payload=b"", mask=True):
    """Encode a client-to-server WebSocket frame (masked by default)."""
    frame = bytearray()
    frame.append(0x80 | opcode)
    length = len(payload)
    if length < 126:
        frame.append(0x80 | length if mask else length)
    elif length < 65536:
        frame.append(0x80 | 126 if mask else 126)
        frame.extend(struct.pack(">H", length))
    else:
        frame.append(0x80 | 127 if mask else 127)
        frame.extend(struct.pack(">Q", length))
    if mask:
        mask_key = bytes(random.randint(0, 255) for _ in range(4))
        frame.extend(mask_key)
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    frame.extend(payload)
    return bytes(frame)


def _create_ws_key():
    raw = bytes(random.randint(0, 255) for _ in range(16))
    return base64.b64encode(raw).decode()


def _compute_accept(key):
    return base64.b64encode(hashlib.sha1(key.encode() + WS_MAGIC).digest()).decode()


def recv_http_status(sock):
    """Read HTTP response headers and return (status_code, raw_headers)."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Server closed during handshake")
        data += chunk
    parts = data.split(b"\r\n", 1)[0].split(b" ", 2)
    return int(parts[1]), data


@contextmanager
def ws_connection(host="127.0.0.1", port=8000, path="/", timeout=10.0):
    """Open a raw TCP socket and perform WebSocket upgrade handshake.
    Yields the connected socket after upgrade.
    """
    key = _create_ws_key()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()
        sock.sendall(request)

        status, response = recv_http_status(sock)
        assert status == 101, f"Expected 101, got {status}: {response[:200]}"
        expected_accept = _compute_accept(key)
        assert expected_accept.encode() in response, f"Accept key mismatch"

        yield sock

    finally:
        try:
            sock.close()
        except OSError:
            pass


@contextmanager
def ssl_ws_connection(host="127.0.0.1", port=8000, path="/", timeout=10.0):
    """Open a TLS-wrapped socket and perform WebSocket upgrade handshake.
    Yields the SSL-wrapped connected socket after upgrade.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    key = _create_ws_key()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        ssl_sock = ctx.wrap_socket(sock, server_hostname=host)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()
        ssl_sock.sendall(request)
        status, response = recv_http_status(ssl_sock)
        assert status == 101, f"Expected 101, got {status}: {response[:200]}"
        expected_accept = _compute_accept(key)
        assert expected_accept.encode() in response
        yield ssl_sock
    finally:
        try:
            ssl_sock.close()
        except (OSError, NameError):
            try:
                sock.close()
            except OSError:
                pass


def recv_frame(sock, timeout=5.0):
    """Receive one WebSocket frame from server (unmasked). Returns (opcode, payload) or None."""
    deadline = time.monotonic() + timeout
    data = b""
    while time.monotonic() < deadline:
        try:
            ready = select.select([sock], [], [], max(0, deadline - time.monotonic()))
            if not ready[0]:
                continue
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except (BlockingIOError, ssl.SSLWantReadError):
            continue
        except (ConnectionResetError, BrokenPipeError, OSError):
            break

        # Try to parse a frame
        if len(data) >= 2:
            b1, b2 = data[0], data[1]
            opcode = b1 & 0x0F
            masked = bool(b2 & 0x80)
            payload_len = b2 & 0x7F

            offset = 2
            if payload_len == 126:
                if len(data) < 4:
                    continue
                payload_len = struct.unpack(">H", data[2:4])[0]
                offset = 4
            elif payload_len == 127:
                if len(data) < 10:
                    continue
                payload_len = struct.unpack(">Q", data[2:10])[0]
                offset = 10

            if masked:
                offset += 4

            total = offset + payload_len
            if len(data) >= total:
                payload = data[offset:total]
                if masked:
                    mask_key = data[offset - 4:offset]
                    payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
                return opcode, payload

    return None


def expect_event(srv, method_prefix):
    """Wait for a pushed event with method starting with prefix."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        event = srv.wait(0.5)
        if event is None:
            continue
        if event.get("method", "").startswith(method_prefix):
            return event
    raise AssertionError(f"Expected event with method prefix '{method_prefix}', none received")


# ────────────────────────────────────────────────
#   Tests
# ────────────────────────────────────────────────


@pytest.mark.moss_args("-e", "websocket")
class TestWebSocketHandshake:
    """Basic WS upgrade handshake (extension loaded)"""

    def test_upgrade_success(cls, moss_port):
        """WS upgrade should return 101 with correct Sec-WebSocket-Accept"""
        key = _create_ws_key()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(("127.0.0.1", moss_port))
            sock.sendall(
                f"GET / HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{moss_port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n".encode()
            )
            status, resp = recv_http_status(sock)
            assert status == 101, f"Expected 101, got {status}: {resp[:200]}"
            expected = _compute_accept(key)
            assert expected.encode() in resp, f"Accept key mismatch, expected {expected}"
        finally:
            sock.close()

    def test_upgrade_missing_key_no_handshake(cls, moss_port):
        """Without Sec-WebSocket-Key, should not upgrade (fall through to default)"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(("127.0.0.1", moss_port))
            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"\r\n"
            )
            status, _ = recv_http_status(sock)
            assert status != 101, "Should NOT have upgraded"
        finally:
            sock.close()


class TestWebSocketUpgradeNoExt:
    """WS upgrade without -e websocket extension (falls through to normal GET)"""

    def test_upgrade_falls_through_without_extension(cls, moss_port):
        """Without websocket extension, WS upgrade falls through to normal GET"""
        key = _create_ws_key()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(("127.0.0.1", moss_port))
            sock.sendall(
                f"GET / HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{moss_port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n".encode()
            )
            status, _ = recv_http_status(sock)
            assert status != 101, "Should NOT have upgraded without -e websocket"
        finally:
            sock.close()


@pytest.mark.moss_args("-e", "websocket")
class TestWebSocketFrameIO:
    """Frame send/receive through WS connection"""

    def test_send_text_frame(cls, moss_port, moss_runner):
        """Send a masked text frame, verify event is pushed"""
        with ws_connection(port=moss_port) as sock:
            payload = b"Hello, WebSocket!"
            frame = _encode_frame(WS_TEXT, payload, mask=True)
            sock.sendall(frame)

            srv = moss_runner.servers[0]
            event = expect_event(srv, "WS-TEXT")
            assert event.get("proto") in ("WS", "WSS")
            assert event.get("path") == "/"
            assert event.get("body") == payload

    def test_send_binary_frame(cls, moss_port, moss_runner):
        """Send a masked binary frame, verify event is pushed"""
        with ws_connection(port=moss_port) as sock:
            payload = bytes(range(256))
            frame = _encode_frame(WS_BINARY, payload, mask=True)
            sock.sendall(frame)

            srv = moss_runner.servers[0]
            event = expect_event(srv, "WS-BINARY")
            assert event.get("body") == payload

    def test_large_frame(cls, moss_port, moss_runner):
        """Send a large (>65535 bytes) masked frame"""
        with ws_connection(port=moss_port) as sock:
            payload = b"X" * 100000
            frame = _encode_frame(WS_TEXT, payload, mask=True)
            sock.sendall(frame)

            srv = moss_runner.servers[0]
            event = expect_event(srv, "WS-TEXT")
            assert len(event.get("body", b"")) == 100000

    def test_multiple_frames(cls, moss_port, moss_runner):
        """Send multiple frames, verify each creates an event"""
        with ws_connection(port=moss_port) as sock:
            for i in range(3):
                payload = f"Frame {i}".encode()
                frame = _encode_frame(WS_TEXT, payload, mask=True)
                sock.sendall(frame)

            srv = moss_runner.servers[0]
            count = 0
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and count < 3:
                event = srv.wait(0.5)
                if event and event.get("method", "").startswith("WS-"):
                    count += 1
            assert count == 3, f"Expected 3 WS events, got {count}"


@pytest.mark.moss_args("-e", "websocket")
class TestWebSocketPingPong:
    """Ping/pong protocol behavior"""

    def test_server_responds_to_ping(cls, moss_port):
        """Server should respond to PING with PONG (same payload)"""
        with ws_connection(port=moss_port) as sock:
            sock.settimeout(5)
            payload = b"pingpayload"
            frame = _encode_frame(WS_PING, payload, mask=True)
            sock.sendall(frame)

            result = recv_frame(sock, timeout=5)
            assert result is not None, "No PONG received"
            opcode, pong_payload = result
            assert opcode == WS_PONG, f"Expected PONG (0xA), got opcode {opcode}"
            assert pong_payload == payload, f"PONG payload mismatch: {pong_payload} != {payload}"


@pytest.mark.moss_args("-e", "websocket")
class TestWebSocketClose:
    """Close frame behavior"""

    def test_close_handshake(cls, moss_port, moss_runner):
        """Server should echo CLOSE frame and close connection"""
        with ws_connection(port=moss_port) as sock:
            sock.settimeout(5)
            frame = _encode_frame(WS_CLOSE, struct.pack(">H", 1000) + b"normal", mask=True)
            sock.sendall(frame)

            result = recv_frame(sock, timeout=5)
            assert result is not None, "No CLOSE response"
            opcode, payload = result
            assert opcode == WS_CLOSE, f"Expected CLOSE (0x8), got opcode {opcode}"

            try:
                remaining = sock.recv(1)
                assert remaining == b"", "Expected connection closed after CLOSE"
            except (ConnectionResetError, BrokenPipeError, OSError, socket.timeout):
                pass

    def test_close_without_reason(cls, moss_port, moss_runner):
        """CLOSE frame with no payload should get CLOSE response"""
        with ws_connection(port=moss_port) as sock:
            sock.settimeout(5)
            frame = _encode_frame(WS_CLOSE, b"", mask=True)
            sock.sendall(frame)

            result = recv_frame(sock, timeout=5)
            assert result is not None, "No CLOSE response"
            opcode, _ = result
            assert opcode == WS_CLOSE


@pytest.mark.moss_https
@pytest.mark.moss_args("-e", "websocket")
class TestWebSocketOverTLS:
    """WSS (WebSocket over TLS) tests"""

    def test_wss_upgrade_success(cls, moss_port):
        """WSS upgrade should return 101 with correct accept key"""
        with ssl_ws_connection(port=moss_port) as sock:
            pass

    def test_wss_send_text_frame(cls, moss_port, moss_runner):
        """Send masked text frame over TLS, verify event is pushed"""
        with ssl_ws_connection(port=moss_port) as sock:
            payload = b"Hello WSS!"
            sock.sendall(_encode_frame(WS_TEXT, payload, mask=True))
            srv = moss_runner.servers[0]
            event = expect_event(srv, "WS-TEXT")
            assert event.get("body") == payload

    def test_wss_send_binary_frame(cls, moss_port, moss_runner):
        """Send masked binary frame over TLS, verify event is pushed"""
        with ssl_ws_connection(port=moss_port) as sock:
            payload = bytes(range(128))
            sock.sendall(_encode_frame(WS_BINARY, payload, mask=True))
            srv = moss_runner.servers[0]
            event = expect_event(srv, "WS-BINARY")
            assert event.get("body") == payload

    def test_wss_large_frame(cls, moss_port, moss_runner):
        """Send large (>65535 bytes) masked frame over TLS"""
        with ssl_ws_connection(port=moss_port) as sock:
            payload = b"Y" * 100000
            sock.sendall(_encode_frame(WS_TEXT, payload, mask=True))
            srv = moss_runner.servers[0]
            event = expect_event(srv, "WS-TEXT")
            assert len(event.get("body", b"")) == 100000

    def test_wss_ping_pong(cls, moss_port):
        """Server should respond to PING with PONG over TLS"""
        with ssl_ws_connection(port=moss_port) as sock:
            sock.settimeout(5)
            payload = b"wss-ping"
            sock.sendall(_encode_frame(WS_PING, payload, mask=True))
            result = recv_frame(sock, timeout=5)
            assert result is not None, "No PONG received"
            opcode, pong_payload = result
            assert opcode == WS_PONG
            assert pong_payload == payload

    def test_wss_close_handshake(cls, moss_port, moss_runner):
        """CLOSE frame echo over TLS"""
        with ssl_ws_connection(port=moss_port) as sock:
            sock.settimeout(5)
            sock.sendall(_encode_frame(WS_CLOSE, struct.pack(">H", 1000), mask=True))
            result = recv_frame(sock, timeout=5)
            assert result is not None, "No CLOSE response"
            opcode, _ = result
            assert opcode == WS_CLOSE


_JSONL_FILE = "ws_test_output.jsonl"


@pytest.mark.moss_args("-e", "websocket", "--jsonl", _JSONL_FILE)
class TestWebSocketJsonlOutput:
    """WS frame events logged to JSONL"""

    def _poll_all(cls, moss_runner):
        for _ in range(4):
            moss_runner.poll(timeout_per_server=0.3)

    def test_jsonl_ws_text(cls, moss_port, moss_runner):
        """WS TEXT frame should appear in JSONL with correct fields"""
        payload = b"jsonl-text-payload"
        with ws_connection(port=moss_port) as sock:
            sock.sendall(_encode_frame(WS_TEXT, payload, mask=True))
        time.sleep(0.1)
        cls._poll_all(moss_runner)
        try:
            assert Path(_JSONL_FILE).exists()
            with open(_JSONL_FILE) as f:
                lines = f.readlines()
            ws_lines = [l for l in lines if json.loads(l).get("ws_event")]
            assert len(ws_lines) >= 1, f"No WS events in JSONL: {lines}"
            data = json.loads(ws_lines[0])
            assert data.get("method") == "WS-TEXT-1"
            assert data.get("proto") in ("WS", "WSS")
            assert data.get("body") == "jsonl-text-payload"
            assert data.get("ws_event") is True
            assert "filter_matches" in data
        finally:
            Path(_JSONL_FILE).unlink(missing_ok=True)

    def test_jsonl_ws_binary(cls, moss_port, moss_runner):
        """WS BINARY frame should appear in JSONL"""
        payload = bytes(range(64))
        with ws_connection(port=moss_port) as sock:
            sock.sendall(_encode_frame(WS_BINARY, payload, mask=True))
        time.sleep(0.1)
        cls._poll_all(moss_runner)
        try:
            assert Path(_JSONL_FILE).exists()
            with open(_JSONL_FILE) as f:
                lines = f.readlines()
            ws_lines = [l for l in lines if json.loads(l).get("ws_event")]
            assert len(ws_lines) >= 1
            data = json.loads(ws_lines[0])
            assert data.get("method") == "WS-BINARY-2"
            assert data.get("ws_event") is True
            assert "filter_matches" in data
        finally:
            Path(_JSONL_FILE).unlink(missing_ok=True)


@pytest.mark.moss_args("-e", "websocket", "--simple")
class TestWebSocketSimpleLog:
    """WS frame events in simple log format (stderr output)"""

    def test_simple_ws_output(cls, moss_port, moss_runner, capsys):
        """WS TEXT frame should appear in simple stderr log"""
        with ws_connection(port=moss_port) as sock:
            sock.sendall(_encode_frame(WS_TEXT, b"simple-log-test", mask=True))
        time.sleep(0.1)
        capsys.readouterr()
        for _ in range(4):
            moss_runner.poll(timeout_per_server=0.3)
        _out, err = capsys.readouterr()
        assert "WSFRM" in err, f"Expected WSFRM in stderr, got: {err}"
        assert "simple-log-test" in err
        assert "TEXT" in err


@pytest.mark.moss_args("-e", "websocket", "--filter", "secret", "--simple", "--output-all")
class TestWebSocketFilteredLog:
    """WS filter matching in log output"""

    def test_filter_match_shows_wsftm(cls, moss_port, moss_runner, capsys):
        """Matching WS payload should show WSFRM in stderr"""
        with ws_connection(port=moss_port) as sock:
            sock.sendall(_encode_frame(WS_TEXT, b"contains-secret-key", mask=True))
        time.sleep(0.1)
        capsys.readouterr()
        for _ in range(4):
            moss_runner.poll(timeout_per_server=0.3)
        _out, err = capsys.readouterr()
        assert "WSFRM" in err, f"Expected WSFRM, got: {err}"

    def test_filter_no_match_shows_wsrej(cls, moss_port, moss_runner, capsys):
        """Non-matching WS payload should show WSREJ in stderr"""
        with ws_connection(port=moss_port) as sock:
            sock.sendall(_encode_frame(WS_TEXT, b"no-match-here", mask=True))
        time.sleep(0.1)
        capsys.readouterr()
        for _ in range(4):
            moss_runner.poll(timeout_per_server=0.3)
        _out, err = capsys.readouterr()
        assert "WSREJ" in err, f"Expected WSREJ, got: {err}"
        assert "WSFRM" not in err
