"""
ext/websocket.py

WebSocket OAST extension for MOSS.

Handles WebSocket upgrade requests and logs incoming frames as structured
events through the standard event pipeline — same as HTTP requests —
so they appear in logs, JSONL, and notifications.

WebSocket support is enabled automatically when this extension is loaded.
The upgrade (101 Switching Protocols) is logged as a regular HTTP
request through EnqueueProcessor. Subsequent WS frames are logged
as WS-TEXT / WS-BINARY events with proto=WS (or WSS for TLS).

Usage:
    moss -e websocket
    moss -e websocket --ws-path /myws --websocket-tester /wstest

CLI flags:
    --ws-path PATH           Restrict WS handling to a specific path (default: any path)
    --websocket-tester PATH  Serve the WebSocket tester HTML page at this path (default: disabled)
"""

import hashlib
import base64
import struct
import select
import ssl
from pathlib import Path
from dataclasses import dataclass, field

GROUP = "websocket (ext/websocket.py)"

WS_CONTINUATION = 0x0
WS_TEXT = 0x1
WS_BINARY = 0x2
WS_CLOSE = 0x8
WS_PING = 0x9
WS_PONG = 0xA

_WS_MAGIC = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _field(default, group=None, doc="", metadata={}, flags=[], choices=[], **kwargs):
    dwargs = {}
    if type(default).__name__ in ("function", "type"):
        dwargs["default_factory"] = default
    else:
        dwargs["default"] = default
    return field(**dwargs, metadata=metadata | dict(group=group, doc=doc, flags=flags, choices=choices, **kwargs))


def _create_accept_key(key):
    digest = hashlib.sha1(key.encode() + _WS_MAGIC).digest()
    return base64.b64encode(digest).decode()


def _encode_frame(opcode, payload=b""):
    """Encode a server-to-client WebSocket frame (unmasked, FIN=1)."""
    frame = bytearray()
    frame.append(0x80 | opcode)
    length = len(payload)
    if length < 126:
        frame.append(length)
    elif length < 65536:
        frame.append(126)
        frame.extend(struct.pack(">H", length))
    else:
        frame.append(127)
        frame.extend(struct.pack(">Q", length))
    frame.extend(payload)
    return bytes(frame)


def _decode_frames(buffer):
    """Parse all complete WebSocket frames from buffer.
    Returns (frames, remaining_bytes).
    Each frame: (fin, opcode, payload)
    """
    frames = []
    while True:
        if len(buffer) < 2:
            break
        b1, b2 = buffer[0], buffer[1]
        fin = bool(b1 & 0x80)
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        payload_len = b2 & 0x7F

        offset = 2
        if payload_len == 126:
            if len(buffer) < 4:
                break
            payload_len = struct.unpack(">H", buffer[2:4])[0]
            offset = 4
        elif payload_len == 127:
            if len(buffer) < 10:
                break
            payload_len = struct.unpack(">Q", buffer[2:10])[0]
            offset = 10

        if masked:
            if len(buffer) < offset + 4:
                break
            mask_key = buffer[offset:offset + 4]
            offset += 4

        total = offset + payload_len
        if len(buffer) < total:
            break

        raw_payload = buffer[offset:total]
        if masked:
            raw_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(raw_payload))

        frames.append((fin, opcode, raw_payload))
        buffer = buffer[total:]

    return frames, buffer


_WS_OPCODE_NAMES = {
    WS_TEXT: "TEXT",
    WS_BINARY: "BINARY",
    WS_CLOSE: "CLOSE",
    WS_PING: "PING",
    WS_PONG: "PONG",
}


@dataclass
class WebSocketMixin:
    ws_path: str = _field("", group=GROUP, flags=["--ws-path"], doc="Specific path for WebSocket connections (default: any path)")
    websocket_tester: str = _field(None, group=GROUP, flags=["--websocket-tester"], doc="Serve the WebSocket tester HTML page at this path (e.g. /wstest). Default: disabled")

    def __post_init__(self):
        if self.ws_path:
            self.logger.info(f"WebSocket path restricted to: {self.ws_path}")
        if self.websocket_tester:
            fp = Path(__file__).parent / "websocket.html"
            self._tester_html = fp.read_text("utf-8")
        else:
            self._tester_html = None
        super().__post_init__()
        if self.websocket_tester:
            self.status(f"[websocket] WebSocket tester: http://127.0.0.1:{self.port}{self.websocket_tester}")


class WebSocketProcessor:
    def do_GET(self, req):
        if req.server.websocket_tester and req.path == req.server.websocket_tester:
            req.send_response_full(200, content=req.server._tester_html, mime="text/html")
            return True

        if req.headers.get("upgrade", "").lower() != "websocket":
            return
        if req.server.ws_path and req.path != req.server.ws_path:
            return

        ws_key = req.headers.get("sec-websocket-key", "")
        if not ws_key:
            return

        accept = _create_accept_key(ws_key)
        req.send_response(101, "Switching Protocols")
        req.send_header("Upgrade", "websocket")
        req.send_header("Connection", "Upgrade")
        req.send_header("Sec-WebSocket-Accept", accept)
        req.end_headers()
        req.wfile.flush()

        req.close_connection = True
        self._ws_loop(req)
        return True

    def _ws_loop(self, req):
        sock = req.connection
        buffer = getattr(req.rfile, 'drain')()

        while True:
            try:
                ready = select.select([sock], [], [], 30.0)
                if not ready[0]:
                    try:
                        sock.sendall(_encode_frame(WS_PING))
                    except (OSError, ssl.SSLError):
                        break
                    continue
            except (OSError, ValueError):
                break

            try:
                data = sock.recv(65536)
            except ssl.SSLWantReadError:
                # If SSL is enabled, there is the possibility that 
                # SSL-specific metadata (like the TLS record) is broken up
                # between packets.
                # 
                # select() can report "ready" before the TLS record
                # is fully received; recv() raises this instead of
                # blocking. Wait for more data on the next iteration.
                continue
            except (BlockingIOError, ssl.SSLWantWriteError):
                continue
            except (ConnectionResetError, BrokenPipeError, OSError, ssl.SSLError):
                break

            if not data:
                break

            buffer += data
            frames, buffer = _decode_frames(buffer)

            for fin, opcode, payload in frames:
                if opcode == WS_CLOSE:
                    reason = payload[:2] if len(payload) >= 2 else b""
                    try:
                        sock.sendall(_encode_frame(WS_CLOSE, reason))
                    except OSError:
                        pass
                    return

                elif opcode == WS_PING:
                    try:
                        sock.sendall(_encode_frame(WS_PONG, payload))
                    except OSError:
                        pass

                elif opcode == WS_PONG:
                    pass

                elif opcode in (WS_TEXT, WS_BINARY):
                    oname = _WS_OPCODE_NAMES.get(opcode, str(opcode))
                    requestline = f"WS {oname} {len(payload)} bytes"
                    req.proto = "WSS" if req.is_ssl else "WS"
                    req.push_event(
                        ws_event=True,
                        method=f"WS-{oname}-{opcode}",
                        path=req.path,
                        requestline=requestline,
                        headers={},
                        body=payload,
                        filter_matches=req.is_match(requestline, payload),
                        correlation_id=req.correlation_id,
                    )
