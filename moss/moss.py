#!/usr/bin/env python3
import argparse
import json
import logging
from http.server import HTTPStatus, ThreadingHTTPServer, BaseHTTPRequestHandler
import random
import sys
import re
from typing import *
import queue
import threading
import traceback
import os
import socket
import select
import ssl
import http.client
from dataclasses import dataclass, field
import dataclasses
import importlib.util
from pathlib import Path
from collections import defaultdict
import time
from copy import deepcopy
import gzip
import math

# Extensions
# try:
#     import websockets
#     from websockets.server import ServerProtocol
#     from websockets.sync.server import ServerConnection
#     from websockets.frames import Frame
#     from websockets.http11 import Request, Response
# except ImportError:
#     printe('websockets not loaded')
# else:
#     printe('websockets loaded!')

__version__ = '0.6.1'

__all__ = [
    'MossRequestHandler', 'HttpMossServer',
    'ProtocolProcessor', 'EnqueueProcessor', 'DefaultProcessor',
    'LoggingEventHandler',
    # Utility classes
    'MossBuilder', 'MossRunner',
    # Expose "config variables" to allow modification
    'logger',
    'COMMON_HEADERS', 'STATIC_FILE_EXTENSIONS',
]

MAX_LENGTH_TO_LOG = 1024

# These headers will be filtered out when `ignore_common_headers` is specified.
COMMON_HEADERS = [
    'accept',
    'accept-encoding',
    'accept-language',
    'cache-control',
    'sec-fetch-dest',
    'sec-fetch-mode',
    'sec-fetch-site',
    'priority',
]

# These are a collection of WEBDAV HTTP methods. Probably won't need to modify this.
WEBDAV_COMMANDS = [
    'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK',
]

# The number of seconds to wait on the initial socket before timing out.
# TODO: test nc client, send 1 byte, then hang
SOCKET_TIMEOUT = 30

# Controls the size of the queue used to pass messages from RequestHandlers to the main server thread.
QUEUE_MAX_SIZE = 40

# Controls the maximum length of the first line of a HTTP request.
MAX_REQUESTLINE_LENGTH = 8192

# List of static file extensions, which influence whether a file may be gzipped if enabled
STATIC_FILE_EXTENSIONS = {
    'text/html', 'text/javascript', 'text/css'
}

MIN_GZIP_LENGTH = 4000

# Rate limiting.
MIN_BADNESS_COUNT = 8
MIN_BADNESS_SCORE = 10.0 

# Pretty colours!
class Whatever: pass
c = Whatever()
c.CYN = CLR_CYN = "\033[96m"
c.GRN = CLR_GRN = "\033[92m"
c.YLW = CLR_YLW = "\033[93m"
c.BLU = CLR_BLU = "\033[94m"
c.RED = CLR_RED = "\033[91m"
c.RST = CLR_RST = "\033[0m"

logging.basicConfig(format=f'{CLR_CYN}[%(asctime)s]{CLR_RST} {CLR_YLW}%(levelname)s{CLR_RST} %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger("moss")

def random_server():
    return random.choice([
        'Apache',
        'nginx',
        'Microsoft-IIS',
        'Cloudflare',
    ])

def printe(*args, **kwargs):
    print(*args, **kwargs, flush=True, file=sys.stderr)

def _field(default, group=None, doc="", metadata={}, flags=[], choices=[], **kwargs):
    """Simple wrapper to express fields more conveniently."""
    dwargs = {}
    if type(default).__name__ in ['function', 'type']:
        dwargs["default_factory"] = default
    else:
        dwargs["default"] = default
    return field(**dwargs, metadata=metadata | dict(group=group, doc=doc, flags=flags, choices=choices, **kwargs))

def strip_headers_in_place(headers):
    for k in list(headers.keys()):
        if k.lower() in COMMON_HEADERS:
            del headers[k]
            
gzip_cache = {}
def memoised_gzippy(s: bytes) -> bytes:
    global gzip_cache
    h = hash(s)
    if h in gzip_cache:
        return gzip_cache[h]
    compressed = gzip.compress(s)
    gzip_cache[h] = compressed
    return compressed

class InitSuccessError(Exception): pass

class MossRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, request, client_address, server):
        self.request = request
        self.client_address = client_address
        self.server = server
        self.is_ssl = False
        self.is_ws = False
        self.proto = 'TCP'

        self.init_success = False
        if server.enable_blocking and server.ratelimiter.banned(client_address[0]):
            return
        
        self.connect_timestamp = self.log_date_time_string()
        self.debug(f"socket opened")

        """
        1. Peek 1 byte into the socket
        2. If it's a TLS byte, wrap the connection with an SSL context
        3. If not, leave the socket as-is
        This implementation is partly inspired by the Python 3.14 HTTPSServer implementation.
        https://github.com/python/cpython/blob/3.14/Lib/http/server.py#L320
        """

        # We need select here to set timeouts. Without this, connection timeout is 
        # dependent on the client, which could be a potential DoS vector.
        ready = select.select([request], [], [], SOCKET_TIMEOUT)
        if not ready[0]:
            # testcase: nc $host $port, then wait
            self.handle_anomaly(
                f'connection timed out',
                tags=['portscan', 'dos'],
            )
            return
    
        try:
            bytes_ = request.recv(1024, socket.MSG_PEEK)
        except ConnectionResetError as e:
            # testcase: nmap -sT
            self.handle_anomaly(
                f'connection reset: {e}',
                tags=['portscan'],
            )
            return
        
        if len(bytes_) == 0:
            # testcase: nc $host $port, then ^C
            # Note: Browsers may sometimes trigger this, possibly to optimise connection handling.
            self.handle_anomaly(
                f'socket opened, but no incoming bytes (during peek)',
                tags=['portscan'],
            )
            return

        self.debug(f"peeked: {'ssl' if bytes_[0] == 0x16 else 'non-ssl'}")
        if bytes_[0] == 0x16:
            # TLS
            if server.supports_https:
                self.certfile = server.certfile
                self.keyfile = server.keyfile
                self.password = None
                self.alpn_protocols = ["http/1.1"]
                self.wait_for_byte(5)
                context = self._create_context()
                try:
                    request = context.wrap_socket(request, server_side=True)
                except ConnectionResetError as e:
                    self.debug(f"connection reset error during init")
                    self.handle_anomaly(f'{e.__class__.__name__} (during init): {e}')
                    return
                except ssl.SSLError as e:
                    # TODO: Maybe it's not SSL? handle that case?
                    tags = []
                    if 'SSLV3_ALERT_BAD_CERTIFICATE' in str(e) or 'SSLV3_ALERT_CERTIFICATE_UNKNOWN' in str(e):
                        # testcase: certain browsers
                        tags.extend(['insecure-ssl-cert'])
                    self.debug(f"ssl error during init")
                    self.handle_anomaly(f'ssl error (during init): {e}', tags=tags)
                    return
                self.debug(f"completed ssl handshake")
                self.proto = 'TLS/SSL'
                self.is_ssl = True
            else:
                self.handle_anomaly(f'detected TLS/SSL or other protocol, but https was not enabled')
                return
        else:
            if server.https_only:
                self.handle_anomaly(f'expected HTTPS only, but got something else', details=bytes_)
                return

        self.init_success = True
        super().__init__(request, client_address, server)

    def wait_for_byte(self, timeout):
        bl = self.request.getblocking()
        self.request.setblocking(0) # set non-blocking to use with select
        ready = select.select([self.request], [], [], timeout)
        if not ready[0]:
            self.debug('timed out')
            # When this method is called in handle_one_request, the timeout here will be
            # triggered often by browsers. So we disregard this as an anomaly to reduce noise.
        #     self.handle_anomaly(
        #         f'connection timed out',
        #         tags=['dos'],
        #     )
            raise TimeoutError('connection timed out')
        self.request.setblocking(bl)

    def debug(self, msg):
        logger.debug(f"{CLR_GRN}[{self.client_address[0]}:{self.client_address[1]}]{CLR_RST} {msg}")

    def info(self, msg):
        logger.info(f"{CLR_GRN}[{self.client_address[0]}:{self.client_address[1]}]{CLR_RST} {msg}")

    def _create_context(self):
        """Create a secure SSL context."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.certfile, self.keyfile, self.password)
        context.set_alpn_protocols(self.alpn_protocols)
        return context

    def send_header(self, k, v):
        # Sanitise header value against CRLF injection.
        # https://github.com/python/cpython/issues/142533
        v = ''.join(c for c in str(v) if c not in '\n\r')
        super().send_header(k, v)

    def send_response(self, code, message=None):
        self.send_response_only(code, message)
        if self.server.server_header:
            self.send_header('Server', self.server.server_header)
        for k, v in self.server.headers:
            self.send_header(k, v)

        self.send_header('Date', self.date_time_string())

    def send_response_full(self, code, *, message=None, content=b"", mime="text/html; charset=utf-8", headers={}):
        if type(content) == str:
            content = content.encode('utf-8')
        self.send_response(code, message)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', len(content))
        if self.server.enable_gzip and "gzip" in self.headers.get("accept-encoding", "") \
            and len(content) > MIN_GZIP_LENGTH and mime in STATIC_FILE_EXTENSIONS:
            content = memoised_gzippy(content)
            self.send_header('Content-Encoding', 'gzip')
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, code, *, data):
        content = json.dumps(data).encode()
        self.send_response_full(code, content=content, mime="application/json")

    def send_error(self, code, message=None, explain=None):
        """Override send_error to report anomalies"""
        kwargs = {}
        if explain:
            kwargs["details"] = f"Explanation: {explain}"
        self.handle_anomaly(message, **kwargs)
        self.send_response(code, message)
        self.send_header("Connection", "close")
        self.end_headers()

    def is_match(self, requestline, body):
        f_str = (self.server.filter_str or "").encode()
        if not f_str:
            return True
        return f_str in requestline.encode() or f_str in body

    def extract_correlation_id(self, requestline, headers, body):
        r = self.server.correlation_regex
        if not r:
            return None

        results = r.findall(f"{requestline}\n{headers}\n{body.decode('utf-8', errors='replace')}")
        if results:
            return results[0]
        else:
            return None

    def handle_anomaly(self, anomaly='unknown anomaly', **kwargs):
        mname = 'handle_anomaly'
        for proc in self.server.processors:
            if hasattr(proc, mname):
                method = getattr(proc, mname)
                if method(self, anomaly=anomaly, **kwargs):
                    break
        else:
            printe(f"unhandled anomaly: {anomaly}; {kwargs}")

    def handle_method(self, method):
        """Dispatch method to processors.
        
        If a processor method returns True, then stop processing.
        """
        self.debug(f"parsed HTTP method: {method}")

        for proc in self.server.processors:
            mname = 'do_' + method
            if hasattr(proc, mname):
                mfunc = getattr(proc, mname)
                if mfunc(self): break
                continue
            mname = 'handle_fallback'
            if hasattr(proc, mname):
                mfunc = getattr(proc, mname)
                if mfunc(self): break
                continue
        else:
            # Method not found.
            self.send_error(
                HTTPStatus.NOT_IMPLEMENTED,
                "Unsupported method (%r)" % method)

    def log_date_time_string(self):
        """Override freedom time dd/mm/yyyy with global standards."""
        now = time.time()
        year, month, day, hh, mm, ss, x, y, z = time.localtime(now)
        s = "%04d-%02d-%02d %02d:%02d:%02d" % (
                year, month, day, hh, mm, ss)
        return s

    def handle_one_request(self):
        """Override the high-level handling of a request.
        + timestamp
        + set a lower requestline length limit
        """
        self.debug('handle one request')
        self.request_timestamp = self.log_date_time_string()
        try:
            self.wait_for_byte(5)
            self.raw_requestline = self.rfile.readline(MAX_REQUESTLINE_LENGTH + 1)
            self.debug(f'read {len(self.raw_requestline)} bytes')
            if len(self.raw_requestline) > MAX_REQUESTLINE_LENGTH:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                # An error code has been sent, just exit
                return
            content_length = int(self.headers.get('Content-Length', 0))
            self.body = self.rfile.read(content_length)
            self.filter_matches = self.is_match(self.requestline, self.body)
            self.correlation_id = self.extract_correlation_id(self.requestline, self.headers, self.body)
            self.handle_method(self.command)
            self.wfile.flush() #actually send the response if not already done.
        except TimeoutError as e:
            #a read or a write timed out.  Discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = True
            return
        # return super().handle_one_request()

    def parse_request(self):
        """Override of Python implementation
        ref: https://github.com/python/cpython/blob/3.14/Lib/http/server.py#L320
        modifications:
        + assign .proto to HTTP/HTTPS after some verification
        + don't freak out on HTTP/2.0
        + other plumbing

        ---

        Parse a request (internal).

        The request should be stored in self.raw_requestline; the results
        are in self.command, self.path, self.request_version and
        self.headers.

        Return True for success, False for failure; on failure, any relevant
        error response has already been sent back.

        """
        is_http_0_9 = False
        self.command = None  # set in case of error on the first line
        self.requestline = ''
        self.headers = {}
        self.body = b''
        
        self.request_version = version = self.default_request_version
        self.close_connection = True
        requestline = str(self.raw_requestline, 'iso-8859-1')
        requestline = requestline.rstrip('\r\n')
        self.requestline = requestline
        words = requestline.split()
        if len(words) == 0:
            return False

        if len(words) >= 3:  # Enough to determine protocol version
            version = words[-1]
            try:
                if not version.startswith('HTTP/'):
                    raise ValueError
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                # RFC 2145 section 3.1 says there can be only one "." and
                #   - major and minor numbers MUST be treated as
                #      separate integers;
                #   - HTTP/2.4 is a lower version than HTTP/2.13, which in
                #      turn is lower than HTTP/12.3;
                #   - Leading zeros MUST be ignored by recipients.
                if len(version_number) != 2:
                    raise ValueError
                if any(not component.isdigit() for component in version_number):
                    raise ValueError("non digit in http version")
                if any(len(component) > 10 for component in version_number):
                    raise ValueError("unreasonable length http version")
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad request version (%r)" % version)
                return False
            if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                self.close_connection = False
            if version_number >= (2, 1):
                self.send_error(
                    HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
                    "Invalid HTTP version (%s)" % base_version_number)
                return False
            self.request_version = version

        if not 2 <= len(words) <= 3:
            self.send_error(
                HTTPStatus.BAD_REQUEST,
                "Bad request syntax (%r)" % requestline)
            return False
        
        command, path = words[:2]
        if len(words) == 2:
            self.close_connection = True
            if command != 'GET':
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad request syntax (%r)" % requestline)
                return False
            is_http_0_9 = True
        self.command, self.path = command, path

        self.proto = 'HTTPS' if self.is_ssl else 'HTTP'

        # gh-87389: The purpose of replacing '//' with '/' is to protect
        # against open redirect attacks possibly triggered if the path starts
        # with '//' because http clients treat //path as an absolute URI
        # without scheme (similar to http://path) rather than a path.
        if self.path.startswith('//'):
            self.path = '/' + self.path.lstrip('/')  # Reduce to a single /

        # For HTTP/0.9, headers are not expected at all.
        if is_http_0_9:
            self.headers = {}
            return True

        # Examine the headers and look for a Connection directive.
        try:
            self.headers = http.client.parse_headers(self.rfile,
                                                     _class=self.MessageClass)
        except http.client.LineTooLong as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Line too long",
                str(err))
            return False
        except http.client.HTTPException as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Too many headers",
                str(err)
            )
            return False

        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = True
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.1"):
            self.close_connection = False
        # Examine the headers and look for an Expect directive
        expect = self.headers.get('Expect', "")
        if (expect.lower() == "100-continue" and
                self.protocol_version >= "HTTP/1.1" and
                self.request_version >= "HTTP/1.1"):
            if not self.handle_expect_100():
                return False
        return True

    # def peek_for_websocket(self, sock):
    #     """NOTE: MSG_PEEK does not work with SSL sockets, likely bc SSL decryption can't be streamed but is done in blocks?"""
    #     # Peek a bit generously.
    #     data = sock.recv(MAX_REQUESTLINE_LENGTH + 1000, socket.MSG_PEEK)
    #     lines = data.split(b'\n')
    #     if len(lines) <= 1:
    #         return False

    #     # Parse headers.
    #     for line in lines[1:]:
    #         if not line:
    #             break # End of headers, start of body.

    #         try:
    #             name, value = line.split(b':', 1)
    #         except TypeError: # malformed header, invalid HTTP
    #             logger.debug(f"Detected malformed HTTP line: {line}, skipping ws peek")
    #             break
            
    #         if (name.strip().lower(), value.strip().lower()) == (b'upgrade', b'websocket'):
    #             return True

    #     return False

    # def handle_websocket(self):
    #     # self.push_request_event("CONNECT")
    #     self.push_event()

    def handle(self):
        """Override handle to catch low-level socket errors gracefully."""
        
        # if self.server.supports_ws:
        #     self.is_ws = self.peek_for_websocket(self.connection)
        #     if self.is_ws:
        #         self.proto = "WSS" if self.is_ssl else "WS"
        #         logger.info('Peeked and detected websocket request.')
        try:
            if not self.init_success:
                raise InitSuccessError()
            # if self.is_ws:
            #     self.handle_websocket()
            # else:
            self.debug("handling request...")
            super().handle()
        except InitSuccessError:
            # This is just a simple control flow to handle bad init states.
            pass
        except (ConnectionResetError, BrokenPipeError) as e:
            # Log the reset but don't crash
            self.handle_anomaly(f"TCP socket was opened, but connection reset ({e})")
        except ssl.SSLError as e:
            self.handle_anomaly(f"ssl error during handle ({e})")
        finally:
            try:
                if self.is_ssl:
                    self.debug("closing ssl connection...")
                    self.connection.unwrap()
            except BrokenPipeError as e:
                self.handle_anomaly(f"{e.__class__.__name__}: {e}", tags=["insecure-ssl-cert", "signer-not-trusted"])
            except ssl.SSLError as e:
                self.handle_anomaly(
                    f"ssl error 2 ({e})",
                    tags=["ssl-domain-enumeration", "insecure-ssl-cert", "cert-subject-name-does-not-match-hostname", "close-connection"]
                )
            except Exception as e:
                self.handle_anomaly(f"{e.__class__.__name__}: {e} (during ssl unwrap)")
                
            # Safely clear buffers and close the connection
            try:
                self.rfile.close()
                self.wfile.flush()
                self.wfile.close()
                # pass
            except Exception as e:
                printe("Error occurred while clearing buffer after anomaly:", e)

    def log_message(self, format, *args):
        # We don't want the default log
        pass

    def push_event(self, **kwargs):
        kwargs = dict(
            connect_timestamp=getattr(self, 'connect_timestamp', None),
            request_timestamp=getattr(self, 'request_timestamp', None),
            proto=getattr(self, 'proto', 'unknown'),
            event_timestamp=self.log_date_time_string(),
            client=self.client_address[0], # + ':' + str(self.client_address[1]),
            **kwargs,
        )
        if self.server.queue.full():
            self.server.queue.put(kwargs, block=True)
        else:
            self.server.queue.put(kwargs, block=False)

    def mark_ip_bad(self, weight=1.0):
        """Mark the IP from this connection as a bad IP.
        This will accumulate an IP's badness score.
        When the badness score, reaches a threshold, that IP will be permanently blocked.
        """
        if not self.server.enable_blocking:
            return
        self.server.ratelimiter.mark(self.client_address[0], weight)

    def mark_ip_ok(self):
        """Treat the IP as ok, erase past records."""
        if not self.server.enable_blocking:
            return
        self.server.ratelimiter.reset(self.client_address[0])

@dataclass
class BadIP:
    score: float = 0
    count: int = 0
    last_seen: float = field(default_factory=lambda: time.time())

class BadnessRateLimiter:
    def __init__(self):
        self.book_of_badness = defaultdict(BadIP)

    def banned(self, ip) -> bool:
        if ip not in self.book_of_badness:
            return False
        stats = self.book_of_badness[ip]
        return stats.count >= MIN_BADNESS_COUNT and stats.score >= MIN_BADNESS_SCORE
    
    def reset(self, ip):
        b = self.book_of_badness[ip]
        b.score = 0
        b.count = 0
    
    def mark(self, ip, weight):
        stats = self.book_of_badness[ip]
        score = self.score(stats, time.time(), weight)
        stats.score += score
        stats.count += 1
        if self.banned(ip):
            logger.warning(f"Blocked {ip}")

    def score(self, stats: BadIP, now, weight):
        elapsed_sec = now - stats.last_seen
        return 5/math.sqrt(elapsed_sec) * weight


def inject_class_utils(clss):
    for cls in clss:
        if not hasattr(cls, "logger"):
            cls.logger = logger
        cls.printe = lambda cls, msg: printe(f"{msg}")
        cls.printerr = lambda cls, msg: printe(f"{CLR_RED}{msg}{CLR_RST}")
        cls.printstatus = lambda cls, msg: printe(f"{CLR_CYN}{msg}{CLR_RST}")
        cls.c = c

# def wrap_processor_mixin(clss):
#     out = []
#     for cls in clss:
#         @dataclass
#         class WrappedClass(CommonProcessorMixin, cls): pass
#         out.append(WrappedClass)
#     return out

@dataclass
class HttpMossServer:
    host: str = _field('0.0.0.0', flags=["--bind", "-b", "--host"], doc="Bind to this address")
    port: int = _field(8000, flags=["--port", "-p"])
    
    RequestHandlerClass = MossRequestHandler
    RateLimiterClass = BadnessRateLimiter
    
    server_header: str = _field("moss (https://github.com/TrebledJ/moss)", group="response", flags=["--server"], doc="Server header in response. Special values: random, none")
    headers: list[str] = _field(list, group="response", flags=["--header", "-H"], doc="Headers to include in server output. You can specify multiple of these, e.g. -H 'Set-Cookie: a=b' -H 'Content-Type: application/json'")
    enable_gzip: bool = _field(False, group="response", flags=["--gzip"], doc="Enable gzip on static file extensions for lower network latency")

    supports_ws: bool = _field(False, group="protocols", flags=["--websockets"], doc="Enable websocket support. Limited support, currently only detects the HTTP handshake")

    supports_https: bool = _field(False, group="https", flags=["--https"], doc="Enable HTTPS polyglot support")
    https_only: bool = _field(False, group="https", doc="Force HTTPS, ignore raw HTTP")
    certfile: str = _field(None, group="https", doc="Public key")
    keyfile: str = _field(None, group="https", doc="Private key")

    filter_str: str = _field(None, group="matching", flags=["--filter"], doc="Match request line and body")
    correlation_regex: str = _field('', group="matching", flags=["--correlation", "-r"], doc="Extract correlation ID based on regex, this works independently of the filter")

    enable_blocking: bool = _field(False, group="security", flags=["--block-scanners"], doc="Enables automatic blocking of IPs which behave like scanners. To unblock, restart the server lol")

    def __post_init__(self):
        self._validate()
        self.processors = []
        params = self.__dict__.items()

        self.server = server = ThreadingHTTPServer((self.host, self.port), self.RequestHandlerClass)
        server.queue = self.queue = queue.Queue(maxsize=QUEUE_MAX_SIZE)
        for attr, value in params:
            setattr(server, attr, value)
        server.running = False
        server.ratelimiter = self.RateLimiterClass()
        # super().__post_init__() # No super post init. This class should be last one in a mixin chain.

    def _validate(self):
        # Convert headers into list of pairs.
        headers, self.headers = self.headers, []
        for h in headers:
            k, v = h.split(':', 1)
            self.headers.append((k.strip(), v.strip()))

        self.correlation_regex = re.compile(self.correlation_regex) if self.correlation_regex else None

        if self.server_header == 'random':
            self.server_header = random_server()
        elif self.server_header == 'none':
            self.server_header = None

        if self.https_only: # Implicitly enable https.
            self.https = True

        if self.supports_https:
            if not self.certfile or not self.keyfile:
                printe(f"{CLR_RED}HTTPS enabled, but certfile or keyfile was not provided{CLR_RST}")
                sys.exit(1)

            if not os.path.exists(self.certfile):
                printe(f"{CLR_RED}certfile does not exist:{CLR_RST}: {self.certfile}")
                sys.exit(1)
            if not os.path.exists(self.keyfile):
                printe(f"{CLR_RED}keyfile does not exist:{CLR_RST}: {self.keyfile}")
                sys.exit(1)

        printe(f"{CLR_GRN}Server listening on {self.host}:{self.port}{CLR_RST}")
        if self.filter_str: printe(f"{CLR_YLW}Filter active:{CLR_RST} {self.filter_str}")
        if self.correlation_regex: printe(f"{CLR_YLW}Correlation ID regex:{CLR_RST} {self.correlation_regex}")

    @classmethod
    def from_args(cls, args: argparse.Namespace):
        inst = build_dataclass_from_args(cls, args)
        for P in cls._processors:
            c = build_dataclass_from_args(P, args)
            inst.processors.append(c)
        return inst


    @classmethod
    def _run_http_server(cls, server):
        server.serve_forever()
        server.server_close()
        
    def serve(self):
        self.server.running = True
        self.thread = threading.Thread(target=self.__class__._run_http_server, args=(self.server, ))
        self.thread.start()

    def serve_forever(self):
        self.serve()
        self.thread.join()
    
    def wait(self, timeout=None):
        if self.server.running and timeout:
            # "Blocking" with timeout.
            try:
                return self.queue.get(timeout=timeout)
            except queue.Empty:
                return None
        else:
            # Wait forever.
            while self.server.running:
                try:
                    # Use polling here, in case we need to quit the thread (e.g. due to SIGINT / ^C).
                    if item := self.queue.get(timeout=0.2):
                        return item
                except queue.Empty:
                    pass
            return None

    def shutdown(self):
        self.server.running = False
        self.server.shutdown()


@dataclass
class ProtocolProcessor:
    """This is a default pre-processor which updates the human-readable protocol field."""

    def do_GET(self, req):
        if req.path.startswith('http://'):
            # TODO: proxy connection
            req.proto = "PROXY/" + req.proto

        if req.server.supports_ws:
            # TODO: handle upgrade and listen for ws
            if req.headers.get('upgrade', '').lower() == 'websocket':
                req.proto = "WSS" if req.is_ssl else "WS"

    def do_CONNECT(self, req):
        req.proto = "TUNNEL/" + req.proto

    def do_PRI(self, req):
        req.proto += "2"

    def handle_fallback(self, req):
        if req.command in WEBDAV_COMMANDS:
            req.proto = "WEBDAV/" + req.proto


# @dataclass
# class CommonProcessorMixin:
#     """This class is used to "add" methods to Processors without the need of importing moss and inheriting anything."""


@dataclass
class EnqueueProcessor:
    """This is a default processor which handles pushing events from RequestHandlers to the main server thread."""

    KNOWN_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE", "DEBUG", "PRI", *WEBDAV_COMMANDS]

    def handle_fallback(self, req):
        """handle_fallback and handle_anomaly could be called
        from multiple threads. So we push the events to a queue to ensure only a single thread
        is writing to file."""
        if req.command in self.KNOWN_METHODS:
            self.push_request_event(req)
    
    def handle_anomaly(self, req, anomaly='unknown anomaly', **kwargs):
        if requestline := getattr(req, 'requestline', None):
            kwargs['requestline'] = requestline
        if headers := getattr(req, 'headers', None):
            kwargs['headers'] = headers
        if 'tags' not in kwargs:
            kwargs['tags'] = []
        if 'details' not in kwargs:
            kwargs['details'] = ''
        req.push_event(
            anomaly=anomaly,
            **kwargs,
        )
        return True

    def push_request_event(self, req):
        req.push_event(
            method=req.command,
            path=req.path,
            headers=req.headers,
            requestline=req.requestline,
            body=req.body,
            filter_matches=req.filter_matches,
            correlation_id=req.correlation_id,
        )


def shorten(s):
    if len(s) > MAX_LENGTH_TO_LOG:
        return s[:MAX_LENGTH_TO_LOG] + f"...({len(s) - MAX_LENGTH_TO_LOG} more bytes, {len(s)} bytes in total)...".encode()
    return s


@dataclass
class LoggingEventHandler:
    """
    Consumes and outputs events to console, file, and notification webhook.
    """
    output_all: bool = _field(False, group="logging", doc="Output all HTTP requests, including those that don't match the filter")
    ignore_common_headers: bool = _field(False, group="logging", flags=["--ignore-common-headers", "-i"], doc="Exclude common request headers from display. This does not affect jsonl output")
    jsonl_file: str = _field(None, group="logging", flags=["--jsonl", "-o"], doc="Output file path for JSONL logging (one JSON event per line). Use `--jsonl -` to output to stdout")
    no_anomaly: bool = _field(False, group="logging", doc="Do not log anomalies")
    simple: bool = _field(False, group="logging", doc="Use simple logging, one line per event")

    def __post_init__(self):
        if self.jsonl_file: printe(f"{CLR_CYN}JSONL logging to:{CLR_RST} {self.jsonl_file}")

    def handle_event(self, data):
        """
        Handle events fired from the Request Handler. The implementation is up to you,
        but here I chose to base it structurally on field names, for convenience.
        i.e. find the first handler which accepts the data fields in its named parameters
        """
        event_handlers = [self.handle_request, self.handle_anomaly, self.handle_response]
        for func in event_handlers:
            try:
                func(**data)
                break
            except TypeError as e:
                if 'missing' not in str(e):
                    raise e # Actual error.
                # # Failed to fit parameters, move on.
                # logger.debug(f'skipping {__class__.__name__}.{func.__name__}: {e}')
                # logger.debug(traceback.format_exc())
                continue
        else:
            # Default handler
            logger.debug(f'{__class__.__name__} discarding event:', data)

    def handle_request(self, *, proto, method, requestline, path, headers, body, **kwargs):
        matches = kwargs.get("filter_matches", False)
        if not matches and not self.output_all: return
        self.log_to_jsonl(
            proto=proto, method=method, requestline=requestline, path=path, headers=headers, body=body,
            **kwargs,
        )

        if self.ignore_common_headers:
            headers = deepcopy(headers)
            strip_headers_in_place(headers)
        self.log_request_to_display(proto, requestline, headers, body, **kwargs)

    def handle_response(self, *, response_message, client, event_timestamp, **kwargs):
        self.log_to_jsonl(response_message=response_message, **kwargs)
        if self.simple:
            printe(f"[{event_timestamp.split(' ')[-1]}] {CLR_CYN}RESPN{CLR_CYN} {CLR_GRN}{response_message}{CLR_RST}")
            return
        
        status = 'RESPONSE'
        printe(f"{CLR_CYN}{status:><12}>{client:>>15}>>>{event_timestamp}{CLR_RST}")
        printe(f"{CLR_GRN}{response_message}{CLR_RST}")
        printe(f"{CLR_CYN}{status:><30}{CLR_RST}\n")

    def handle_anomaly(self, *, anomaly, details, **kwargs):
        if self.no_anomaly:
            return
        deets = escape_non_printable(details)
        self.log_to_jsonl(anomaly=anomaly, details=deets, **kwargs)
        self.log_anomaly_to_display(anomaly, details=details, **kwargs)

    def log_to_jsonl(self, *, headers=None, body='', **kwargs):
        if not self.jsonl_file: return
        jsonl_headers = {k.lower(): v for k, v in headers.items()} if headers else {}
        output = json.dumps(dict(**kwargs, headers=jsonl_headers, body=shorten(body)))
        if self.jsonl_file == '-':
            print(output, flush=True)
        else:
            with open(self.jsonl_file, "a", encoding="utf-8") as f:
                print(output, file=f, flush=True)

    def log_request_to_display(
        self, proto, requestline, headers, body,
        *, request_timestamp, event_timestamp, client,
        filter_matches, correlation_id,
        **_kwargs,
    ):
        top_status = bot_status = proto
        if not filter_matches:
            top_status = 'REJECTED'

        if self.simple:
            brief = f"{CLR_CYN}MATCH{CLR_RST}" if filter_matches else f"{CLR_RED}REJCT{CLR_RST}"
            method, path, *_ = requestline.split()
            e = escape_non_printable
            reqline = f"{e(method)} {e(path[:30])}"
            bod = e(body[:30].decode('utf-8', errors='backslashreplace'))
            printe(f"[{event_timestamp.split(' ')[-1]}] {brief} [{client}] {CLR_GRN}{proto}{CLR_RST} {CLR_YLW}{reqline}{CLR_RST} {CLR_BLU}{bod}{CLR_RST}")
            return

        if filter_matches:
            printe(f"{CLR_CYN}{top_status:-<12}-{client:->15}---{request_timestamp}{CLR_RST}")
            printe(f"{CLR_GRN}{escape_non_printable(shorten(requestline))}{CLR_RST}")
            if headers:
                printe(f"{CLR_YLW}{escape_non_printable(str(headers).strip())}{CLR_RST}")
            if body:
                printe(f"{escape_non_printable(shorten(body))}")
            if correlation_id:
                printe(f"{CLR_CYN}{bot_status:-<12}-{escape_non_printable(correlation_id):->15}---{event_timestamp}{CLR_RST}\n")
            else:
                printe(f"{CLR_CYN}{bot_status:-<30}-{event_timestamp}{CLR_RST}\n")
        else:
            printe(f"{CLR_RED}{top_status:-<12}-{client:->15}---{request_timestamp}{CLR_RST}")
            printe(f"{CLR_RED}{escape_non_printable(shorten(requestline))}{CLR_RST}")
            printe(f"{CLR_RED}{bot_status:-<30}-{event_timestamp}{CLR_RST}\n")

    def log_anomaly_to_display(self, anomaly, *, tags, details, connect_timestamp, event_timestamp, client, status='ANOMALY', **kwargs):
        if self.simple:
            printe(f"[{event_timestamp.split(' ')[-1]}] {CLR_YLW}ANMLY{CLR_RST} [{client}] {CLR_RED}{anomaly}{CLR_RST}")
            return
        
        printe(f"{CLR_YLW}{status:-<12}{client:->16}---{connect_timestamp}{CLR_RST}")
        printe(f"{CLR_RED}{anomaly}{CLR_RST}")
        if tags:
            c = ', '.join(tags)
            printe(f"{CLR_GRN}tags: {c}{CLR_RST}")
        if details:
            printe(f"{CLR_YLW}{escape_non_printable(shorten(details))}{CLR_RST}")
        if requestline := kwargs.get('requestline', None):
            printe(f"{CLR_YLW}{escape_non_printable(shorten(requestline))}{CLR_RST}")
        if headers := kwargs.get('headers', None):
            printe(f"{CLR_YLW}{escape_non_printable(str(headers).strip())}{CLR_RST}")
        if body := kwargs.get('body', None):
            printe(f"{CLR_YLW}{escape_non_printable(shorten(body))}{CLR_RST}")

        bot_status = kwargs.get('proto', status)
        printe(f"{CLR_YLW}{bot_status:-<30}-{event_timestamp}{CLR_RST}\n")

    
@dataclass
class DefaultProcessor:
    default_status_code: int = _field(200, group="response", flags=["--status-code", "-S"], doc="The default status code to return")
    default_mime_type: str = _field("text/html", group="response", flags=["--mime-type", "-M"], doc="The default mime type to return")
    default_body: str = _field("", group="response", flags=["--body"], doc="The default content to return. This could be a file, which will be loaded")
    enable_services_index: bool = _field(False, group="response", flags=["--index"], doc="Enable an index page which lists the services enabled")

    def __post_init__(self):
        if b := self.default_body:
            if os.path.exists(b):
                with open(b, 'rb') as f:
                    self.default_body = f.read()
        if type(self.default_body) == str:
            self.default_body = self.default_body.encode('utf-8')

        if self.default_body:
            status_message = MossRequestHandler.responses.get(self.default_status_code, ["(Unknown Status Code)"])[0]
            printe(f"{CLR_CYN}Default response:{CLR_RST} {CLR_GRN}{self.default_status_code} {status_message}{CLR_RST}, {CLR_YLW}{len(self.default_body)} bytes{CLR_RST}")

    def do_GET(self, req):
        if self.enable_services_index and req.path.strip('/') == '':
            r = []
            r.append('<!DOCTYPE HTML>')
            r.append('<html lang="en">')
            r.append('<head>')
            r.append('<style type="text/css">\n:root {\ncolor-scheme: light dark;\n}\n</style>')
            r.append('</head>')
            r.append(f'<body>\n<h1>Services</h1>')
            r.append('<hr>\n<ul>\n')
            for p in req.server.processors:
                try:
                    if method := getattr(p, "get_services", None):
                        services = method(req.server)
                        for href, description in services:
                            r.append(f"<li><a href=\"{href}\">{href}</a> - {description}</li>\n")
                except Exception as e:
                    self.logger.error(f"exception occurred while getting services: {e}")
                    self.send_default_response(req)
                    return True
            
            r.append('</ul>\n<hr>\n</body>\n</html>\n')
            req.send_response_full(200, content=''.join(r), mime='text/html')
            return True

        req.mark_ip_bad()
        if req.server.supports_ws and (req.proto.endswith("WS") or req.proto.endswith("WSS")):
            # TODO: handle upgrade and listen for ws
            self.send_invalid_method_and_close(req)
        else:
            self.send_default_response(req)
        return True

    def do_HEAD(self, req):
        req.mark_ip_bad()
        req.send_response_full(200)
        return True

    def do_OPTIONS(self, req):
        req.mark_ip_bad()
        # TODO: ACAO
        req.send_response_full(200)
        return True

    def send_default_response(self, req):
        req.send_response_full(self.default_status_code, content=self.default_body, mime=self.default_mime_type)

    def send_invalid_method_and_close(self, req):
        req.send_error(405, "Unsupported method (%r)" % req.command)
        
    def handle_fallback(self, req):
        req.mark_ip_bad()
        if req.command in ["POST", "PATCH", "PUT", "DELETE"]:
            self.send_default_response(req)
        else:
            self.send_invalid_method_and_close(req)
        return True

def escape_non_printable(s):
    if type(s) == bytes:
        s = s.decode(errors='backslashreplace')
    return "".join(c if c.isprintable() or c in '\r\n' else r'\x{0:02x}'.format(ord(c)) for c in s)

def add_args_from_dataclass(parser, *DataClasses):
    """Simple thingymabob to convert dataclass fields to argparse args."""
    # First, group by "field.metadata.group".
    ordered = [] # Preserve the order in which groups are seen.
    groups = defaultdict(list)
    seen_fields = {}
    for DataClass in DataClasses:
        for arg in getattr(DataClass, "__match_args__", []):
            field = DataClass.__dataclass_fields__[arg]
            if not field.metadata.get('cli', True): # Skip if cli==False
                continue

            if field.name in seen_fields:
                # We can accept duplicate fields, because some fields may be
                # needed across multiple extensions and it's sometimes hard for
                # one extension to coordinate with others.
                f, dupcls = seen_fields[field.name]
                if f.default == field.default \
                    and f.default_factory == field.default_factory \
                    and f.type == field.type:
                    # OK! Everything matches.
                    continue
                else:
                    # Nope, the duplicate field should at least have the same basics.
                    raise RuntimeError(f"encountered duplicate field {field.name} in class {dupcls.__name__} and {DataClass.__name__}; make sure the type and defaults match")
            else:
                seen_fields[field.name] = (field, DataClass)

            group = field.metadata.get('group', None) or 'default'
            groups[group].append(field)
            if group not in ordered:
                ordered.append(group)

    # Reorder so that groups within the main module show up first.
    _ordered, ordered = ordered, ['default', 'response', 'matching', 'logging', 'https', 'protocols', 'security']
    for o in _ordered:
        if o not in  ordered:
            ordered.append(o)

    for group in ordered:
        fields = groups[group]
        gparser = parser.add_argument_group(group) if group != "default" else parser
        for field in fields:
            # Add the field to the parser.
            flags = field.metadata.get("flags", []) or ["--" + field.name.replace("_", "-")]
            kwargs = dict(type=field.type)
            kwargs["dest"] = field.name
            if field.default is not dataclasses.MISSING:
                kwargs['default'] = field.default
                if field.type == bool:
                    kwargs['action'] = 'store_true' if field.default == False else 'store_false'
                    del kwargs['type'] # store_{true,false} does not play nice with `type`.
            elif field.default_factory is not dataclasses.MISSING:
                kwargs['default'] = field.default_factory()
                if field.default_factory == list:
                    if get_origin(kwargs['type']) == list:
                        # Use the inner argument for type. e.g. list[str] -> type=str.
                        kwargs['type'] = get_args(kwargs['type'])[0]
                    kwargs['action'] = 'append'
            else:
                raise RuntimeError("both default and default_factory are missing")
            if doc := getattr(field, 'doc', None): # Available in higher Python versions.
                kwargs['help'] = doc
            elif doc := field.metadata.get('doc', None):
                kwargs['help'] = doc
            if choices := field.metadata.get('choices', None):
                kwargs['choices'] = choices

            gparser.add_argument(*flags, **kwargs)

def get_dataclass_args(DataClass, namespace):
    kwargs = {}
    for arg in getattr(DataClass, '__match_args__', []):
        if (attr := getattr(namespace, arg, None)) is not None:
            kwargs[arg] = attr
    return kwargs

def build_dataclass_from_args(DataClass, namespace):
    return DataClass(**get_dataclass_args(DataClass, namespace))

class Formatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass

def load_module(path):
    path = Path(path)
    mod_name = path.stem
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except FileNotFoundError:
        return None
    return mod

def load_module_with_retry(path):
    path = str(path)
    if not path.endswith(".py"):
        path += ".py"

    mod = load_module(path)
    if mod:
        return mod
    
    path = Path(__file__).parent / "ext" / path
    mod = load_module(path)
    if mod:
        return mod

def find_extension_classes(module):
    mixins, processors, handlers = [], [], []
    for name in dir(module):
        if name.endswith('Mixin'):
            mixins.append(getattr(module, name))
        elif name.endswith('Processor'):
            processors.append(getattr(module, name))
        elif name.endswith('Handler'):
            handlers.append(getattr(module, name))
    return mixins, processors, handlers

class FancySchmancyArgumentParser(argparse.ArgumentParser):
    """
    One arg name-pair per line.
    Lines will be stripped.
    # for comment.
    
    Example:
    --arg
    --arg 1
    --arg '1'
    --arg "1"

    For nargs='+', arguments must be split into lines. For instance:

    --arg 1
          2
    --arg
        1
        2
    """
    def convert_arg_line_to_args(self, arg_line):
        line = arg_line.strip()
        if not line or line.startswith('#'):
            return []
        try:
            first, arg = line.split(' ', 1)
        except ValueError:
            # no space, single arg
            return [line]
        arg = arg.strip()
        if len(arg) >= 2:
            if arg.startswith("'") and arg.endswith("'"):
                arg = arg[1:-1]
            elif arg.startswith('"') and arg.endswith('"'):
                arg = arg[1:-1]

        return [first, arg]
    
@dataclass
class MossBuilder:
    """Utility class to help build a moss server. Inherit and override methods to customise it."""
    def __init__(self, args=None):
        if sys.version_info < (3, 10):
            printe(f"{CLR_RED}moss requires Python 3.10 or above")
            sys.exit(1)
        
        self.mixins = []
        self.processors = []
        self.handlers = []
        self.args = sys.argv[1:] if args is None else args

    def load_mixin(self, *cls):
        self.mixins += [*cls]

    def load_processor(self, *cls):
        self.processors += [*cls]

    def load_handler(self, *cls):
        self.handlers += [*cls]

    def load_extension(self, ext):
        mod = load_module_with_retry(ext)
        if mod is None:
            printe(f"{CLR_RED}module not found: {ext}{CLR_RST}")
            sys.exit(1)
        
        m, p, h = find_extension_classes(mod)
        self.mixins += m
        self.processors += p
        self.handlers += h

    def load_extensions_from_args(self):
        # Handle extension flags
        parser = FancySchmancyArgumentParser(
            fromfile_prefix_chars='@',
            add_help=False,
        )
        parser.add_argument("--ext", "-e", type=str, default=[], nargs='+', action='append')
        args, rest_args = parser.parse_known_args(self.args)
        exts = [y for x in args.ext for y in x]
        for ext in exts:
            self.load_extension(ext)
        self.args = rest_args
    
    def make_server(self, ServerClass=HttpMossServer, RequestHandlerClasss=MossRequestHandler):
        mixins, processors, handlers = self.mixins, self.processors, self.handlers
        mixins = mixins[::-1] # Reverse so that they are loaded/displayed in the order given
        # processors = wrap_processor_mixin(processors)
        if DefaultProcessor not in processors:
            processors.append(DefaultProcessor)

        inject_class_utils(mixins)
        inject_class_utils(processors)
        inject_class_utils(handlers)

        @dataclass
        class Server(*mixins, ServerClass):
            _processors = processors
            _handlers = handlers
            RequestHandlerClass = RequestHandlerClasss
        self.server = Server
        return Server

    def parse_args(self):
        parser = FancySchmancyArgumentParser(
            description=f"Simple, modular offensive HTTP server by TrebledJ, v{__version__}",
            formatter_class=Formatter,
            fromfile_prefix_chars='@',
        )

        # Add -e here so that it shows up in help, even though it would be processed before.
        parser.add_argument("--ext", "-e", type=str, default=[], nargs='+', help="Load extensions (Python files). Works with bash file glob/expansion, e.g. -e ext/{file,upload}.py")
        parser.add_argument('-v', action='count', default=0, help='Verbosity. -v for INFO, -vv for DEBUG messages.')

        # Add all CLI args from dataclasses.
        add_args_from_dataclass(parser, self.server, *self.server._processors, *self.server._handlers)

        # Parse!
        namespace = parser.parse_args(self.args)

        if namespace.v == 0:
            logger.setLevel(logging.WARNING)
        elif namespace.v == 1:
            logger.setLevel(logging.INFO)
        else:
            logger.setLevel(logging.DEBUG)
        
        return namespace

    def make_runner(self, namespace):
        server = self.server.from_args(namespace)
        handlers = [build_dataclass_from_args(H, namespace) for H in self.server._handlers]
        return MossRunner([server], handlers)
    
    def cli(self, ServerClass=HttpMossServer, RequestHandlerClasss=MossRequestHandler):
        self.load_processor(ProtocolProcessor, EnqueueProcessor)
        self.load_handler(LoggingEventHandler)
        self.load_extensions_from_args()
        self.make_server(ServerClass, RequestHandlerClasss)
        
        namespace = self.parse_args()
        runner = self.make_runner(namespace)
        return runner

class MossRunner:
    """Utility class to help run a moss server."""
    def __init__(self, servers, handlers):
        self.servers = servers
        self.handlers = handlers

    def handle_event(self, event):
        for h in self.handlers:
            try:
                h.handle_event(event)
            except KeyboardInterrupt as e:
                raise e
            except Exception as e:
                printe(f"{CLR_RED}An error occurred while in {h.__class__.__name__} while handling an event: {e}{CLR_RST}")
                printe(f"{CLR_RED}Le event: {event}{CLR_RST}")
                printe(traceback.format_exc())

    def loop(self):
        for server in self.servers:
            server.serve()
        
        try:
            # Poll servers.
            while True:
                for server in self.servers:
                    if (event := server.wait(0.2)) is not None:
                        self.handle_event(event)
        except KeyboardInterrupt:
            printe('shutting down...')
            for server in self.servers:
                server.shutdown()

def main():
    builder = MossBuilder()
    runner = builder.cli()
    runner.loop()

if __name__ == "__main__":
    main()