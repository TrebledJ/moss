#!/usr/bin/env python3
import argparse
import json
import logging
from http.server import HTTPStatus, ThreadingHTTPServer, BaseHTTPRequestHandler
from datetime import datetime
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
import tomllib

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


VERSION = '0.2'

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

WEBDAV_COMMANDS = [
    'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK',
]

SOCKET_TIMEOUT = 30

MAX_REQUESTLINE_LENGTH = 8192

CLR_CYN = "\033[96m"
CLR_GRN = "\033[92m"
CLR_YLW = "\033[93m"
CLR_BLU = "\033[94m"
CLR_RED = "\033[91m"
CLR_RST = "\033[0m"

logging.basicConfig(format=f'{CLR_CYN}[%(asctime)s]{CLR_RST} {CLR_YLW}%(levelname)s{CLR_RST} %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger("simpleoast")

def random_server():
    return random.choice([
        'Apache',
        'nginx',
        'Microsoft-IIS',
        'Cloudflare',
    ])

def printe(*args, **kwargs):
    print(*args, **kwargs, flush=True, file=sys.stderr)

class OastRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, request, client_address, server):
        self.request = request
        self.client_address = client_address
        self.server = server
        self.is_ssl = False
        self.is_ws = False
        self.proto = 'TCP'
        
        self.connect_timestamp = self.log_date_time_string()
        self.info(f"socket opened")

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
            self.push_anomaly_event(
                f'connection timed out',
                tags=['portscan', 'dos'],
            )
            return

        try:
            bytes_ = request.recv(1024, socket.MSG_PEEK)
        except ConnectionResetError as e:
            # testcase: nmap -sT
            self.push_anomaly_event(
                f'connection reset: {e}',
                tags=['portscan'],
            )
            return
        
        if len(bytes_) == 0:
            # testcase: nc $host $port, then ^C
            self.push_anomaly_event(
                f'socket opened, but no incoming bytes (during peek)',
                tags=['portscan'],
            )
            return

        self.info(f"peeked: {'ssl' if bytes_[0] == 0x16 else 'non-ssl'}")
        if bytes_[0] == 0x16:
            # TLS
            if server.support_https:
                self.certfile = server.certfile
                self.keyfile = server.keyfile
                self.password = server.password
                self.alpn_protocols = (
                    ["http/1.1"] if server.alpn_protocols is None else server.alpn_protocols
                )
                context = self._create_context()
                try:
                    request = context.wrap_socket(request, server_side=True)
                except ConnectionResetError as e:
                    self.info(f"connection reset error during init")
                    self.push_anomaly_event(f'{e.__class__.__name__} (during init): {e}')
                    return
                except ssl.SSLError as e:
                    # TODO: Maybe it's not SSL? handle that case?
                    tags = []
                    if 'SSLV3_ALERT_BAD_CERTIFICATE' in str(e):
                        # testcase: certain browsers
                        tags.extend(['insecure-ssl-cert'])
                    self.info(f"ssl error during init")
                    self.push_anomaly_event(f'ssl error (during init): {e}', tags=tags)
                    return
                self.info(f"completed ssl handshake")
                self.proto = 'TLS/SSL'
                self.is_ssl = True
            else:
                self.push_anomaly_event(f'detected TLS/SSL or other protocol, but https was not enabled')
                return
        else:
            if server.https_only:
                self.push_anomaly_event(f'expected HTTPS only, but got something else', details=bytes_)
                return

        super().__init__(request, client_address, server)

    def info(self, msg, *args, **kwargs):
        logger.info(f"{CLR_GRN}[{self.client_address[0]}:{self.client_address[1]}]{CLR_RST} {msg}")

    def _create_context(self):
        """Create a secure SSL context."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.certfile, self.keyfile, self.password)
        context.set_alpn_protocols(self.alpn_protocols)
        return context

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

    def push_request_event(self):
        self.push_event(
            method=self.command,
            path=self.path,
            headers=self.headers,
            requestline=self.requestline,
            body=self.body,
        )
    
    def push_anomaly_event(self, anomaly='unknown anomaly', **kwargs):
        if requestline := getattr(self, 'requestline', None):
            kwargs['requestline'] = requestline
        if headers := getattr(self, 'headers', None):
            kwargs['headers'] = headers
        # if body := ??? # Not possible? would need to be passed through param or reading rfile...
        # TODO: read the rest of rfile and set as body? But would that disrupt subsequent requests in the connection? (think: HTTP 1 request smuggling)
        if 'tags' not in kwargs:
            kwargs['tags'] = []
        if 'details' not in kwargs:
            kwargs['details'] = ''
        self.push_event(
            anomaly=anomaly,
            **kwargs,
        )

    def send_response(self, code, message=None):
        self.send_response_only(code, message)
        if self.server.server_header:
            self.send_header('Server', self.server.server_header)
        for k, v in self.server.headers:
            self.send_header(k, v)

        self.send_header('Date', self.date_time_string())

    def send_file(self, path):
        mime_type, content = self.server.files[self.path]
        self.send_header('Content-Type', mime_type)
        self.send_header('Content-Length', len(content))
        self.end_headers()
        self.wfile.write(content)
        self.push_event(response_message=f"sent file {self.path} with {len(content)} bytes")

    def send_response_body(self):
        if self.path in self.server.files:
            self.send_response(200)
            self.send_file(self.path)
        else:
            self.send_response(self.server.default_status_code)
            self.send_header('Content-Length', len(self.server.default_body))
            self.end_headers()
            self.wfile.write(self.server.default_body)
    
    def do_GET(self):
        if self.path.startswith('http://'):
            # TODO: proxy connection
            self.proto = "PROXY/" + self.proto

        if self.server.support_ws:
            # TODO: handle upgrade and listen for ws
            if self.headers.get('upgrade', '').lower() == 'websocket':
                self.proto = "WSS" if self.is_ssl else "WS"
                self.push_request_event()
                self.send_invalid_method_and_close()
                return

        # if (self.headers['upgrade'] or '').lower() == 'h2c':
        #     # Upgrade request to HTTP2.
        #     self.proto += "2"
        #     self.push_request_event("GET")
        #     return

        self.push_request_event()
        self.send_response_body()
        
    def do_POST(self):
        self.push_request_event()
        self.send_response_body()

    def do_PUT(self):
        self.push_request_event()
        # if self.path == '/api/v2/healthcheck':
            
        self.send_response_body()

    def do_PATCH(self):
        self.push_request_event()
        self.send_response_body()

    def do_DELETE(self):
        self.push_request_event()
        self.send_response_body()

    def do_HEAD(self):
        self.push_request_event()
        self.send_response(200)
        self.send_header('Content-Length', 0)
        self.end_headers()

    def do_OPTIONS(self):
        self.push_request_event()
        self.send_response(200)
        self.send_header('Content-Length', 0)
        self.end_headers()

    def do_CONNECT(self):
        self.proto = "TUNNEL/" + self.proto
        self.push_request_event()
        # TODO: implement proxying for traffic
        self.send_invalid_method_and_close()

    def do_PRI(self):
        self.proto += "2"
        self.push_request_event()
        self.send_invalid_method_and_close()

    def send_invalid_method_and_close(self):
        self.send_response(405)
        self.send_header('Connection', 'close')
        self.end_headers()

    def send_error(self, code, message=None, explain=None):
        """Override send_error to report anomalies"""
        self.push_anomaly_event(message, explain=explain)
        self.send_response(code, message)
        self.send_header('Connection', 'close')
        self.end_headers()
        # return super().send_error(code, message, explain)

    def handle_webdav(self):
        self.proto = "WEBDAV/" + self.proto
        self.push_request_event()
        self.send_invalid_method_and_close()

    def handle_method(self, method):
        self.info(f"parsed HTTP method: {method}")
        if method in WEBDAV_COMMANDS:
            self.handle_webdav(method)
            return
        mname = 'do_' + method
        if not hasattr(self, mname):
            self.send_error(
                HTTPStatus.NOT_IMPLEMENTED,
                "Unsupported method (%r)" % method)
            return
        method = getattr(self, mname)
        method()

    def handle_one_request(self):
        """Override the high-level handling of a request.

        Adds: timestamp
        Modifies: set a lower requestline length limit
        """
        self.request_timestamp = self.log_date_time_string()
        try:
            self.raw_requestline = self.rfile.readline(MAX_REQUESTLINE_LENGTH + 1)
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
            self.body = self.rfile.read(content_length).decode('utf-8', errors='replace')
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
        self.body = ''
        
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

    def peek_for_websocket(self, sock):
        """NOTE: MSG_PEEK does not work with SSL sockets, likely bc SSL decryption can't be streamed but is done in blocks?"""
        # Peek a bit generously.
        data = sock.recv(MAX_REQUESTLINE_LENGTH + 1000, socket.MSG_PEEK)
        lines = data.split(b'\n')
        if len(lines) <= 1:
            return False

        # Parse headers.
        for line in lines[1:]:
            if not line:
                break # End of headers, start of body.

            try:
                name, value = line.split(b':', 1)
            except TypeError: # malformed header, invalid HTTP
                logger.debug(f"Detected malformed HTTP line: {line}, skipping ws peek")
                break
            
            if (name.strip().lower(), value.strip().lower()) == (b'upgrade', b'websocket'):
                return True

        return False

    # def handle_websocket(self):
    #     # self.push_request_event("CONNECT")
    #     self.push_event()

    def handle(self):
        """Override handle to catch low-level socket errors gracefully."""
        
        # if self.server.support_ws:
        #     self.is_ws = self.peek_for_websocket(self.connection)
        #     if self.is_ws:
        #         self.proto = "WSS" if self.is_ssl else "WS"
        #         logger.info('Peeked and detected websocket request.')
        try:
            # if self.is_ws:
            #     self.handle_websocket()
            # else:
            self.info("handling request...")
            super().handle()
        except (ConnectionResetError, BrokenPipeError) as e:
            # Log the reset but don't crash
            self.push_anomaly_event(f"TCP socket was opened, but connection reset ({e})")
        except ssl.SSLError as e:
            self.push_anomaly_event(f"ssl error during handle ({e})")
        finally:
            try:
                if self.is_ssl:
                    self.info("closing ssl connection...")
                    self.connection.unwrap()
            except BrokenPipeError as e:
                self.push_anomaly_event(f"{e.__class__.__name__}: {e}", tags=["insecure-ssl-cert", "signer-not-trusted"])
            except ssl.SSLError as e:
                self.push_anomaly_event(
                    f"ssl error 2 ({e})",
                    tags=["ssl-domain-enumeration", "insecure-ssl-cert", "cert-subject-name-does-not-match-hostname", "close-connection"]
                )
            except Exception as e:
                self.push_anomaly_event(f"{e.__class__.__name__}: {e} (during ssl unwrap)")
                
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

class HttpOastServer:
    def __init__(
        self,
        host: str = '0.0.0.0',
        port: int = 8080,
        RequestHandlerClass = OastRequestHandler,
        *,
        default_status_code: int = 200,
        default_body: str = '',
        server_header: str = None,
        headers: List[str] = [],
        static_file_prefix: str = '/static',
        support_ws: bool = False,
        support_https: bool = False,
        https_only: bool = False,
        certfile = None,
        keyfile = None,
    ):
        self.server = server = ThreadingHTTPServer((host, port), RequestHandlerClass)
        server.port = port
        server.files = self.files = {}
        server.queue = self.queue = queue.Queue(maxsize=30)
        server.default_status_code = default_status_code
        server.default_body = default_body
        server.server_header = server_header
        server.headers = []
        for h in headers:
            k, v = h.split(':')
            server.headers.append((k.strip(), v.strip()))
        self.static_file_prefix = static_file_prefix
        server.running = False
        server.support_ws = support_ws
        server.support_https = support_https or https_only
        server.https_only = https_only
        server.certfile = certfile
        server.keyfile = keyfile
        server.password = None
        server.alpn_protocols = None

    def serve_file(self, filename: str, content: bytes, mime_type: str = 'text/html'):
        filename = os.path.realpath(f'{self.static_file_prefix}/{filename}')
        self.files[filename] = (mime_type, content)
        logger.info(f"Load {filename} with {mime_type} and {len(content)} bytes")
    
    @staticmethod
    def _run_http_server(server):
        server.serve_forever()
        server.server_close()
        
    def serve(self):
        self.server.running = True
        self.thread = threading.Thread(target=HttpOastServer._run_http_server, args=(self.server, ))
        self.thread.start()

    def serve_forever(self):
        self.serve()
        self.thread.join()
    
    def wait(self, timeout=None):
        if self.server.running and timeout:
            try:
                return self.queue.get(timeout=timeout)
            except queue.Empty:
                return None
        else:
            # "Blocking"
            while self.server.running:
                try:
                    # Use polling here, in case we need to quit the thread (e.g. due to SIGINT / ^C)
                    if item := self.queue.get(timeout=1):
                        return item
                except queue.Empty:
                    pass
            return None
        # items = self.queue.get()
        # return items

    def shutdown(self):
        self.server.running = False
        self.server.shutdown()
        # self.thread.join()


@dataclass
class LoggingEventHandler:
    """
    Simple example of handling events which outputs the events to console and file.
    """
    filter_str: str = ''
    correlation_regex: str = ''
    output_all: bool = False
    ignore_common_headers: bool = False
    jsonl_file: str = ''
    no_anomaly: bool = False
    notify_platform: str = ''
    notify_on: List[str] = field(default_factory=list)
    webhook_url: str = ''
    identifier: str = ''
    def __post_init__(self):
        self.correlation_regex = re.compile(self.correlation_regex) if self.correlation_regex else None
        if self.notify_platform:
            try:
                import requests
            except ImportError:
                printe('Notifications requires the requests package:')
                printe()
                printe('\tpip install requests')
                sys.exit(1)
            self.requests = requests

    def handle_event(self, data):
        """
        Handle events fired from the Request Handler. The implementation is up to you,
        but here I chose to base it structurally on field names, for convenience.
        i.e. find the first handler which accepts the data fields in its named parameters

        The disadvantage of this is
        """
        event_handlers = [self.handle_request, self.handle_anomaly, self.handle_response]
        for func in event_handlers:
            try:
                func(**data)
                break
            except TypeError as e:
                # Failed to fit parameters, move on
                logger.debug(f'skipping {func.__name__}: {e}')
                logger.debug(traceback.format_exc())
                continue
        else:
            # Default handler
            printe('Discarding event:', data)

    def handle_request(self, *, proto, method, requestline, path, headers, body, **kwargs):
        matches = self.should_log(requestline, body)
        if not matches and not self.output_all: return
        correlation_id = self.extract_correlation_id(requestline, headers, body)
        self.log_to_jsonl(
            proto=proto, method=method, requestline=requestline, path=path, headers=headers, body=body,
            filter_match=matches, correlation_id=correlation_id,
            **kwargs,
        )
        
        top_status = bot_status = proto
        if matches:
            if self.filter_str:
                top_status = 'MATCH'
        else:
            top_status = 'REJECTED'

        self.strip_headers_in_place(headers)
        self.log_request_to_display(
            method, requestline, path, headers, body, matches, correlation_id,
            top_status, bot_status, **kwargs)
        
        notify_type = "none"
        if matches:
            notify_type = "match"
        if correlation_id:
            notify_type = "correlation"
        self.notify(
            notify_type, proto=proto, filter_match=matches, correlation_id=correlation_id,
            requestline=requestline, path=path, headers=headers, body=body,
            **kwargs)

    def handle_response(self, *, response_message, client, event_timestamp, **kwargs):
        self.log_to_jsonl(response_message=response_message, **kwargs)
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
        self.notify("anomaly", anomaly=anomaly, details=details, **kwargs)

    def log_to_jsonl(self, *, headers=None, **kwargs):
        if not self.jsonl_file: return
        jsonl_headers = {k.lower(): v for k, v in headers.items()} if headers else {}
        output = json.dumps(dict(**kwargs, headers=jsonl_headers))
        if self.jsonl_file == '-':
            print(output, flush=True)
        else:
            with open(self.jsonl_file, "a", encoding="utf-8") as f:
                print(output, file=f, flush=True)

    def log_request_to_display(
        self, method, requestline, path, headers, body, matches, correlation_id,
        top_status, bot_status,
        *, request_timestamp, event_timestamp, client,
        **_kwargs,
    ):
        if matches:
            printe(f"{CLR_CYN}{top_status:-<12}-{client:->15}---{request_timestamp}{CLR_RST}")
            printe(f"{CLR_GRN}{requestline}{CLR_RST}")
            if headers:
                printe(f"{CLR_YLW}{str(headers).strip()}{CLR_RST}")
            if body: printe(f"{body}")
            if correlation_id:
                printe(f"{CLR_CYN}{bot_status:-<12}-{correlation_id:->15}---{event_timestamp}{CLR_RST}\n")
            else:
                printe(f"{CLR_CYN}{bot_status:-<30}-{event_timestamp}{CLR_RST}\n")
        else:
            printe(f"{CLR_RED}{top_status:-<12}-{client:->15}---{request_timestamp}{CLR_RST}")
            printe(f"{CLR_RED}{requestline}{CLR_RST}")
            printe(f"{CLR_RED}{bot_status:-<30}-{event_timestamp}{CLR_RST}\n")

    def log_anomaly_to_display(self, anomaly, *, tags, details, connect_timestamp, event_timestamp, client, status='ANOMALY', **kwargs):
        printe(f"{CLR_YLW}{status:-<12}{client:->16}---{connect_timestamp}{CLR_RST}")
        printe(f"{CLR_RED}{anomaly}{CLR_RST}")
        if tags:
            c = ', '.join(tags)
            printe(f"{CLR_GRN}tags: {c}{CLR_RST}")
        if details:
            printe(f"{CLR_YLW}{escape_non_printable(details)}{CLR_RST}")
        if requestline := kwargs.get('requestline', None):
            printe(f"{CLR_YLW}{escape_non_printable(requestline)}{CLR_RST}")
        if headers := kwargs.get('headers', None):
            printe(f"{CLR_YLW}{escape_non_printable(str(headers).strip())}{CLR_RST}")
        if body := kwargs.get('body', None):
            printe(f"{CLR_YLW}{escape_non_printable(body)}{CLR_RST}")

        bot_status = kwargs.get('proto', status)
        printe(f"{CLR_YLW}{bot_status:-<30}-{event_timestamp}{CLR_RST}\n")

    def notify(self, type: Literal["match"] | Literal["correlation"] | Literal["anomaly"], event_timestamp, client, proto, **kwargs):
        if not self.notify_platform:
            return
        if type in self.notify_on or "all" in self.notify_on:
            emoji = ":bulb:" if type in ["match", "correlation"] else ":warning:"
            msg = f"{emoji} {type.upper()} - [{event_timestamp}] {emoji}\n"
            msg += f"**Instance**: {self.identifier}\n"
            msg += f"**Protocol**: {proto}\n"
            msg += f"**Client IP**: {client}\n"
            if matches := kwargs.get("filter_match", None):
                msg += f"**Filter**: {self.filter_str}\n"
            if correlation_id := kwargs.get("correlation_id", None):
                msg += f"**Correlation ID**: {correlation_id}\n"
            if type in ["match", "correlation"]:
                msg += f"**Request**:\n```http\n"
                msg += kwargs["requestline"] + "\n"
                msg += str(kwargs["headers"])
                msg += kwargs["body"] + "\n"
                msg += "```"
            if type == "anomaly":
                msg += f"**Anomaly**:\n```\n"
                msg += f"{kwargs['anomaly']}\n"
                if deets := kwargs.get("details", None):
                    msg += escape_non_printable(deets) + "\n"
                msg += f"```"
            data = {"content": msg}
            try:
                self.requests.post(self.webhook_url, json=data)
            except self.requests.exceptions.RequestException as e:
                logger.error(f'failed to send webhook: {e}')

    def strip_headers_in_place(self, headers):
        if self.ignore_common_headers:
            for k in list(headers.keys()):
                if k.lower() in COMMON_HEADERS:
                    del headers[k]

    def should_log(self, requestline, body):
        f_str = self.filter_str
        if not f_str:
            return True
        return f_str in requestline or f_str in body

    def extract_correlation_id(self, requestline, headers, body):
        r = self.correlation_regex
        if not r:
            return None

        results = r.findall(f"{requestline}\n{headers}\n{body}")
        if results:
            return results[0]
        else:
            return None

def escape_non_printable(s):
    if type(s) == bytes:
        s = s.decode(errors='backslashreplace')
    return "".join(c if c.isprintable() or c in '\r\n' else r'\x{0:02x}'.format(ord(c)) for c in s)

def scan_and_read_files(directory_path):
    content = {}
    for root, dirs, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            with open(file_path, 'rb') as f:
                rel_file_path = os.path.relpath(file_path, start=directory_path)
                content[rel_file_path] = f.read()

    return content

def start_server(args, port, files, **kwargs):
    server = HttpOastServer(
        args.bind, port,
        **dict(
            default_status_code=args.status_code,
            default_body=args.body,
            server_header=args.server,
            headers=args.header,
            static_file_prefix=args.base_path,
            support_https=args.https,
            certfile=args.certfile,
            keyfile=args.keyfile,
            support_ws=args.websockets,
        ) | kwargs,
    )

    if files:
        for filename, content in files.items():
            server.serve_file(filename, content)
    
    return server


class Formatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass

def run():
    parser = argparse.ArgumentParser(
        description=f"Dead simple HTTP OAST server by TrebledJ.",
        formatter_class=Formatter,
    )
    
    parser.add_argument("--bind", "-b", type=str, default='0.0.0.0', help="Bind to this address")
    parser.add_argument("--port", "-p", type=int, default=8000)
    parser.add_argument('-v', action='count', default=0, help='Verbosity. -v for INFO, -vv for DEBUG messages.')
    parser.add_argument('--config', '-c', type=str, help='.toml config file')

    group = parser.add_argument_group('response')
    group.add_argument("--status-code", "-S", type=int, default=200, help="The default status code to return")
    group.add_argument("--body", type=str, default='', help="The default content to return. This could be a file, which will be loaded")
    group.add_argument("--server", type=str, default='SimpleOAST (https://github.com/TrebledJ/simpleoast)', help="Server header in response. Special values: random, none")
    group.add_argument("--header", "-H", type=str, action='append', default=[], help='Headers to include in server output. You can specify multiple of these arguments')

    group.add_argument("--directory", "-d", type=str, help='The directory to serve files from. Files served from this directory always return status code 200')
    group.add_argument("--base-path", type=str, default='/static', help='The base path to "put" static files in. A base path of /static means files can be accessed through http://HOSTNAME:PORT/static')

    group = parser.add_argument_group('display/logging')
    group.add_argument("--filter", type=str, default=None, help="Match request line and body")
    group.add_argument("--correlation-regex", "-r", type=str, help='Extract correlation ID based on regex, this works independently of the filter')
    group.add_argument("--jsonl", "-o", type=str, help="Output file path for JSONL logging (one JSON event per line). Use `--jsonl -` to output to stdout")
    group.add_argument("--output-all", "-f", action='store_true', help="Output all HTTP requests, including those that don't match the filter")
    group.add_argument("--ignore-common-headers", "-i", action='store_true', help='Exclude common request headers from display. This does not affect jsonl output')
    group.add_argument("--no-anomaly", action='store_true', help='Do not log anomalies')

    group = parser.add_argument_group('protocol')
    group.add_argument('--https', action='store_true', help='Enable https polyglot support. ')
    group.add_argument("--certfile", type=str, help='')
    group.add_argument("--keyfile", type=str, help='')
    group.add_argument("--websockets", "-ws", action='store_true', help='Enable websocket support. Limited support, currently only detects the HTTP handshake')
    
    group.add_argument("--start80443", action='store_true', help='Start a http server on port 80, and https server on port 443. Ignores the --port parameter')

    group = parser.add_argument_group('notifications')
    group.add_argument('--notify', choices=['discord'], help='Enable third-party notifications')
    group.add_argument('--notify-on', choices=['match', 'correlation', 'anomaly', 'all'], default=['match'], nargs='+', help='You can pass multiple choices, for example: `--notify-on match anomaly`. "all" means notify on match/correlation/anomaly')
    group.add_argument('--webhook', type=str, help='Webhook URL')
    group.add_argument('--id', type=str, default=None, help='An identifier which will be sent along with the notification, primarily to help you identify this instance in case you have multiple running. An id will be automatically generated if not provided')

    pargs = parser.parse_args()

    if pargs.config:
        try:
            with open(pargs.config, 'rb') as f:
                conf = tomllib.load(f)
        except FileNotFoundError as e:
            printe(e)
            sys.exit(1)
    else:
        conf = {}

    # Reparse args to overwrite older arguments
    # print('config:', dict(**conf))
    # print('args:', pargs.__dict__)
    args = parser.parse_args(namespace=argparse.Namespace(**conf))
    # print('new args:', args.__dict__)
    

    if args.directory and not os.path.exists(args.directory):
        printe(f"{CLR_RED}path does not exist:{CLR_RST}: {args.directory}")
        sys.exit(1)

    if args.https:
        if not args.certfile or not args.keyfile:
            printe(f"{CLR_RED}HTTPS enabled, but certfile or keyfile was not provided{CLR_RST}")
            sys.exit(1)

        if not os.path.exists(args.certfile):
            printe(f"{CLR_RED}certfile does not exist:{CLR_RST}: {args.certfile}")
            sys.exit(1)
        if not os.path.exists(args.keyfile):
            printe(f"{CLR_RED}keyfile does not exist:{CLR_RST}: {args.keyfile}")
            sys.exit(1)
    
    if args.body:
        if os.path.exists(args.body):
            with open(args.body, 'rb') as f:
                args.body = f.read()
    if type(args.body) == str:
        args.body = args.body.encode('utf-8')
    
    if args.id is None:
        args.id = f"{socket.gethostname()}_{args.port}"
        if args.start80443:
            args.id = f"{socket.gethostname()}_web"

    if args.server == 'random':
        args.server = random_server()
    elif args.server == 'none':
        args.server = None

    if args.v == 0:
        logger.setLevel(logging.WARNING)
    elif args.v == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.DEBUG)
    
    # try:
    #     if args.websockets and websockets:
    #         pass
    # except NameError:
    #     printe(f"{CLR_RED}Error: unable to load websockets module.{CLR_RST}")
    #     printe(f"Make sure you have websockets installed: pip install websockets")
    #     sys.exit(1)

    # Prepare files.
    if args.directory:
        files = scan_and_read_files(args.directory)
    else:
        files = {}

    if args.start80443:
        server80 = start_server(args, 80, files, support_https=False)
        server443 = start_server(args, 443, files, https_only=True)
        servers = [server80, server443]
        printe(f"{CLR_GRN}Server listening on {args.bind}:{80} and {args.bind}:{443}{CLR_RST}")
    else:
        servers = [start_server(args, args.port, files)]
        printe(f"{CLR_GRN}Server listening on {args.bind}:{args.port}{CLR_RST}")

    if args.body:
        status_message = OastRequestHandler.responses.get(args.status_code, ["(Unknown Status)"])[0]
        printe(f"{CLR_CYN}Default response:{CLR_RST} {CLR_GRN}{args.status_code} {status_message}{CLR_RST}, {CLR_YLW}{len(args.body)} bytes{CLR_RST}")

    if args.filter: printe(f"{CLR_YLW}Filter active:{CLR_RST} {args.filter}")
    if args.correlation_regex: printe(f"{CLR_YLW}Correlation ID regex:{CLR_RST} {args.correlation_regex}")
    if args.jsonl: printe(f"{CLR_CYN}JSONL logging to:{CLR_RST} {args.jsonl}")
    if args.notify: printe(f"{CLR_CYN}Notifications:{CLR_RST} {args.notify}")
    printe()

    handler = LoggingEventHandler(
        filter_str=args.filter,
        output_all=args.output_all,
        jsonl_file=args.jsonl,
        ignore_common_headers=args.ignore_common_headers,
        correlation_regex=args.correlation_regex,
        no_anomaly=args.no_anomaly,
        notify_platform=args.notify,
        notify_on=args.notify_on,
        webhook_url=args.webhook,
        identifier=args.id,
    )

    for server in servers:
        server.serve()
    
    try:
        # Poll servers.
        while True:
            for server in servers:
                if (event := server.wait(0.2)) is not None:
                    handler.handle_event(event)
    except KeyboardInterrupt:
        for server in servers:
            server.shutdown()


if __name__ == "__main__":
    run()
