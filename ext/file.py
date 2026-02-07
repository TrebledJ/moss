"""
ext/file.py

---

This is a simple extension which demonstrates a sending files from the local
file system. Files are scanned and preloaded into memory for safety guarantees
at the expense of memory.

When loaded, HttpOastServer is extended with a .serve_file() method, which
accepts a file name (the HTTP sub-path to access the file), the content (in
bytes), and the mime type.

This extension also defines two options:
    --base-path: (HTTP path) where your files can be accessed
    --directory: (local path) where to load files from

"""

from dataclasses import dataclass, field
import os, sys

GROUP = "fileserver (ext/file.py)"

def _field(default, group=None, doc="", metadata={}, flags=[], choices=[], **kwargs):
    """Simple wrapper to express fields more conveniently."""
    dwargs = {}
    if type(default).__name__ in ["function", "type"]:
        dwargs["default_factory"] = default
    else:
        dwargs["default"] = default
    return field(**dwargs, metadata=metadata | dict(group=group, doc=doc, flags=flags, choices=choices, **kwargs))

def scan_and_read_files(directory_path):
    """Helper function for recursively reading files under a folder."""
    content = {}
    for root, _dirs, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            with open(file_path, "rb") as f:
                rel_file_path = os.path.relpath(file_path, start=directory_path)
                content[rel_file_path] = f.read()
    return content

@dataclass
class SimpleFileServerMixin:
    # You can define your own CLI/API arguments.
    base_path: str = _field("/static", group=GROUP, doc="The HTTP base path to \"put\" static files in. A base path of /static means files can be accessed through http://HOSTNAME:PORT/static")
    directory: str = _field(None, group=GROUP, flags=["--directory", "-d"], doc="The local directory to serve files from. Files served from this directory always return status code 200")
    files: dict = _field(dict, cli=False)
    # You can access injected utilities such as self.logger, self.printerr, and self.printstatus.

    def __post_init__(self):
        # This is where you handle init, validate args, etc.

        if self.directory and not os.path.exists(self.directory):
            self.printerr(f"path does not exist: {self.directory}")
            sys.exit(1)

        # Note: serve_file() and self.files may be used by other mixins prior to this post_init.
        files = scan_and_read_files(self.directory) if self.directory else {}
        for filename, content in files.items():
            self.serve_file(filename, content)
        
        if self.files:
            self.printstatus(f"Serving: {len(self.files)} files")

        # Any instance properties will be copied over to req.server.
        # So it is possible to access req.server.base_path, req.server.directory, and req.server.files.
        
        # Make sure to call super post init so that other mixins also handle init!
        super().__post_init__()

    def serve_file(self, filename: str, content: bytes, mime_type: str = "text/html"):
        filename = os.path.realpath(f"{self.base_path}/{filename}")
        if type(content) == str:
            content = content.encode("utf-8")
        self.files[filename] = (mime_type, content)
        self.logger.info(f"Load {filename} with {mime_type} and {len(content)} bytes")

@dataclass
class SimpleFileServerProcessor:
    # Processors are responsible for handling requests.
    # You can use this to do your own logging, push your own events, or customise responses to servers.
    def do_GET(self, req):
        if req.path in req.server.files:
            req.send_response(200)
            mime_type, content = req.server.files[req.path]
            req.send_header("Content-Type", mime_type)
            req.send_header("Content-Length", len(content))
            req.end_headers()
            req.wfile.write(content)

            # Extensions can push their own events. self.push_event will be "injected" into the class when loaded.
            self.push_event(req, response_message=f"sent file {req.path} with {len(content)} bytes")

            # Return True to tell dispatch that response is finished!
            return True

    def handle_fallback(self, req):
        # If no do_METHOD function was found for a processor, it will fallback to... you guessed it! handle_fallback()
        pass
        