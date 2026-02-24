"""
ext/sfile.py

---

This is a simple extension which demonstrates a sending files from the local
file system. Files are scanned and preloaded into memory for safety guarantees
at the expense of memory.

When loaded, HttpMossServer is extended with a .serve_file() method, which
accepts a file name (the HTTP sub-path to access the file), the content (in
bytes), and the mime type.

This extension is not intended to be used in conjunction with ext/file.py.
"""

from dataclasses import dataclass, field
import os, sys
import mimetypes

GROUP = "fileserver (ext/sfile.py)"

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

def guess_mime_type(path):
    guess, _ = mimetypes.guess_type(path)
    if guess:
        return guess
    return 'application/octet-stream'

@dataclass
class SimpleFileServerMixin:
    # You can define your own CLI/API arguments.
    fileserver_base_path: str = _field("/files", group=GROUP, doc="The HTTP base path to \"put\" static files in. A base path of /static means files can be accessed through http://HOSTNAME:PORT/static")
    directory: str = _field(None, group=GROUP, flags=["--directory", "-d"], doc="The local directory to serve files from. Files served from this directory always return status code 200")
    files: dict = _field(dict, cli=False) # This option won't be treated as a CLI flag.
    # You can access injected utilities such as self.logger, self.printerr, and self.printstatus.

    def __post_init__(self):
        # This is where you handle init, validate args, etc.

        if self.directory and not os.path.exists(self.directory):
            self.printerr(f"path does not exist: {self.directory}")
            sys.exit(1)

        if not self.fileserver_base_path.startswith('/'):
            self.printerr(f"fileserver base path does not start with /: {self.fileserver_base_path}")
            sys.exit(1)

        # Note: serve_file() and self.files may be used by other mixins prior to this post_init.
        # Be careful that we don't overwrite self.files.
        files = scan_and_read_files(self.directory) if self.directory else {}
        for filename, content in files.items():
            mime_type = guess_mime_type(filename)
            self.serve_file(filename, content, mime_type=mime_type)
        
        if self.files:
            self.printstatus(f"Serving: {len(self.files)} files")

        # Any instance properties will be copied over to req.server.
        # So it is possible to access req.server.base_path, req.server.directory, and req.server.files.
        
        # Make sure to call super post init so that other mixins also handle init!
        super().__post_init__()

    def serve_file(self, filename: str, content: bytes, mime_type: str = "text/html"):
        filename = os.path.realpath(f"{self.fileserver_base_path}/{filename}")
        if type(content) == str:
            content = content.encode("utf-8")
        self.files[filename] = (mime_type, content)
        self.logger.info(f"Load {filename} with {mime_type} and {len(content)} bytes")

@dataclass
class SimpleFileServerProcessor:
    # Processors are responsible for handling requests.
    # You can use this to do your own logging, push your own events, or customise responses to servers.

    enable_file_index: bool = _field(False, group=GROUP, flags=["--file-index"], doc="Enable an index page listing files within the directory")

    def get_services(self, server):
        # This is function provides information on the services offered by this processor,
        # used in listing services for the index page.
        return [(server.fileserver_base_path, "files")]
    
    def do_GET(self, req):
        if req.path in req.server.files:
            mime_type, content = req.server.files[req.path]
            req.send_response_full(200, content=content, mime=mime_type)

            # Extensions can push their own events. These will be passed to all Handler classes.
            req.push_event(response_message=f"sent file {req.path} with {len(content)} bytes")

            # Return True to tell dispatch that response is finished!
            return True
        elif self.enable_file_index and req.path.rstrip('/') == req.server.fileserver_base_path:
            return self.list_files(req)

        # By default, a Python function returns None.
        # This is used to communicate to moss that the request was not yet handled.

    def handle_fallback(self, req):
        # If no do_METHOD function was found for a processor, it will fallback to... you guessed it! handle_fallback()
        pass

    def list_files(self, req):
        r = []
        title = f'Directory listing'
        r.append('<!DOCTYPE HTML>')
        r.append('<html lang="en">')
        r.append('<head>')
        r.append('<style type="text/css">\n:root {\ncolor-scheme: light dark;\n}\n</style>')
        r.append(f'<title>{title}</title>\n</head>')
        r.append(f'<body>\n<h1>{title}</h1>')
        r.append('<hr>\n<ul>\n')
        for file in req.server.files:
            r.append(f'<li><a href="{file}">{file[len(req.server.fileserver_base_path):]}</a></li>\n')

        r.append('</ul>\n<hr>\n</body>\n</html>\n')
        req.send_response_full(200, content="".join(r), mime="text/html")
        return True

