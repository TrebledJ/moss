"""
ext/file.py

Combined file server with upload support for MOSS. Supports in-memory and
on-disk file serving, file uploads, and directory listing.

In-memory mode: pass `-d [[memory]]` to enable serve_file() API and serve
files from RAM instead of disk.

Upload mode: files received via POST to --upload-url-path are stored in memory
or on disk and served alongside regular files.

Usage:
    moss -e file -d /path/to/serve --file-url-path /static --file-index
    moss -e file -d [[memory]] --file-index  (in-memory mode)
    moss -e file -d /srv/files --upload-dir /srv/uploads (disk uploads)

CLI flags:
    --file-url-path PATH   HTTP base path for file access (default: /files)
    --file-directory, -d    Local directory to serve files from,
                            or [[memory]] for in-memory mode
    --file-index            Enable index/directory listing page
    --upload-url-path PATH  HTTP path for uploads (default: /upload)
    --upload-dir, -ud       Directory to store uploaded files (default: same as -d)
    --max-size BYTES        Max upload file size (default: 10485760)
"""

from dataclasses import dataclass, field
from pathlib import Path
import sys, html, urllib, mimetypes, string, random

GROUP = "fileserver (ext/file.py)"

def _field(default, group=None, doc="", metadata={}, flags=[], choices=[], **kwargs):
    """Simple wrapper to express fields more conveniently."""
    dwargs = {}
    if type(default).__name__ in ["function", "type"]:
        dwargs["default_factory"] = default
    else:
        dwargs["default"] = default
    return field(**dwargs, metadata=metadata | dict(group=group, doc=doc, flags=flags, choices=choices, **kwargs))

def relative_under_base_path(path, url_base_path):
    """Checks whether the incoming URL matches the file server base path.
    If so, return the relative path under.
    """
    if url_base_path == '/':
        return path
    ps = path.rstrip('/').split('/')
    bps = url_base_path.rstrip('/').split('/')
    for a, b in zip(ps, bps):
        if a != b:
            return None
    if len(ps) < len(bps):
        return None
    return '/' + "/".join(ps[len(bps):])

@dataclass
class FileServerMixin:
    fileserver_url_path: str = _field("/files", group=GROUP, flags=["--file-url-path"], doc="The HTTP base path to access files. A base path of /static means files can be accessed through http://HOSTNAME:PORT/static")
    directory: str = _field("[[memory]]", group=GROUP, flags=["--file-directory", "-d"], doc="The local directory to serve files from, or [[memory]] for in-memory mode")
    upload_url_path: str = _field("/upload", group=GROUP, doc="HTTP path which accepts upload payloads")
    upload_dir: str = _field(None, group=GROUP, flags=["--upload-dir", "-ud"], doc="Directory to store uploaded files (default: same as --file-directory)")
    max_size: int = _field(10485760, group=GROUP, flags=["--max-size"], doc="Max upload file size in bytes")

    files: dict = _field(dict, cli=False)
    _memory_mode: bool = _field(False, cli=False)

    extensions_map = {
        '.gz': 'application/gzip',
        '.bz2': 'application/x-bzip2',
        '.xz': 'application/x-xz',
    }

    def __post_init__(self):
        if self.directory == "[[memory]]":
            self.directory = None
            self._memory_mode = True
        elif self.directory is None:
            self._memory_mode = True

        if self._memory_mode:
            if self.upload_dir:
                self.error("[file] --upload-dir cannot be used with [[memory]] mode")
                sys.exit(1)
            self.status("[file] in-memory mode enabled")
        else:
            if not self.directory:
                self.directory = '.'
            if not Path(self.directory).exists():
                self.error(f"[file] path does not exist: {self.directory}")
                sys.exit(1)
            if self.upload_dir:
                p = Path(self.upload_dir)
                if not p.is_absolute():
                    p = Path(self.directory) / self.upload_dir
                self.upload_dir = str(p.resolve())
            else:
                self.upload_dir = str(Path(self.directory).resolve() / 'uploads')
            Path(self.upload_dir).mkdir(parents=True, exist_ok=True)

        if not self.fileserver_url_path.startswith('/'):
            self.error(f"[file] base path does not start with /: {self.fileserver_url_path}")
            sys.exit(1)

        if not self.upload_url_path.startswith('/'):
            self.error(f"[file] upload path does not start with /: {self.upload_url_path}")
            sys.exit(1)

        super().__post_init__()

    def serve_file(self, filename, content, mime_type=None):
        if isinstance(content, str):
            content = content.encode("utf-8")
        if mime_type is None:
            mime_type = self.guess_mime_type(filename)
        if self._memory_mode:
            key = f"{self.fileserver_url_path}/{filename}".replace("\\", "/")
            self.files[key] = (mime_type, content)
            return key
        dest = get_unique_filename(self.upload_dir, filename)
        with open(dest, "wb") as f:
            f.write(content)
        return dest

    def get_file(self, url_path):
        """Get (mime_type, content) for a URL path. Returns None if not found."""
        rel = relative_under_base_path(url_path, self.fileserver_url_path)
        if rel is None:
            return None

        if self._memory_mode:
            key = f"{self.fileserver_url_path}/{rel.lstrip('/')}".replace("\\", "/")
            return self.files.get(key, None)

        fp = self._resolve(rel)
        if fp is None or not fp.exists():
            return None

        if url_path.endswith('/') and not fp.is_dir():
            return None

        if fp.is_dir():
            for index in "index.html", "index.htm":
                ip = fp / index
                if ip.is_file():
                    return (self.guess_mime_type(str(ip)), ip.read_bytes())
            return None

        try:
            return (self.guess_mime_type(str(fp)), fp.read_bytes())
        except OSError:
            return None

    def get_directory_entries(self, url_path):
        """Get list of (name, is_dir, is_symlink) for directory listing. Returns None if not a directory."""
        if self._memory_mode:
            if url_path.rstrip('/') != self.fileserver_url_path.rstrip('/'):
                return None
            entries = []
            bp = self.fileserver_url_path.rstrip('/')
            for path in sorted(self.files):
                display = path[len(bp):] if path.startswith(bp + '/') else path
                entries.append((display.lstrip('/'), False, False))
            return entries

        rel = relative_under_base_path(url_path, self.fileserver_url_path)
        if rel is None:
            return None
        fp = self._resolve(rel)
        if fp is None or not fp.is_dir():
            return None
        try:
            return [(e.name, e.is_dir(), e.is_symlink()) for e in fp.iterdir()]
        except OSError:
            return None

    def _resolve(self, relpath):
        """Resolve a URL-safe relative path to a local filesystem Path, or None if outside the base directory."""
        relpath = relpath.split('#', 1)[0]
        relpath = relpath.split('?', 1)[0]
        try:
            relpath = urllib.parse.unquote(relpath, errors='surrogatepass')
        except UnicodeDecodeError:
            relpath = urllib.parse.unquote(relpath)
        base = Path(self.directory).resolve()
        candidate = (base / relpath.lstrip('/')).resolve()
        try:
            candidate.relative_to(base)
            return candidate
        except ValueError:
            return None

    def guess_mime_type(self, filepath):
        """Guess the type of a file."""
        _, ext = filepath.rsplit('.', 1) if '.' in filepath else (filepath, '')
        ext = '.' + ext
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        guess, _ = mimetypes.guess_type(filepath)
        if guess:
            return guess
        return 'application/octet-stream'


@dataclass
class FileServerProcessor:
    enable_file_index: bool = _field(False, group=GROUP, flags=["--file-index"], doc="Enable an index page listing files within the directory")

    def get_services(self, server):
        return [(server.fileserver_url_path, "files"), (server.upload_url_path, "upload")]

    def do_GET(self, req):
        if req.path == req.server.upload_url_path:
            req.send_response_full(200, content=UPLOAD_FORM_HTML, mime="text/html")
            return True

        file_data = req.server.get_file(req.path)
        if file_data is not None:
            mime_type, content = file_data
            req.send_response_full(200, content=content, mime=mime_type)
            return True

        if self.enable_file_index:
            entries = req.server.get_directory_entries(req.path)
            if entries is not None:
                self._render_directory_listing(req, entries)
                return True

        if relative_under_base_path(req.path, req.server.fileserver_url_path) is None:
            return
        req.send_error(404, "File not found")
        return True

    def do_POST(self, req):
        if req.path != req.server.upload_url_path:
            return

        filename = req.headers.get('x-file-name')
        if not filename:
            self.error(f"[file] POST {req.server.upload_url_path} request missing filename")
            req.send_response_full(400)
            return True

        filename = sanitise_filename(filename)
        if not filename or filename in ('.', '..'):
            self.error(f"[file] POST {req.server.upload_url_path} request has invalid filename")
            req.send_response_full(400)
            return True

        if len(req.body) > req.server.max_size:
            self.error(f"[file] Incoming file exceeded max size ({len(req.body)} > {req.server.max_size})")
            req.send_response_full(413)
            return True

        try:
            req.server.serve_file(filename, req.body)
        except (FileNotFoundError, PermissionError) as e:
            self.error(f"[file] Failed to write upload: {e}")
            req.send_response_full(500, content=str(e).encode(), mime='text/plain')
            return True

        req.send_response_full(201, content=b'ok', mime='text/plain')
        req.push_event(response_message=f"uploaded file {filename} with {len(req.body)} bytes")
        return True

    def handle_fallback(self, req):
        pass

    def _render_directory_listing(self, req, entries):
        """Render directory entries as an HTML listing page."""
        displaypath = req.path
        displaypath = displaypath.split('#', 1)[0]
        displaypath = displaypath.split('?', 1)[0]
        try:
            displaypath = urllib.parse.unquote(displaypath, errors='surrogatepass')
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(displaypath)
        displaypath = html.escape(displaypath, quote=False)
        enc = sys.getfilesystemencoding()
        title = f'Directory listing for {displaypath}'
        r = []
        r.append('<!DOCTYPE HTML>')
        r.append('<html lang="en">')
        r.append('<head>')
        r.append(f'<meta charset="{enc}">')
        r.append('<style type="text/css">\n:root {\ncolor-scheme: light dark;\n}\n</style>')
        r.append(f'<title>{title}</title>\n</head>')
        r.append(f'<body>\n<h1>{title}</h1>')
        r.append('<hr>\n<ul>')
        for name, is_dir, is_symlink in entries:
            displayname = linkname = name
            linkname = req.path.rstrip('/') + '/' + linkname
            if is_dir:
                displayname += "/"
                linkname += "/"
            if is_symlink:
                displayname = name + "@"
            r.append('<li><a href="%s">%s</a></li>'
                    % (urllib.parse.quote(linkname, errors='surrogatepass'),
                       html.escape(displayname, quote=False)))
        r.append('</ul>\n<hr>\n</body>\n</html>\n')
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        req.send_response_full(200, mime="text/html; charset=%s" % enc, content=encoded)


def get_unique_filename(path, filename):
    p = Path(path) / filename
    while p.exists():
        p = (Path(path) / f"{p.stem}_{random_id(4)}").with_suffix(p.suffix)
    return str(p)

def random_id(n: int):
    return "".join(random.sample("abcdefghijkmnopqrstuvwxyz0123456789", n))

DEFAULT_CHAR = ord("_")
WHITELIST = (string.ascii_letters + string.digits + "_-.").encode()

def sanitise_filename(s: bytes | str) -> str:
    if isinstance(s, str):
        s = s.encode("utf-8")
    s = bytes([(c if c in WHITELIST else DEFAULT_CHAR) for c in s])
    return s.decode()

UPLOAD_FORM_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>File Upload</title>
<meta name="viewport" content="width=device-width, user-scalable=no" />
<meta name="color-scheme" content="light dark">
</head>
<body>
<h1>File Upload</h1>
<form action="" method="POST" enctype="multipart/form-data">
<input id="fileInput" name="files" type="file" multiple />
<br />
<br />
<input type="submit" />
</form>
<p id="task"></p>
<p id="status"></p>
</body>
<script>
document.getElementsByTagName('form')[0].addEventListener('submit', async (e) => {
  e.preventDefault();
  const fileInput = document.getElementById('fileInput');
  const file = fileInput.files[0];
  const xhr = new XMLHttpRequest();

  xhr.timeout = 3600000

  xhr.onreadystatechange = () => {
    if (xhr.readyState === XMLHttpRequest.DONE) {
      let message = `${xhr.status}: ${xhr.statusText}`
      if (xhr.status === 0) message = 'Connection failed'
      if (xhr.status === 204) {
        message = `Success: ${xhr.statusText}`
      }
      document.getElementById('status').textContent = message
    }
  }

  xhr.upload.onprogress = e => {
    document.getElementById('status').textContent = (e.loaded === e.total ?
      'Saving\xe2\x80\xa6' :
      `${Math.floor(100*e.loaded/e.total)}% ` +
      `[${Math.floor(e.loaded/1024)} / ${Math.floor(e.total/1024)}KiB]`
    )
  }

  xhr.open(e.target.method, e.target.action, true);
  xhr.setRequestHeader("Content-Type", file.type || "application/octet-stream");
  xhr.setRequestHeader("X-File-Name", file.name);

  xhr.send(file);

  document.getElementById('task').textContent = `Uploading ${file.name}:`
  document.getElementById('status').textContent = '0%'
});
</script>
</html>
""".strip().encode()
