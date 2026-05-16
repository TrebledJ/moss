"""
ext/upload.py

Simple file upload server for MOSS. Inspired by the uploadserver package
(https://github.com/Densaugeo/uploadserver/).

Uses the raw POST body (no multipart form data) — one file per request.
Files can be stored in memory or on disk.

Usage:
    moss -e upload
    moss -e upload --upload-path /receive --upload-to ./incoming

CLI flags:
    --upload-path PATH      HTTP path for uploads (default: /upload)
    --upload-to DIR         Directory to store files (default: in-memory)
    --upload-max-size BYTES Max file size; defaults to 1 MiB (memory) or MOSS max body (disk)
"""

from dataclasses import dataclass, field
import string
from pathlib import Path
import random

GROUP = "simpleupload (ext/upload.py)"

def _field(default, group=None, doc="", metadata={}, flags=[], choices=[], **kwargs):
    """Simple wrapper to express fields more conveniently."""
    dwargs = {}
    if type(default).__name__ in ['function', 'type']:
        dwargs["default_factory"] = default
    else:
        dwargs["default"] = default
    return field(**dwargs, metadata=metadata | dict(group=group, doc=doc, flags=flags, choices=choices, **kwargs))

@dataclass
class UploadServerMixin:
    upload_path: str = _field("/upload", group=GROUP, doc="HTTP path which accepts upload payloads")
    upload_to: str = _field(None, group=GROUP, doc="Store uploaded files in this directory")
    upload_max_size: int = _field(None, group=GROUP, doc="Max file size accepted for files stored on disk. Defaults to 1 MiB (for in-memory) or MOSS' max body size (for filesystem)")

    def __post_init__(self):
        if self.upload_to and not (p := Path(self.upload_to)).exists():
            self.logger.warning(f"upload path did not exist, creating path... (mkdir {self.upload_to})")
            p.mkdir(parents=True, exist_ok=True)
        self.uploaded_files = {}
        self.upload_store_type = 'file' if self.upload_to else 'memory'

        # If storing in-memory, max size defaults to 1 MiB.
        # If storing in filesystem, no max size (handled by MOSS' max body size).
        self.upload_max_size = self.upload_max_size or (1 * 1024**2 if self.upload_store_type == 'memory' else None)
        super().__post_init__()

    def list_uploaded_files(self):
        return list(self.uploaded_files)
    
    def get_uploaded_file(self, filename: str) -> bytes:
        if filename in self.uploaded_file:
            return self.uploaded_file[filename]
        
        with open(filename, "rb") as f:
            data = f.read()
            return data
    
        raise FileNotFoundError(f"could not find file: {filename}")
    
    def check_upload_limit(self, length: int):
        if self.upload_max_size:
            return length <= self.upload_max_size
        else:
            return True

    def upload_file(self, filename: str, content: bytes):
        if self.upload_store_type == 'memory':
            self.uploaded_files[filename] = content
            return True, filename
        elif self.upload_store_type == 'file':
            path = get_unique_filename(self.upload_to, filename)
            try:
                with open(path, "wb") as f:
                    f.write(content)
                return True, path
            except (FileNotFoundError, PermissionError) as e:
                return False, f"Encountered {e.__class__.__name__}: {e}"
        else:
            return False, f'unknown upload store type: {self.upload_store_type}'

class UploadProcessor:
    def get_services(self, server):
        return [(server.upload_path, "simple upload")]
    
    def do_GET(self, req):
        if req.path == req.server.upload_path:
            req.send_response_full(200, content=UPLOAD_FORM_HTML, mime="text/html")
            return True
        
    def do_POST(self, req):
        if req.path != req.server.upload_path:
            return
        
        filename = req.headers['x-file-name']
        if not filename:
            self.printerr(f"Got POST {req.server.upload_path} request, but no filename")
            req.send_response_full(400)
            return True
        
        filename = sanitise_filename(filename)
        length = len(req.body)
        if not req.server.check_upload_limit(length):
            self.printerr(f"Incoming file exceeded max file size ({length} > {req.server.upload_max_size})")
            req.send_response_full(413) # Content too large.
            return True
        
        ok, msg = req.server.upload_file(filename, req.body)
        if ok:
            req.send_response_full(201, content=b'ok', mime='text/plain')
            self.logger.info(f"Saved {len(req.body)} bytes to {msg}")
        else:
            req.send_response_full(500, content=msg.encode(), mime='text/plain')
            self.printerr(msg)
        return True

def get_unique_filename(path, filename):
    p = Path(path) / filename
    while p.exists():
        p = (Path(path) / f"{p.stem}_{random_id(4)}").with_suffix(p.suffix)
    return p

def random_id(n: int):
    return "".join(random.sample("abcdefghijkmnopqrstuvwxyz0123456789", n))

DEFAULT_CHAR = ord("_")
WHITELIST = (string.ascii_letters + string.digits + "_-.").encode()

def sanitise_filename(s: bytes | str) -> str:
    if type(s) == str:
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
      'Saving…' :
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


