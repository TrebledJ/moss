"""
ext/upload.py

---

A simple file upload extension inspired by
https://github.com/Densaugeo/uploadserver/.

For simplicity, this implementation uses the entire POST body (no form data) to
upload files. As such, only one file can be uploaded at a time.

"""

from dataclasses import dataclass, field
import string
from pathlib import Path
import random

GROUP = "uploadserver (ext/upload.py)"

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
    upload_inmem_max_size: int = _field(1 * 1024**2, group=GROUP, doc="Max file size for files cached in-memory. Defaults to 1 MiB")
    upload_max_size: int = _field(2 * 1024**3, group=GROUP, doc="Max file size accepted for files stored on disk. Defaults to 2 GiB")

    def __post_init__(self):
        if self.upload_to and not (p := Path(self.upload_to)).exists():
            self.logger.warning(f"upload path did not exist, creating path... (mkdir {self.upload_to})")
            p.mkdir(parents=True, exist_ok=True)
        self.uploaded_files = {}
        super().__post_init__()

    def list_uploaded_files(self):
        return list(self.uploaded_files)
    
    def get_uploaded_file(self, file):
        return self.uploaded_file.get(file, None)

class UploadProcessor:
    def do_GET(self, req):
        if req.path == req.server.upload_path:
            req.send_response(200)
            req.send_header('Content-Type', 'text/html')
            req.send_header('Content-Length', len(UPLOAD_FORM_HTML))
            req.end_headers()
            req.wfile.write(UPLOAD_FORM_HTML)
            return True
        
    def do_POST(self, req):
        if req.path != req.server.upload_path:
            return
        
        filename = req.headers['x-file-name']
        if not filename:
            self.printerr(f"Got POST {req.server.upload_path} request, but no filename")
            return
        filename = sanitise_filename(filename)

        length = len(req.body)
        if length <= req.server.upload_inmem_max_size:
            req.server.uploaded_files[filename] = req.body
        else:
            pass
            # Not an error, since we allowed uploads to be stored in file, especially for larger files.

        req.send_response(201)
        content = b'ok'
        req.send_header('Content-Type', 'text/plain')
        req.send_header('Content-Length', len(content))
        req.end_headers()
        req.wfile.write(content)

        if not req.server.upload_to:
            return True
        
        if length > req.server.upload_max_size:
            self.printerr(f"Incoming file exceeded max file size ({length} > {req.server.upload_max_size})")
            return True
        
        path = get_unique_filename(req.server.upload_to, filename)
        try:
            with open(path, "wb") as f:
                f.write(req.body)
        except (FileNotFoundError, PermissionError) as e:
            self.printerr(f"Encountered {e.__class__.__name__}: {e}")
            return True
            
        return True

def get_unique_filename(path, filename):
    p = Path(path) / filename
    while p.exists():
        p = (Path(path) / f"{p.stem}_{random_id(4)}").with_suffix(p.suffix)
    return p

def random_id(n: int):
    return "".join(random.sample("abcdefghijkmnopqrstuvwxyz0123456789", n))

DEFAULT_CHAR = b"_"
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
<form action="upload" method="POST" enctype="multipart/form-data">
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


