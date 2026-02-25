"""
ext/file.py

---

This is an extension which resembles Python's default http.server.

Index page (directory listing) can be enabled with `--index`.

This is different from ext/sfile.py in that files are queried from the filesystem
during the HTTP request rather than during init. This extension also does
not provide a `serve_file()` API, which would allow scripting/automation
to customise server responses.

This extension is not intended to be used in conjunction with ext/sfile.py.
"""

from dataclasses import dataclass, field
import os, sys
import html, urllib
import shutil, posixpath, mimetypes
from http.server import HTTPStatus
import email
import datetime

GROUP = "fileserver (ext/file.py)"

def _field(default, group=None, doc="", metadata={}, flags=[], choices=[], **kwargs):
    """Simple wrapper to express fields more conveniently."""
    dwargs = {}
    if type(default).__name__ in ["function", "type"]:
        dwargs["default_factory"] = default
    else:
        dwargs["default"] = default
    return field(**dwargs, metadata=metadata | dict(group=group, doc=doc, flags=flags, choices=choices, **kwargs))

@dataclass
class FileServerProcessor:
    fileserver_base_path: str = _field("/files", group=GROUP, flags=["--file-base-path"], doc="The HTTP base path to access files. A base path of /static means files can be accessed through http://HOSTNAME:PORT/static")
    directory: str = _field(None, group=GROUP, flags=["--file-directory", "-d"], doc="The local directory to serve files from. Files served from this directory always return status code 200")
    enable_file_index: bool = _field(False, group=GROUP, flags=["--file-index"], doc="Enable an index page listing files within the directory")

    extensions_map = _encodings_map_default = {
        '.gz': 'application/gzip',
        '.bz2': 'application/x-bzip2',
        '.xz': 'application/x-xz',
    }

    def __post_init__(self):
        if not self.directory:
            # self.directory = os.getcwd()
            self.directory = '.'

        if self.directory and not os.path.exists(self.directory):
            self.printerr(f"path does not exist: {self.directory}")
            sys.exit(1)

        if not self.fileserver_base_path.startswith('/'):
            self.printerr(f"base path does not start with /: {self.fileserver_base_path}")
            sys.exit(1)

    def get_services(self, server):
        return [(self.fileserver_base_path, "files")]

    def do_GET(self, req):
        # Get the relative path from the directory.
        relpath = self.relative_under_base_path(req.path, self.fileserver_base_path)
        if relpath is None:
            return
        # Sanitise and decode
        path = self.translate_path(self.directory, relpath)
        f = self.send_head(req, path)
        if f:
            try:
                self.copyfile(f, req.wfile)
            finally:
                f.close()
        return True

    def relative_under_base_path(self, path, url_base_path):
        """Checks whether the incoming URL matches the file server base path.
        If so, return the relative path under.
        For instance, if /static/abc is under /static.
        """
        if url_base_path == '/':
            # All URL paths should match.
            return path
        ps = path.rstrip('/').split('/')
        bps = url_base_path.rstrip('/').split('/')
        for a, b in zip(ps, bps):
            if a != b:
                return None
        if len(ps) < len(bps):
            # e.g. if path=/static, base_path=/static/files --> should not match
            return None
        return '/' + "/".join(ps[len(bps):])
    
    def handle_fallback(self, req):
        # If no do_METHOD function was found for a processor, it will fallback to... you guessed it! handle_fallback()
        pass

    # def do_HEAD(self, req):
    #     """Serve a HEAD request."""
    #     f = self.send_head(req)
    #     if f:
    #         f.close()

    def send_head(self, req, path):
        """Common code for GET and HEAD commands.

        This sends the response code and MIME headers.

        Return value is either a file object (which has to be copied
        to the outputfile by the caller unless the command was HEAD,
        and must be closed by the caller under all circumstances), or
        None, in which case the caller has nothing further to do.

        """
        f = None
        if os.path.isdir(path):
            self.logger.info(f"fileserver: (dir) {path}")
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.isfile(index):
                    path = index
                    break
            else:
                return self.list_directory(req, path)
        
        self.logger.info(f"fileserver: (file) {path}")
        ctype = self.guess_type(path)
        # check for trailing "/" which should return 404. See Issue17324
        # The test for this was added in test_httpserver.py
        # However, some OS platforms accept a trailingSlash as a filename
        # See discussion on python-dev and Issue34711 regarding
        # parsing and rejection of filenames with a trailing slash
        if path.endswith("/"):
            req.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None
        try:
            f = open(path, 'rb')
        except OSError:
            req.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None

        try:
            fs = os.fstat(f.fileno())
            # Use browser cache if possible
            if ("If-Modified-Since" in req.headers
                    and "If-None-Match" not in req.headers):
                # compare If-Modified-Since and time of last file modification
                try:
                    ims = email.utils.parsedate_to_datetime(
                        req.headers["If-Modified-Since"])
                except (TypeError, IndexError, OverflowError, ValueError):
                    # ignore ill-formed values
                    pass
                else:
                    if ims.tzinfo is None:
                        # obsolete format with no timezone, cf.
                        # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
                        ims = ims.replace(tzinfo=datetime.timezone.utc)
                    if ims.tzinfo is datetime.timezone.utc:
                        # compare to UTC datetime of last modification
                        last_modif = datetime.datetime.fromtimestamp(
                            fs.st_mtime, datetime.timezone.utc)
                        # remove microseconds, like in If-Modified-Since
                        last_modif = last_modif.replace(microsecond=0)

                        if last_modif <= ims:
                            req.send_response(HTTPStatus.NOT_MODIFIED)
                            req.end_headers()
                            f.close()
                            return None

            req.send_response(HTTPStatus.OK)
            req.send_header("Content-type", ctype)
            req.send_header("Content-Length", str(fs[6]))
            req.send_header("Last-Modified",
                req.date_time_string(fs.st_mtime))
            req.end_headers()
            return f
        except:
            f.close()
            raise

    def list_directory(self, req, path):
        """Adapted from Python's http.server implementation.
        
        Helper to produce a directory listing (absent index.html).

        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().

        """
        if not self.enable_file_index:
            req.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        try:
            list = os.listdir(path)
        except OSError:
            req.send_error(
                404,
                "No permission to list directory")
            return None
        list.sort(key=lambda a: a.lower())
        r = []
        displaypath = req.path
        displaypath = displaypath.split('#', 1)[0]
        displaypath = displaypath.split('?', 1)[0]
        try:
            displaypath = urllib.parse.unquote(displaypath,
                                            errors='surrogatepass')
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(displaypath)
        displaypath = html.escape(displaypath, quote=False)
        enc = sys.getfilesystemencoding()
        title = f'Directory listing for {displaypath}'
        r.append('<!DOCTYPE HTML>')
        r.append('<html lang="en">')
        r.append('<head>')
        r.append(f'<meta charset="{enc}">')
        r.append('<style type="text/css">\n:root {\ncolor-scheme: light dark;\n}\n</style>')
        r.append(f'<title>{title}</title>\n</head>')
        r.append(f'<body>\n<h1>{title}</h1>')
        r.append('<hr>\n<ul>')
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            linkname = req.path.rstrip('/') + '/' + linkname
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                displayname += "/"
                linkname += "/"
            if os.path.islink(fullname):
                displayname = name + "@"
                # Note: a link to a directory displays with @ and links with /
            r.append('<li><a href="%s">%s</a></li>'
                    % (urllib.parse.quote(linkname,
                                        errors='surrogatepass'),
                    html.escape(displayname, quote=False)))
        r.append('</ul>\n<hr>\n</body>\n</html>\n')
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        req.send_response_full(200, mime="text/html; charset=%s" % enc, content=encoded)
        
    
    def translate_path(self, directory, path):
        """Translate a /-separated PATH to the local filename syntax.

        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)

        """
        # abandon query parameters
        path = path.split('#', 1)[0]
        path = path.split('?', 1)[0]
        # Don't forget explicit trailing slash when normalizing. Issue17324
        try:
            path = urllib.parse.unquote(path, errors='surrogatepass')
        except UnicodeDecodeError:
            path = urllib.parse.unquote(path)
        trailing_slash = path.endswith('/')
        path = posixpath.normpath(path)
        words = path.split('/')
        words = filter(None, words)
        path = directory
        for word in words:
            if os.path.dirname(word) or word in (os.curdir, os.pardir):
                # Ignore components that are not a simple file/directory name
                continue
            path = os.path.join(path, word)
        if trailing_slash:
            path += '/'
        return path

    def copyfile(self, source, outputfile):
        """Copy all data between two file objects.

        The SOURCE argument is a file object open for reading
        (or anything with a read() method) and the DESTINATION
        argument is a file object open for writing (or
        anything with a write() method).

        The only reason for overriding this would be to change
        the block size or perhaps to replace newlines by CRLF
        -- note however that this the default server uses this
        to copy binary data as well.

        """
        shutil.copyfileobj(source, outputfile)

    def guess_type(self, path):
        """Guess the type of a file.

        Argument is a PATH (a filename).

        Return value is a string of the form type/subtype,
        usable for a MIME Content-type header.

        The default implementation looks the file's extension
        up in the table self.extensions_map, using application/octet-stream
        as a default; however it would be permissible (if
        slow) to look inside the data to make a better guess.

        """
        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        guess, _ = mimetypes.guess_type(path)
        if guess:
            return guess
        return 'application/octet-stream'
    