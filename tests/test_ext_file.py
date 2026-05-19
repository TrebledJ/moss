import pytest
import tempfile
from pathlib import Path

_FILE_CONTENT = "Hello from test.txt"
_INDEX_CONTENT = "<html><body>Index</body></html>"
_DEEP_CONTENT = "Deep file"
_OUTSIDE_CONTENT = "This file is outside the served directory"

_TEMP_DIR = Path(tempfile.mkdtemp())
_BASE_DIR = _TEMP_DIR / "base"
_BASE_DIR.mkdir()

(_TEMP_DIR / "outside.txt").write_text(_OUTSIDE_CONTENT)
(_BASE_DIR / "test.txt").write_text(_FILE_CONTENT)
(_BASE_DIR / "index.html").write_text(_INDEX_CONTENT)

_subdir = _BASE_DIR / "subdir"
_subdir.mkdir()
(_subdir / "deep.txt").write_text(_DEEP_CONTENT)


@pytest.mark.moss_args("-e", "file", "-d", str(_BASE_DIR))
class TestFileServer:
    def test_serves_existing_file(self, http_client):
        r = http_client.get("/files/test.txt")
        assert r.status_code == 200
        assert r.content == _FILE_CONTENT.encode()
        assert "text/plain" in r.headers.get("content-type", "")

    def test_returns_404_for_missing(self, http_client):
        r = http_client.get("/files/nonexistent.txt")
        assert r.status_code == 404

    def test_outside_base_path_not_served_by_file_ext(self, http_client):
        r = http_client.get("/other/test.txt")
        assert _FILE_CONTENT.encode() not in r.content


@pytest.mark.moss_args("-e", "file", "-d", str(_BASE_DIR), "--file-url-path", "/static")
class TestFileServerCustomBase:
    def test_serves_via_custom_base(self, http_client):
        r = http_client.get("/static/test.txt")
        assert r.status_code == 200
        assert r.content == _FILE_CONTENT.encode()

    def test_original_base_not_served(self, http_client):
        r = http_client.get("/files/test.txt")
        assert _FILE_CONTENT.encode() not in r.content


@pytest.mark.moss_args("-e", "file", "-d", str(_BASE_DIR), "--file-index")
class TestFileServerIndex:
    def test_directory_listing_for_subdir(self, http_client):
        r = http_client.get("/files/subdir/")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("content-type", "")
        assert "deep.txt" in r.content.decode()

    def test_index_html_served_instead_of_listing(self, http_client):
        r = http_client.get("/files/")
        assert r.status_code == 200
        assert _INDEX_CONTENT.encode() in r.content


@pytest.mark.moss_args("-e", "file", "-d", str(_BASE_DIR))
class TestFileServerSubdir:
    def test_serves_file_in_subdir(self, http_client):
        r = http_client.get("/files/subdir/deep.txt")
        assert r.status_code == 200
        assert r.content == _DEEP_CONTENT.encode()

    def test_url_encoded_traversal_blocked(self, http_client):
        r = http_client.get("/files/..%2foutside.txt")
        assert r.status_code == 404

    def test_deep_url_encoded_traversal_blocked(self, http_client):
        r = http_client.get("/files/..%2f..%2foutside.txt")
        assert r.status_code == 404

    def test_trailing_slash_on_file_returns_404(self, http_client):
        r = http_client.get("/files/test.txt/")
        assert r.status_code == 404


def teardown_module(module):
    import shutil
    shutil.rmtree(_TEMP_DIR, ignore_errors=True)
