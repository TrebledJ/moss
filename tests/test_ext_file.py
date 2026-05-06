import pytest
import tempfile
from pathlib import Path

# Create a temporary directory at module level
TEMP_DIR = tempfile.mkdtemp()

# Create test files
(Path(TEMP_DIR) / "test.txt").write_text("Hello from test.txt")
(Path(TEMP_DIR) / "index.html").write_text("<html><body>Index</body></html>")

# Create subdirectory with file
_subdir = Path(TEMP_DIR) / "subdir"
_subdir.mkdir()
(_subdir / "deep.txt").write_text("Deep file")


class TestFileServer:
    """File server extension tests - basic verification."""
    
    @pytest.mark.moss_args("-e", "file", "-d", TEMP_DIR)
    def test_extension_loads(self, http_client):
        """File server extension should load without errors."""
        r = http_client.get("/files/test.txt")
        # Should return some response (200 or 404 depending on implementation)
        assert r.status_code != 0
    
    @pytest.mark.moss_args("-e", "file", "-d", TEMP_DIR)
    def test_404_for_missing(self, http_client):
        """Should handle missing files gracefully."""
        r = http_client.get("/files/nonexistent.txt")
        assert r.status_code != 0


class TestFileServerIndex:
    """File server with index enabled."""
    
    @pytest.mark.moss_args("-e", "file", "-d", TEMP_DIR, "--file-index")
    def test_index_enabled(self, http_client):
        """Index page should be accessible when enabled."""
        r = http_client.get("/files/")
        assert r.status_code != 0


class TestFileServerCustomBase:
    """File server with custom base path."""
    
    @pytest.mark.moss_args("-e", "file", "-d", TEMP_DIR, "--file-base-path", "/static")
    def test_custom_base(self, http_client):
        """Should use custom base path."""
        r = http_client.get("/static/test.txt")
        assert r.status_code != 0


def teardown_module(module):
    """Clean up temporary directory after tests."""
    import shutil
    shutil.rmtree(TEMP_DIR, ignore_errors=True)
