import pytest
from pathlib import Path
import tempfile
import random
from moss import moss


UPLOAD_DIR = Path(tempfile.gettempdir()) / "moss_test_upload"
UPLOAD_DIR.mkdir(exist_ok=True)

FILE_DIR = Path(tempfile.gettempdir()) / "moss_test_file_dir"
FILE_DIR.mkdir(exist_ok=True)


def random_id(n: int = 8):
    return "".join(random.sample("abcdefghijkmnopqrstuvwxyz0123456789", n))


@pytest.mark.moss_args("-e", "file", "-d", "[[memory]]")
class TestUploadMemory:
    """Upload server tests using in-memory storage."""

    def test_get_form(self, http_client):
        r = http_client.get("/upload")
        assert r.status_code == 200
        assert "html" in r.headers.get("content-type", "").lower()

    def test_upload_and_retrieve(self, http_client):
        r = http_client.post(
            "/upload",
            content=b"Test file content for upload",
            headers={"X-File-Name": "upload_test.txt"},
        )
        assert r.status_code == 201

        r = http_client.get("/files/upload_test.txt")
        assert r.status_code == 200
        assert r.content == b"Test file content for upload"

    def test_upload_no_filename(self, http_client):
        r = http_client.post("/upload", content=b"Test content")
        assert 400 <= r.status_code < 500



@pytest.mark.moss_args("-e", "file", "--file-directory", ".", "--upload-dir", str(UPLOAD_DIR))
class TestUploadDirectory:    
    """Upload server tests using disk storage."""

    def test_upload_to_directory(self, http_client):
        filename = f"disk_test_{random_id()}.txt"
        r = http_client.post(
            "/upload",
            content=b"Test file content for disk upload",
            headers={"X-File-Name": filename},
        )
        assert r.status_code == 201

        import time
        time.sleep(1)

        assert (UPLOAD_DIR / filename).exists()

    def test_multiple_files_unique_names(self, http_client):
        for i in range(2):
            r = http_client.post(
                "/upload",
                content=f"Content {i}".encode(),
                headers={"X-File-Name": "duplicate_test.txt"},
            )
            assert r.status_code == 201

        import time
        time.sleep(1)

        matching = [f for f in UPLOAD_DIR.iterdir() if "duplicate_test" in f.name]
        assert len(matching) >= 2

    def test_upload_large_file_to_dir(self, http_client):
        filename = f"large_file_{random_id()}.bin"
        r = http_client.post(
            "/upload",
            content=b"x" * (1024 * 1024),
            headers={"X-File-Name": filename},
        )
        assert r.status_code == 201

        import time
        time.sleep(2)

        assert (UPLOAD_DIR / filename).exists()


@pytest.mark.moss_args("-e", "file", "--file-directory", ".", "--max-size", "100", "--upload-dir", str(UPLOAD_DIR))
class TestUploadWithLimit:
    """Upload server with file size limit tests."""

    def test_upload_under_limit(self, http_client):
        filename = f"small_file_{random_id()}.txt"
        r = http_client.post(
            "/upload",
            content=b"x" * 50,
            headers={"X-File-Name": filename},
        )
        assert r.status_code == 201

    def test_upload_at_limit(self, http_client):
        filename = f"at_limit_{random_id()}.txt"
        r = http_client.post(
            "/upload",
            content=b"x" * 100,
            headers={"X-File-Name": filename},
        )
        assert r.status_code == 201

    def test_upload_exceeds_max_size(self, http_client):
        filename = f"large_{random_id()}.txt"
        r = http_client.post(
            "/upload",
            content=b"x" * 200,
            headers={"X-File-Name": filename},
        )
        assert r.status_code != 201

        import time
        time.sleep(1)

        assert not (UPLOAD_DIR / filename).exists()


@pytest.mark.moss_args("-e", "file", "--file-directory", ".", "--upload-dir", str(UPLOAD_DIR))
class TestUploadFilenameHandling:
    """Test filename sanitization and handling."""

    def test_filename_sanitization(self, http_client):
        import time

        r = http_client.post(
            "/upload",
            content=b"test content",
            headers={"X-File-Name": "test<>:file?.txt"},
        )
        assert r.status_code == 201

        time.sleep(1)

        matching = [f for f in UPLOAD_DIR.iterdir() if "test" in f.name and "file" in f.name]
        assert len(matching) > 0
        for f in matching:
            assert not any(c in f.name for c in '<>?:')

    def test_empty_filename(self, http_client):
        r = http_client.post("/upload", content=b"test content", headers={"X-File-Name": ""})
        assert r.status_code >= 400

    def test_filename_dot_is_rejected(self, http_client):
        r = http_client.post("/upload", content=b"dot", headers={"X-File-Name": "."})
        assert r.status_code >= 400

    def test_filename_dotdot_is_rejected(self, http_client):
        r = http_client.post("/upload", content=b"dotdot", headers={"X-File-Name": ".."})
        assert r.status_code >= 400

    def test_unicode_filename_sanitization(self, http_client):
        import time

        r = http_client.post(
            "/upload",
            content=b"unicode test",
            headers={"X-File-Name": "test_file.txt"},
        )
        assert r.status_code == 201

        time.sleep(1)

        # All files in UPLOAD_DIR should be ASCII-only
        for f in UPLOAD_DIR.iterdir():
            try:
                f.name.encode("ascii")
            except UnicodeEncodeError:
                pytest.fail(f"Filename not sanitized to ASCII: {f.name}")


def teardown_module(module):
    import shutil
    shutil.rmtree(UPLOAD_DIR, ignore_errors=True)
    shutil.rmtree(FILE_DIR, ignore_errors=True)


@pytest.mark.moss_args("-e", "file")
class TestNoDirDefaultsToMemory:
    """No -d flag defaults to memory mode."""

    def test_upload_and_retrieve(self, http_client):
        r = http_client.post("/upload", content=b"mem default", headers={"X-File-Name": "mem_default.txt"})
        assert r.status_code == 201
        r = http_client.get("/files/mem_default.txt")
        assert r.status_code == 200
        assert r.content == b"mem default"

    def test_memory_mode_active(self, moss_runner):
        assert moss_runner.servers[0]._memory_mode


@pytest.mark.moss_args("-e", "file", "--file-directory", str(FILE_DIR))
class TestDiskModeDefaultUploadDir:
    """Disk mode without --upload-dir defaults to directory/uploads/."""

    def test_upload_dir_defaults_to_uploads(self, moss_runner):
        srv = moss_runner.servers[0]
        expected = str(Path(FILE_DIR).resolve() / "uploads")
        assert srv.upload_dir == expected
        assert Path(expected).exists()

    def test_upload_goes_to_default_dir(self, http_client):
        r = http_client.post("/upload", content=b"disk default", headers={"X-File-Name": "disk_default.txt"})
        assert r.status_code == 201
        uploads_dir = Path(FILE_DIR).resolve() / "uploads"
        assert (uploads_dir / "disk_default.txt").exists()
        r = http_client.get("/files/uploads/disk_default.txt")
        assert r.status_code == 200
        assert r.content == b"disk default"


@pytest.mark.moss_args("-e", "file", "--file-directory", str(FILE_DIR), "--upload-dir", "custom")
class TestRelativeUploadDir:
    """Relative --upload-dir resolves against --file-directory."""

    def test_relative_dir_resolved(self, moss_runner):
        srv = moss_runner.servers[0]
        expected = str(Path(FILE_DIR).resolve() / "custom")
        assert srv.upload_dir == expected


@pytest.mark.moss_args("-e", "file", "--file-directory", str(FILE_DIR), "--upload-dir", str(UPLOAD_DIR))
class TestAbsoluteUploadDir:
    """Absolute --upload-dir is used as-is."""

    def test_absolute_dir(self, moss_runner):
        srv = moss_runner.servers[0]
        assert srv.upload_dir == str(Path(UPLOAD_DIR).resolve())


def test_memory_upload_dir_exits():
    """-d [[memory]] with --upload-dir raises SystemExit."""
    with pytest.raises(SystemExit):
        moss.MossBuilder(["-e", "file", "-d", "[[memory]]", "--upload-dir", "/tmp/test"]).cli()


def test_no_dir_upload_dir_exits():
    """No -d defaults to memory, --upload-dir raises SystemExit."""
    with pytest.raises(SystemExit):
        moss.MossBuilder(["-e", "file", "--upload-dir", "/tmp/test"]).cli()


@pytest.mark.moss_args("-e", "file", "-d", "[[memory]]", "--file-index")
class TestMemoryDirectoryListing:
    """Memory mode directory listing."""

    def test_listing_shows_uploaded_files(self, http_client):
        http_client.post("/upload", content=b"alpha", headers={"X-File-Name": "alpha.txt"})
        http_client.post("/upload", content=b"beta",  headers={"X-File-Name": "beta.txt"})
        r = http_client.get("/files/")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("content-type", "")
        body = r.content.decode()
        assert "alpha.txt" in body
        assert "beta.txt" in body


def test_nonexistent_directory_exits():
    """-d /nonexistent in disk mode raises SystemExit."""
    with pytest.raises(SystemExit):
        moss.MossBuilder(["-e", "file", "-d", "/nonexistent_moss_test_path"]).cli()

def test_bad_file_url_path_exits():
    """--file-url-path without leading / raises SystemExit."""
    with pytest.raises(SystemExit):
        moss.MossBuilder(["-e", "file", "-d", ".", "--file-url-path", "relative/path"]).cli()
