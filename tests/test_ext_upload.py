import pytest
from pathlib import Path
import tempfile
import random


UPLOAD_DIR = Path(tempfile.gettempdir()) / "moss_test_upload"
UPLOAD_DIR.mkdir(exist_ok=True)


def random_id(n: int = 8):
    return "".join(random.sample("abcdefghijkmnopqrstuvwxyz0123456789", n))


@pytest.mark.moss_args("-e", "upload")
class TestUploadServer:
    """Basic upload server tests."""

    def test_get_form(self, http_client):
        r = http_client.get("/upload")
        assert r.status_code == 200
        assert "html" in r.headers.get("content-type", "").lower()

    def test_upload_file(self, http_client):
        r = http_client.post(
            "/upload",
            content=b"Test file content for upload",
            headers={"X-File-Name": "test.txt"},
        )
        assert r.status_code == 201

    def test_upload_no_filename(self, http_client):
        r = http_client.post("/upload", content=b"Test content")
        assert 400 <= r.status_code < 500

    def test_upload_store_type_memory(self, moss_runner):
        for h in moss_runner.handlers:
            if hasattr(h, "upload_store_type"):
                assert h.upload_store_type == "memory"
                break

    def test_upload_file_memory(self, http_client):
        r = http_client.post(
            "/upload",
            content=b"Memory stored content",
            headers={"X-File-Name": "mem_test.txt"},
        )
        assert r.status_code == 201



@pytest.mark.moss_args("-e", "upload", "--upload-to", str(UPLOAD_DIR))
class TestUploadServerWithDirectory:
    """Upload server with directory storage tests."""

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


@pytest.mark.moss_args("-e", "upload", "--upload-max-size", 100, "--upload-to", str(UPLOAD_DIR))
class TestUploadServerWithLimit:
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


@pytest.mark.moss_args("-e", "upload", "--upload-to", str(UPLOAD_DIR))
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
