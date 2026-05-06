import pytest


class TestStealthnetBasic:
    """Basic stealthnet extension tests (LOW PRIORITY - deprioritized)."""

    @pytest.mark.moss_args("-e", "stealthnet", "-vv")
    def test_stealth_path_loads(self, http_client):
        """Default stealth path /sneakers should serve index.html."""
        r = http_client.get("/sneakers")
        assert r.status_code == 200

    @pytest.mark.moss_args("-e", "stealthnet", "--stealth-no-validate", "-vv")
    def test_stealth_no_validate(self, http_client):
        """Should work with --stealth-no-validate flag."""
        r = http_client.get("/sneakers")
        assert r.status_code == 200


class TestStealthnetProfile:
    """Test profile loading (LOW PRIORITY - deprioritized)."""

    def test_profile_not_found(self):
        """Should exit on missing profile file."""
        import subprocess
        result = subprocess.run(
            ["python", "-m", "moss.moss", "-e", "stealthnet", "--stealth-profile", "nonexistent.json"],
            capture_output=True,
            text=True,
            cwd="D:\\workspace\\00\\moss"
        )
        assert result.returncode != 0
        assert "error loading profile" in result.stderr.lower() or "FileNotFoundError" in result.stderr
