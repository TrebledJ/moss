import pytest
import base64

@pytest.mark.moss_args("-e", "auth", "--basic-auth", "testuser:testpass")
class TestBasicAuth:
    def test_valid_credentials(cls, http_client):
        auth_value = "Basic " + base64.b64encode(b"testuser:testpass").decode()
        http_client.headers["Authorization"] = auth_value
        r = http_client.get("/")
        assert r.status_code == 200

    def test_invalid_credentials(cls, http_client):
        auth_value = "Basic " + base64.b64encode(b"wrong:pass").decode()
        http_client.headers["Authorization"] = auth_value
        r = http_client.get("/")
        assert r.status_code == 401
        assert "WWW-Authenticate" in r.headers
        assert "Basic" in r.headers["WWW-Authenticate"]

    def test_missing_credentials(cls, http_client):
        r = http_client.get("/")
        assert r.status_code == 401
        assert "WWW-Authenticate" in r.headers


@pytest.mark.moss_args("-e", "auth", "--token-auth", "mysecrettoken")
class TestBearerAuth:
    def test_valid_token(cls, http_client):
        http_client.headers["Authorization"] = "Bearer mysecrettoken"
        r = http_client.get("/")
        assert r.status_code == 200

    def test_invalid_token(cls, http_client):
        http_client.headers["Authorization"] = "Bearer wrongtoken"
        r = http_client.get("/")
        assert r.status_code == 401
        assert "WWW-Authenticate" in r.headers
        assert "Bearer" in r.headers["WWW-Authenticate"]

    def test_missing_token(cls, http_client):
        r = http_client.get("/")
        assert r.status_code == 401
