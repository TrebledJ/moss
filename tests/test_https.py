import pytest

TEST_BODY = "whatchamacallit"

@pytest.mark.moss_args("-vv")
@pytest.mark.moss_https
class TestDefault:
    def test_basic_call_works(cls, http_client):
        r = http_client.get("/")
        assert r.status_code != 0


@pytest.mark.moss_args("--status-code", 404, "--body", TEST_BODY)
@pytest.mark.moss_https
class TestHttpResponse:
    def test_basic_get(cls, http_client):
        r = http_client.get("/")
        assert r.status_code == 404

    def test_basic_post(cls, http_client):
        r = http_client.post("/api/check")
        assert r.status_code == 404

    def test_post_with_expected_body(cls, http_client):
        r = http_client.get("/api/submit")
        assert r.text == TEST_BODY
