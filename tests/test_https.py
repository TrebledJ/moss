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

    def test_post_under_rfile_buffer_size(cls, http_client):
        r = http_client.post("/api/data", content="a"*7000)
        assert r.text == TEST_BODY

    def test_post_with_rfile_buffer_size(cls, http_client):
        r = http_client.post("/api/data", content="a"*8192)
        assert r.text == TEST_BODY

    def test_post_much_over_rfile_buffer_size(cls, http_client):
        r = http_client.post("/api/data", content="a"*8192*2)
        assert r.text == TEST_BODY

    def test_post_much_over_rfile_buffer_size2(cls, http_client):
        r = http_client.post("/api/data", content="a"*8192*3)
        assert r.text == TEST_BODY

    def test_post_with_rfile_buffer_size_py314(cls, http_client):
        r = http_client.post("/api/data", content="a"*131072)
        assert r.text == TEST_BODY

    def test_post_over_rfile_buffer_size_py314(cls, http_client):
        r = http_client.post("/api/data", content="a"*int(131072*1.5))
        assert r.text == TEST_BODY

    def test_post_over_rfile_buffer_size_py314_2(cls, http_client):
        r = http_client.post("/api/data", content="a"*131072*2)
        assert r.text == TEST_BODY