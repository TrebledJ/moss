import pytest

TEST_BODY = "whatchamacallit"

@pytest.mark.moss_args()
class TestDefault:
    def test_server_moss(cls, http_client):
        r = http_client.get("/")
        assert r.headers.get("server") is not None
        assert "moss" in str(r.headers["server"]).lower()

    def test_basic_call_works(cls, http_client):
        r = http_client.get("/")
        assert r.status_code != 0

@pytest.mark.moss_args("--status-code", 404, "--body", TEST_BODY)
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

    @pytest.mark.asyncio
    async def test_async_call(cls, async_http_client):
        r = await async_http_client.get("/yabadabadoo")
        assert r.status_code == 404

@pytest.mark.moss_args("--server", "random")
class TestServerRandom:
    def test_server_opsec(cls, http_client):
        r = http_client.get("/")
        assert r.headers.get("server") is not None
        assert "github" not in str(r.headers["server"]).lower()
        assert "moss" not in str(r.headers["server"]).lower()

@pytest.mark.moss_args("--server", "none")
class TestServerNone:
    def test_no_server_header(cls, http_client):
        r = http_client.get("/")
        assert r.headers.get("server") is None

LONG_HEADER = "a" * 1000
WEIRD_HEADER = "$ %,17!(*^(!@[]|{}./))"
@pytest.mark.moss_args("-H", "X-A: 123", "-H", f"longheader: {LONG_HEADER}", "-H", f"weirdheader: {WEIRD_HEADER}")
class TestCustomHeader:
    def test_header_params(cls, http_client):
        r = http_client.get("/")
        assert r.headers.get("x-a") == "123"
        assert r.headers.get("longheader") == LONG_HEADER
        assert r.headers.get("weirdheader") == WEIRD_HEADER


def expect_anomaly(srv, anomaly_description, with_tags=[]):
    while (event := srv.wait(1)) is not None:
        tags_ok = len(set(with_tags) - set(event.get("tags", []))) == 0
        if anomaly_description in event.get("anomaly", "") and tags_ok:
            return # Assert ok! Return early.
    else:
        assert False, f"expected anomaly containing '{anomaly_description}'"


@pytest.mark.moss_args("--status-code", 200, "-vv")
class TestRequestLine:
    def test_request_line(cls, http_client):
        r = http_client.get("/" + "a" * 4000)
        assert r.status_code == 200

    def test_long_request_line_status(cls, http_client):
        r = http_client.get("/" + "a" * 10000)
        assert r.status_code == 414 # 414: Request URI Too Long

    def test_long_request_line_anomaly(cls, http_client, moss_runner):
        r = http_client.get("/" + "a" * 10000)
        srv = moss_runner.servers[0]
        expect_anomaly(srv, "URI Too Long")


from moss.moss import MAX_BODY_SIZE

@pytest.mark.moss_args("-vv", "--status-code", 200)
# @pytest.mark.override_moss_port(8000)
class TestRequestTooLarge:
    def test_body_sanity_smol(cls, http_client):
        payload = 10 * "a"
        r = http_client.post("/", content=payload)
        assert r.status_code == 200

    def test_body_sanity(cls, http_client):
        payload = (MAX_BODY_SIZE - 1) * "a"
        r = http_client.post("/", content=payload)
        assert r.status_code == 200

    def test_long_body_status(cls, http_client):
        payload = (MAX_BODY_SIZE + 1) * "a"
        r = http_client.post("/", content=payload)
        assert r.status_code == 413

    def test_long_body_anomaly(cls, http_client, moss_runner):
        payload = (MAX_BODY_SIZE + 1) * "a"
        r = http_client.post("/", content=payload)
        srv = moss_runner.servers[0]
        expect_anomaly(srv, "Request Entity Too Large")

    
