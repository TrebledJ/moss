import pytest

def expect_event(srv, timeout=2, **expected_kwargs):
    """Loop through events until we find one matching expected kwargs."""
    while (event := srv.wait(timeout)) is not None:
        print(f"DEBUG: Got event: {event}")
        match = True
        for key, expected_value in expected_kwargs.items():
            actual_value = event.get(key)
            print(f"DEBUG: Checking {key}: expected={expected_value}, actual={actual_value}")
            if key == "filter_matches":
                if expected_value is True and not actual_value:
                    match = False
                elif expected_value is False and actual_value:
                    match = False
            else:
                if actual_value != expected_value:
                    match = False
                    break
        if match:
            return event
    else:
        assert False, f"expected event with {expected_kwargs}"


@pytest.mark.moss_args("--filter", "secret")
class TestFilter:
    def test_filter_matches_url(cls, http_client, moss_runner):
        r = http_client.get("/?secret=123")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, filter_matches=True)
        assert event is not None

    def test_filter_no_match(cls, http_client, moss_runner):
        r = http_client.get("/?q=123")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, filter_matches=False)
        assert event is not None

    def test_filter_matches_body(cls, http_client, moss_runner):
        r = http_client.post("/", content=b"secret data here")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, filter_matches=True)
        assert event is not None


@pytest.mark.moss_args("--filter", r"code[= ]\d{3}")
class TestFilterDigits:
    def test_matches_three_digits_in_url(cls, http_client, moss_runner):
        r = http_client.get("/?code=123")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, filter_matches=True)
        assert event is not None

    def test_no_match_letters(cls, http_client, moss_runner):
        r = http_client.get("/?code=abc")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, filter_matches=False)
        assert event is not None

    def test_matches_digits_in_body(cls, http_client, moss_runner):
        r = http_client.post("/", content=b"code 123 here")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, filter_matches=True)
        assert event is not None


@pytest.mark.moss_args("--filter", r"admin|login|register")
class TestFilterOrPattern:
    def test_matches_admin(cls, http_client, moss_runner):
        r = http_client.get("/admin")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, filter_matches=True)
        assert event is not None

    def test_matches_login(cls, http_client, moss_runner):
        r = http_client.get("/login")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, filter_matches=True)
        assert event is not None

    def test_no_match_public(cls, http_client, moss_runner):
        r = http_client.get("/public")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, filter_matches=False)
        assert event is not None


@pytest.mark.moss_args("--correlation", r"id=(\d+)")
class TestCorrelation:
    def test_correlation_in_url(cls, http_client, moss_runner):
        r = http_client.get("/?id=12345")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, correlation_id="12345")
        assert event is not None

    def test_correlation_in_body(cls, http_client, moss_runner):
        r = http_client.post("/", content=b"id=67890")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, correlation_id="67890")
        assert event is not None

    def test_correlation_no_match(cls, http_client, moss_runner):
        r = http_client.get("/?q=123")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        # Wait for event and check correlation_id is None
        event = srv.wait(2)
        assert event is not None
        assert event.get("correlation_id") is None


@pytest.mark.moss_args("--filter", "xyzzy", "--filter", "qwerty")
class TestMultipleFilters:
    def test_first_pattern_matches(cls, http_client, moss_runner):
        r = http_client.get("/xyzzy")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, filter_matches=True)
        assert event is not None

    def test_second_pattern_matches(cls, http_client, moss_runner):
        r = http_client.get("/qwerty")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, filter_matches=True)
        assert event is not None

    def test_neither_pattern_matches(cls, http_client, moss_runner):
        r = http_client.get("/nope")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, filter_matches=False)
        assert event is not None


@pytest.mark.moss_args("--filter", r"Host: 127\.0\.0\.1")
class TestFilterHost:
    def test_header_matches(cls, http_client, moss_runner):
        r = http_client.get("/")
        assert r.status_code != 0
        srv = moss_runner.servers[0]
        event = expect_event(srv, filter_matches=True)
        assert event is not None
