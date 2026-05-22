import pytest
import json
import os
import httpx

# ──────────────────────────────────────────────────────────
#   Basic endpoints (no encryption, no input thread)
# ──────────────────────────────────────────────────────────

@pytest.mark.moss_args("-e", "debugger", "--debugger-no-input", "--debugger-id-length", "0")
class TestBasicEndpoints:
    def test_get_js(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path
        r = httpx.get(f"{moss_url}{path}", timeout=5.0)
        assert r.status_code == 200
        assert r.headers.get("content-type", "").startswith("text/javascript")
        assert "(function(){" in r.text
        assert "var base = " in r.text

    def test_get_html(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/html"
        r = httpx.get(f"{moss_url}{path}", timeout=5.0)
        assert r.status_code == 200
        assert r.headers.get("content-type", "").startswith("text/html")
        assert "<script>" in r.text

    def test_get_pending_no_cmds(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/pending"
        r = httpx.get(f"{moss_url}{path}?name=test&last_id=0", timeout=5.0)
        assert r.status_code == 200
        assert r.headers.get("content-type", "").startswith("application/json")
        assert r.json() == []

    def test_get_pending_tracks_connection(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/pending"
        httpx.get(f"{moss_url}{path}?name=browser1&last_id=0", timeout=5.0)
        conn_name = f"127.0.0.1_browser1"
        assert conn_name in srv._connections

    def test_post_result(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/result"
        payload = {"id": 1, "name": "test", "result": "hello"}
        r = httpx.post(f"{moss_url}{path}", json=payload, timeout=5.0)
        assert r.status_code == 200
        assert r.json() == {"ok": True}

    def test_post_result_error(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/result"
        payload = {"id": 2, "name": "test", "error": "ReferenceError"}
        r = httpx.post(f"{moss_url}{path}", json=payload, timeout=5.0)
        assert r.status_code == 200

    def test_post_result_missing_id(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/result"
        payload = {"name": "test"}
        r = httpx.post(f"{moss_url}{path}", json=payload, timeout=5.0)
        assert r.status_code == 400

    def test_post_result_invalid_json(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/result"
        r = httpx.post(f"{moss_url}{path}", content=b"not-json", timeout=5.0)
        assert r.status_code == 400

    def test_options_cors(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/")
        for p in [path, path + "/pending", path + "/result"]:
            r = httpx.options(f"{moss_url}{p}", timeout=5.0)
            assert r.status_code == 200
            assert r.headers.get("access-control-allow-origin") == "*"

    def test_services_index(self, moss_url):
        r = httpx.get(f"{moss_url}/", timeout=5.0)
        assert r.status_code == 200


# ──────────────────────────────────────────────────────────
#   Command flow
# ──────────────────────────────────────────────────────────

@pytest.mark.moss_args("-e", "debugger", "--debugger-no-input", "--debugger-id-length", "0")
class TestCommandFlow:
    def test_pending_returns_queued_commands(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        with srv._lock:
            srv._pending.append({"id": 100, "code": "document.cookie"})
        path = srv.debugger_path.rstrip("/") + "/pending"
        r = httpx.get(f"{moss_url}{path}?name=test&last_id=0", timeout=5.0)
        assert r.status_code == 200
        cmds = r.json()
        assert any(c["id"] == 100 and c["code"] == "document.cookie" for c in cmds)

    def test_pending_filters_by_last_id(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        with srv._lock:
            srv._pending.append({"id": 200, "code": "navigator.userAgent"})
        path = srv.debugger_path.rstrip("/") + "/pending"
        r = httpx.get(f"{moss_url}{path}?name=test&last_id=200", timeout=5.0)
        assert r.status_code == 200
        cmds = r.json()
        assert not any(c["id"] == 200 for c in cmds)


# ──────────────────────────────────────────────────────────
#   Connection tracking
# ──────────────────────────────────────────────────────────

@pytest.mark.moss_args("-e", "debugger", "--debugger-no-input", "--debugger-id-length", "0")
class TestConnectionTracking:
    def test_multiple_browsers_tracked(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/pending"
        httpx.get(f"{moss_url}{path}?name=alpha&last_id=0", timeout=5.0)
        httpx.get(f"{moss_url}{path}?name=beta&last_id=0", timeout=5.0)
        assert "127.0.0.1_alpha" in srv._connections
        assert "127.0.0.1_beta" in srv._connections


# ──────────────────────────────────────────────────────────
#   Command targeting
# ──────────────────────────────────────────────────────────

@pytest.mark.moss_args("-e", "debugger", "--debugger-no-input", "--debugger-id-length", "0")
class TestCommandTargeting:
    def test_targeted_cmd_only_delivered_to_target(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        with srv._lock:
            srv._pending.append({"id": 300, "code": "secret", "target": "127.0.0.1_alice"})
        path = srv.debugger_path.rstrip("/") + "/pending"
        r_alice = httpx.get(f"{moss_url}{path}?name=alice&last_id=0", timeout=5.0)
        r_bob = httpx.get(f"{moss_url}{path}?name=bob&last_id=0", timeout=5.0)
        assert any(c["id"] == 300 for c in r_alice.json())
        assert not any(c["id"] == 300 for c in r_bob.json())

    def test_broadcast_cmd_delivered_to_all(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        with srv._lock:
            srv._pending.append({"id": 400, "code": "1+1"})
        path = srv.debugger_path.rstrip("/") + "/pending"
        r_a = httpx.get(f"{moss_url}{path}?name=alice&last_id=0", timeout=5.0)
        r_b = httpx.get(f"{moss_url}{path}?name=bob&last_id=0", timeout=5.0)
        assert any(c["id"] == 400 for c in r_a.json())
        assert any(c["id"] == 400 for c in r_b.json())


# ──────────────────────────────────────────────────────────
#   Encryption
# ──────────────────────────────────────────────────────────

from moss.ext.debugger import _xor_encrypt, _xor_decrypt, _derive_key

_TEST_KEY = "test-encryption-key-12345"

@pytest.mark.moss_args("-e", "debugger", "--debugger-no-input", "--debugger-id-length", "0", "--debugger-key", _TEST_KEY)
class TestEncryption:
    def test_js_contains_key(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path
        r = httpx.get(f"{moss_url}{path}", timeout=5.0)
        assert r.status_code == 200
        assert "var keyB64 = '" in r.text
        assert "function _sha256" in r.text
        assert "async function _encryptPayload" in r.text
        assert "async function _decryptCmds" in r.text

    def test_pending_returns_encrypted(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        with srv._lock:
            srv._pending.append({"id": 500, "code": "1+1"})
        path = srv.debugger_path.rstrip("/") + "/pending"
        r = httpx.get(f"{moss_url}{path}?name=test&last_id=0", timeout=5.0)
        assert r.status_code == 200
        data = r.json()
        assert "encrypted" in data
        assert isinstance(data["encrypted"], str)
        assert data["encrypted"].count(".") == 2

    def test_pending_encrypted_decrypts_correctly(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        with srv._lock:
            srv._pending.append({"id": 600, "code": "location.href"})
        path = srv.debugger_path.rstrip("/") + "/pending"
        r = httpx.get(f"{moss_url}{path}?name=test&last_id=0", timeout=5.0)
        key = _derive_key(_TEST_KEY)
        cmds = _xor_decrypt(key, r.json()["encrypted"])
        assert any(c["id"] == 600 and c["code"] == "location.href" for c in cmds)

    def test_post_encrypted_result(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/result"
        key = _derive_key(_TEST_KEY)
        payload = {"id": 700, "name": "test", "result": "decrypted-ok"}
        encrypted = _xor_encrypt(key, payload)
        r = httpx.post(f"{moss_url}{path}", json={"encrypted": encrypted}, timeout=5.0)
        assert r.status_code == 200
        assert r.json() == {"ok": True}

    def test_post_encrypted_result_tampered(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/result"
        r = httpx.post(f"{moss_url}{path}", json={"encrypted": "AAAA.AAAA.AAAA"}, timeout=5.0)
        assert r.status_code == 400

    def test_post_encrypted_result_missing_field(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/result"
        r = httpx.post(f"{moss_url}{path}", json={"id": 1, "name": "x"}, timeout=5.0)
        assert r.status_code == 400

    def test_get_pending_unknown_name_still_works(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/pending"
        r = httpx.get(f"{moss_url}{path}?name=&last_id=0", timeout=5.0)
        assert r.status_code == 200

    def test_get_pending_missing_qs_still_ok(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/pending"
        r = httpx.get(f"{moss_url}{path}", timeout=5.0)
        assert r.status_code == 200
        assert "encrypted" in r.json()


# ──────────────────────────────────────────────────────────
#   No encryption backwards compat
# ──────────────────────────────────────────────────────────

@pytest.mark.moss_args("-e", "debugger", "--debugger-no-input", "--debugger-id-length", "0")
class TestNoEncryption:
    def test_js_no_crypto_functions(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path
        r = httpx.get(f"{moss_url}{path}", timeout=5.0)
        assert r.status_code == 200
        assert "var keyB64 = ''" in r.text
        assert "async function _encryptPayload" not in r.text
        assert "function _sha256" not in r.text

    def test_pending_returns_plain(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        with srv._lock:
            srv._pending.append({"id": 800, "code": "alert(1)"})
        path = srv.debugger_path.rstrip("/") + "/pending"
        r = httpx.get(f"{moss_url}{path}?name=test&last_id=0", timeout=5.0)
        assert r.status_code == 200
        assert isinstance(r.json(), list)
        assert any(c["id"] == 800 for c in r.json())


# ──────────────────────────────────────────────────────────
#   State isolation between test classes
# ──────────────────────────────────────────────────────────

@pytest.mark.moss_args("-e", "debugger", "--debugger-no-input", "--debugger-id-length", "0")
class TestStateIsolation:
    def test_pending_is_empty_for_new_server(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        path = srv.debugger_path.rstrip("/") + "/pending"
        r = httpx.get(f"{moss_url}{path}?name=test&last_id=0", timeout=5.0)
        assert r.json() == []


# ──────────────────────────────────────────────────────────
#   Script command loading
# ──────────────────────────────────────────────────────────

@pytest.mark.moss_args("-e", "debugger", "--debugger-no-input", "--debugger-id-length", "0")
class TestScriptCommands:
    def _write_script(self, tmp_path, data, name="test_script.json"):
        path = tmp_path / name
        path.write_text(json.dumps(data))
        return str(path)

    def test_load_valid_json(self, moss_url, moss_runner, tmp_path):
        srv = moss_runner.servers[0]
        srv._script_commands.clear()
        path = self._write_script(tmp_path, {
            "name": "demo",
            "commands": {
                "ping": {"code": "'pong'", "description": "returns pong"}
            }
        })
        count = srv._load_script_file(path)
        assert count == 1
        assert "demo.ping" in srv._script_commands
        assert srv._script_commands["demo.ping"]["code"] == "'pong'"
        assert srv._script_commands["demo.ping"]["description"] == "returns pong"
        assert srv._script_commands["demo.ping"]["args"] == 0

    def test_load_name_defaults_to_stem(self, moss_url, moss_runner, tmp_path):
        srv = moss_runner.servers[0]
        srv._script_commands.clear()
        path = self._write_script(tmp_path, {
            "commands": {
                "cmd1": {"code": "1+1"}
            }
        }, name="my_script.json")
        count = srv._load_script_file(path)
        assert count == 1
        assert "my_script.cmd1" in srv._script_commands

    def test_load_custom_name(self, moss_url, moss_runner, tmp_path):
        srv = moss_runner.servers[0]
        srv._script_commands.clear()
        path = self._write_script(tmp_path, {
            "name": "custom",
            "commands": {
                "cmd1": {"code": "1+1"}
            }
        })
        count = srv._load_script_file(path)
        assert count == 1
        assert "custom.cmd1" in srv._script_commands

    def test_load_args_defaults(self, moss_url, moss_runner, tmp_path):
        srv = moss_runner.servers[0]
        srv._script_commands.clear()
        path = self._write_script(tmp_path, {
            "name": "a",
            "commands": {
                "zero": {"code": "1"},
                "two": {"code": "f('{0}', '{1}')", "args": 2}
            }
        })
        count = srv._load_script_file(path)
        assert count == 2
        assert srv._script_commands["a.zero"]["args"] == 0
        assert srv._script_commands["a.two"]["args"] == 2

    def test_load_file_not_found(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        assert srv._load_script_file("nonexistent.json") == 0

    def test_load_invalid_json(self, moss_url, moss_runner, tmp_path):
        srv = moss_runner.servers[0]
        path = tmp_path / "bad.json"
        path.write_text("{invalid json}")
        assert srv._load_script_file(str(path)) == 0

    def test_load_schema_violation(self, moss_url, moss_runner, tmp_path):
        srv = moss_runner.servers[0]
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({
            "commands": "not an object"
        }))
        assert srv._load_script_file(str(path)) == 0

    def test_load_missing_code(self, moss_url, moss_runner, tmp_path):
        srv = moss_runner.servers[0]
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({
            "name": "x",
            "commands": {
                "bad": {"description": "no code"}
            }
        }))
        assert srv._load_script_file(str(path)) == 0

    def test_load_duplicate_skipped(self, moss_url, moss_runner, tmp_path):
        srv = moss_runner.servers[0]
        path = self._write_script(tmp_path, {
            "name": "x",
            "commands": {"ping": {"code": "'pong'"}}
        })
        srv._load_script_file(path)
        assert srv._load_script_file(path) == 0

    def test_load_multiple_commands(self, moss_url, moss_runner, tmp_path):
        srv = moss_runner.servers[0]
        srv._script_commands.clear()
        path = self._write_script(tmp_path, {
            "name": "multi",
            "commands": {
                "a": {"code": "1"},
                "b": {"code": "2", "description": "second"},
                "c": {"code": "3", "args": 1}
            }
        })
        count = srv._load_script_file(path)
        assert count == 3
        keys = [k for k in srv._script_commands if k.startswith("multi.")]
        assert len(keys) == 3

    def test_resolve_absolute_path(self, moss_url, moss_runner, tmp_path):
        srv = moss_runner.servers[0]
        script_path = tmp_path / "abs.json"
        script_path.write_text(json.dumps({"commands": {"c": {"code": "1"}}}))
        resolved = srv._resolve_script_path(str(script_path))
        assert resolved == str(script_path)

    def test_resolve_not_found(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        assert srv._resolve_script_path("does_not_exist_12345.json") is None

    def test_resolve_debugger_dir(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        resolved = srv._resolve_script_path("recon.json")
        assert resolved is not None
        assert resolved.endswith("recon.json")

    def test_resolve_cwd_fallback(self, moss_url, moss_runner):
        srv = moss_runner.servers[0]
        fname = "_moss_test_cwd_script.json"
        fpath = os.path.join(os.getcwd(), fname)
        try:
            with open(fpath, "w") as f:
                json.dump({"commands": {"c": {"code": "1"}}}, f)
            resolved = srv._resolve_script_path(fname)
            assert resolved == fpath
        finally:
            if os.path.isfile(fpath):
                os.remove(fpath)

    def test_script_command_queuing(self, moss_url, moss_runner, tmp_path):
        srv = moss_runner.servers[0]
        srv._script_commands.clear()
        path = self._write_script(tmp_path, {
            "name": "demo",
            "commands": {
                "ping": {"code": "'pong'"}
            }
        })
        srv._load_script_file(path)

        cmd_def = srv._script_commands["demo.ping"]
        cmd_id = srv._next_id
        srv._next_id += 1
        with srv._lock:
            srv._pending.append({"id": cmd_id, "code": cmd_def["code"]})
            srv._cmd_history[cmd_id] = "demo.ping"

        pending_path = srv.debugger_path.rstrip("/") + "/pending"
        r = httpx.get(f"{moss_url}{pending_path}?name=test&last_id=0", timeout=5.0)
        assert r.status_code == 200
        assert any(c["id"] == cmd_id and c["code"] == "'pong'" for c in r.json())
        assert srv._cmd_history[cmd_id] == "demo.ping"

    def test_script_command_arg_substitution(self, moss_url, moss_runner, tmp_path):
        srv = moss_runner.servers[0]
        srv._script_commands.clear()
        path = self._write_script(tmp_path, {
            "name": "demo",
            "commands": {
                "fetch": {"code": "fetch('{0}').then(r=>r.text())", "args": 1}
            }
        })
        srv._load_script_file(path)

        cmd_def = srv._script_commands["demo.fetch"]
        code = cmd_def["code"].replace("{0}", "http://example.com")
        expected_code = "fetch('http://example.com').then(r=>r.text())"
        assert code == expected_code

        cmd_id = srv._next_id
        srv._next_id += 1
        with srv._lock:
            srv._pending.append({"id": cmd_id, "code": code})
            srv._cmd_history[cmd_id] = "demo.fetch http://example.com"

        pending_path = srv.debugger_path.rstrip("/") + "/pending"
        r = httpx.get(f"{moss_url}{pending_path}?name=test&last_id=0", timeout=5.0)
        assert r.status_code == 200
        assert any(c["id"] == cmd_id and c["code"] == expected_code for c in r.json())
        assert srv._cmd_history[cmd_id] == "demo.fetch http://example.com"
