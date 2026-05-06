import pytest
import base64
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_pastebin_payload(data: bytes, password: str) -> str:
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=400000)
    key = kdf.derive(password.encode("utf-8"))
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, data, None)
    return json.dumps({
        "iv": base64.b64encode(iv).decode("utf-8"),
        "salt": base64.b64encode(salt).decode("utf-8"),
        "data": base64.b64encode(ciphertext).decode("utf-8"),
    })


def decrypt_pastebin_payload(json_str: str, password: str) -> bytes:
    payload = json.loads(json_str)
    iv = base64.b64decode(payload["iv"])
    salt = base64.b64decode(payload["salt"])
    ciphertext = base64.b64decode(payload["data"])
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=400000)
    key = kdf.derive(password.encode("utf-8"))
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)


@pytest.mark.moss_args("-e", "pastebin")
class TestPastebin:
    def test_get_form(self, http_client):
        r = http_client.get("/pastebin")
        assert r.status_code == 200
        assert r.headers.get("content-type", "").startswith("text/html")

    def test_post_and_decrypt_precise(self, http_client):
        password = "test-password-123"
        original_data = b"hello world from pastebin - exact content verification!"
        payload = generate_pastebin_payload(original_data, password)
        r = http_client.post("/pastebin", content=payload, headers={"Content-Type": "application/json"})
        assert r.status_code == 201
        json_data = r.json()
        assert json_data["message"] == "Success!"
        r2 = http_client.get(json_data["url"])
        assert r2.status_code == 200
        import re
        match = re.search(r'<script id="encrypted-data" type="application/json">(.*?)</script>', r2.text, re.DOTALL)
        assert match is not None
        decrypted_data = decrypt_pastebin_payload(match.group(1).strip(), password)
        assert decrypted_data == original_data

    def test_post_paste(self, http_client):
        password = "test-password-123"
        original_data = b"hello world from pastebin"
        payload = generate_pastebin_payload(original_data, password)
        r = http_client.post("/pastebin", content=payload, headers={"Content-Type": "application/json"})
        assert r.status_code == 201
        json_data = r.json()
        assert "url" in json_data
        r2 = http_client.get(json_data["url"])
        assert r2.status_code == 200
        assert b"encrypted" in r2.content.lower() or b"decrypt" in r2.content.lower()

    def test_nonexistent_paste(self, http_client):
        r = http_client.get("/pastebin/nonexistent123")
        assert r.status_code == 404

    def test_invalid_json(self, http_client):
        r = http_client.post("/pastebin", content=b"not json", headers={"Content-Type": "application/json"})
        assert r.status_code == 403
        assert "message" in r.json()


@pytest.mark.moss_args("-e", "pastebin", "--pastebin-max-size", "100")
class TestPastebinMaxSize:
    def test_exceed_max_size(self, http_client):
        password = "test-password-123"
        large_data = b"a" * 80
        payload = generate_pastebin_payload(large_data, password)
        r = http_client.post("/pastebin", content=payload, headers={"Content-Type": "application/json"})
        assert r.status_code == 413
        assert "message" in r.json()


@pytest.mark.moss_args("-e", "pastebin", "--pastebin-fixed", "test-paste-fixed")
class TestPastebinFixedPath:
    def test_fixed_path(self, http_client):
        password = "test-password-123"
        original_data = b"fixed path test"
        payload = generate_pastebin_payload(original_data, password)
        r = http_client.post("/pastebin", content=payload, headers={"Content-Type": "application/json"})
        assert r.status_code == 201
        json_data = r.json()
        assert json_data["url"].endswith("/test-paste-fixed")


@pytest.mark.moss_https
@pytest.mark.moss_args("-e", "pastebin")
class TestPastebinHeadlessBrowser:
    """Use playwright headless browser to emulate user submitting data via the web interface."""

    test_messages = [
        "Hello from headless browser test!",
        "Hello 世界! 🌍 " * 10,
        "Symbols: !@#$%^&*()_+-=[]{}|;:'\",.<>?/" * 5,
        "English: Hello, Français: Bonjour, Español: Hola, 日本語: こんにちは, 中文: 你好, العربية: مرحبا, 한국어: 안녕하세요",
        "Line1\nLine2\nLine3\nLine4\nLine5",
        "a" * 500,
    ]

    @pytest.fixture(params=test_messages)
    def test_message(self, request):
        return request.param

    def test_submit_via_browser(self, moss_runner, moss_url, test_message):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            pytest.skip("playwright not installed")
        password = "e2e-test-password"
        import time
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.on("console", lambda msg: print(f"Browser console: {msg.text}"))
            page.goto(f"{moss_url}/pastebin", timeout=15000)
            page.wait_for_load_state("networkidle")
            page.fill("textarea#message", test_message)
            page.on("dialog", lambda dialog: [print('accepting dialog!'), dialog.accept(password)])
            page.click("button:has-text('Encrypt & Send')")
            page.wait_for_selector("a#link[href]", timeout=10000)
            paste_url = page.get_attribute("a#link", "href")
            assert paste_url is not None
            assert paste_url.startswith("/pastebin/")
            page.goto(f"{moss_url}{paste_url}", timeout=15000)
            time.sleep(3)
            result = page.get_attribute("textarea#result", "textContent") or \
                page.evaluate("() => document.getElementById('result').textContent")
            assert result == test_message, f"Decrypted mismatch.\nExpected: {test_message}\nGot: {result}"
            browser.close()
