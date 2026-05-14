import pytest
import base64
import json
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time
import socket


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
    """Basic pastebin functionality tests that don't require frontend encryption."""
    
    def test_get_form(self, http_client):
        r = http_client.get("/pastebin")
        assert r.status_code == 200
        assert r.headers.get("content-type", "").startswith("text/html")
    
    def test_nonexistent_paste(self, http_client):
        r = http_client.get("/pastebin/nonexistent123")
        assert r.status_code == 404
    
    def test_empty_id(self, http_client):
        r = http_client.get("/pastebin/")
        assert r.status_code == 200
    
    def test_invalid_json(self, http_client):
        r = http_client.post("/pastebin", content=b"not json", headers={"Content-Type": "application/json"})
        assert r.status_code == 400
        assert "message" in r.json()
    
    def test_server_side_decrypt(self, http_client):
        """Test server-side decryption of GCM payloads (Python crypto)."""
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

    @pytest.mark.slow
    def test_http_flow(self, moss_runner, moss_url, browser_http):
        """Test complete encrypt/decrypt cycle via headless browser over HTTP."""
        password = "http-flow-password"
        test_message = "Hello from HTTP browser test!"
        
        page = browser_http.new_page()
        
        page.goto(f"{moss_url}/pastebin", timeout=15000)
        page.wait_for_load_state("networkidle")
        page.fill("textarea#message", test_message)
        page.on("dialog", lambda dialog: dialog.accept(password))
        page.click("button:has-text('Encrypt & Send')")
        page.wait_for_selector("a#link[href]", timeout=15000)
        
        paste_url = page.get_attribute("a#link", "href")
        assert paste_url and paste_url.startswith("/pastebin/")
        
        page.goto(f"{moss_url}{paste_url}", timeout=15000)
        page.wait_for_load_state("networkidle")
        
        result = page.get_attribute("textarea#result", "textContent") or \
            page.evaluate("() => document.getElementById('result').textContent")
        assert result == test_message, f"Decrypted mismatch.\nExpected: {test_message}\nGot: {result}"
        
        page.close()

    @pytest.mark.slow
    def test_https_warning_hidden_when_no_https(self, moss_runner, moss_url, browser_http):
        """Test HTTPS warning in pastebin form using headless browser.
        When server does not support HTTPS, warning should be hidden."""
        page = browser_http.new_page()
        page.goto(f"{moss_url}/pastebin", timeout=15000)
        page.wait_for_load_state("networkidle")
        
        display_style = page.evaluate("() => window.getComputedStyle(document.getElementById('https-warning')).display")
        assert display_style == "none", f"Expected warning to be hidden, but display is: {display_style}"
        
        page.close()



def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to an external address; no data is actually sent
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        raise Exception("unable to get local IP")
        # ip = "127.0.0.1" # Fallback to localhost
    finally:
        s.close()
    return ip


@pytest.mark.slow
@pytest.mark.moss_https
@pytest.mark.moss_args("-e", "pastebin")
class TestPastebinHTTPSFlow:
    """Test encrypt/decrypt cycle via headless browser over HTTPS."""

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

    def test_https_flow(self, moss_runner, moss_url, browser_https, test_message):
        password = "e2e-test-password"
        page = browser_https.new_page()
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
        page.close()

    def test_https_warning_not_shown_for_localhost_when_https_supported(self, moss_url, browser_https):
        """Test HTTPS warning when server supports HTTPS but is accessed with HTTP on localhost."""
        page = browser_https.new_page()
        page.goto(f"{moss_url}/pastebin", timeout=15000)
        page.wait_for_load_state("networkidle")
        
        display_style = page.evaluate("() => window.getComputedStyle(document.getElementById('https-warning')).display")
        assert display_style == "none", f"Expected warning to be hidden, but display is: {display_style}"
        
        page.close()

    def test_https_warning_shown_when_https_supported(self, moss_port, browser_https):
        """Test HTTPS warning when server supports HTTPS but is accessed with HTTP."""
        page = browser_https.new_page()
        ip = get_local_ip() # Use a local IP because 127.0.0.1/localhost are treated as secure contexts and therefore have subtle crypto.
        page.goto(f"http://{ip}:{moss_port}/pastebin", timeout=15000)
        page.wait_for_load_state("networkidle")

        display_style = page.evaluate("() => window.getComputedStyle(document.getElementById('https-warning')).display")
        assert display_style == "block", f"Expected warning to be visible, but display is: {display_style}"
        
        https_link = page.locator("#https-link")
        href = https_link.get_attribute("href")
        assert href and href.startswith("https://"), f"Expected HTTPS link, got: {href}"
        
        page.close()

    def test_http_access_redirects_to_https(self, moss_runner, moss_port, browser_https):
        """Test redirect when accessing encrypted paste (originally submitted with HTTPS) over HTTP when HTTPS is available."""
        password = "redirect-test-password"
        
        page = browser_https.new_page()
        
        https_url = f"https://127.0.0.1:{moss_port}"
        page.goto(f"{https_url}/pastebin", timeout=15000)
        page.wait_for_load_state("networkidle")
        
        page.fill("textarea#message", "Redirect test message")
        page.on("dialog", lambda dialog: dialog.accept(password))
        page.click("button:has-text('Encrypt & Send')")
        page.wait_for_selector("a#link[href]", timeout=10000)
        
        paste_path = page.get_attribute("a#link", "href")
        assert paste_path and paste_path.startswith("/pastebin/")
        
        http_url = f"http://127.0.0.1:{moss_port}{paste_path}"
        
        page.goto(http_url, timeout=15000)
        
        final_url = page.url
        assert final_url.startswith("https://"), \
            f"Expected redirect to HTTPS, but got: {final_url}"
        
        page.close()


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


@pytest.mark.moss_args("-e", "pastebin", "--pastebin-password", "hardcoded123")
class TestPastebinHardcodedPassword:
    """Test the --pastebin-password flag."""
    
    @pytest.mark.slow
    def test_hardcoded_password_auto_decrypt(self, moss_runner, moss_url, browser_https):
        """Test that paste with hardcoded password auto-decrypts in browser."""
        test_message = "Auto-decrypt with hardcoded password"
        
        page = browser_https.new_page()
        
        page.goto(f"{moss_url}/pastebin", timeout=15000)
        page.wait_for_load_state("networkidle")
        page.fill("textarea#message", test_message)
        page.on("dialog", lambda dialog: dialog.accept("hardcoded123"))
        page.click("button:has-text('Encrypt & Send')")
        page.wait_for_selector("a#link[href]", timeout=10000)
        
        paste_url = page.get_attribute("a#link", "href")
        
        page.goto(f"{moss_url}{paste_url}", timeout=15000)
        page.wait_for_load_state("networkidle")
        
        result = page.get_attribute("textarea#result", "textContent") or \
            page.evaluate("() => document.getElementById('result').textContent")
        assert result == test_message, f"Decrypted mismatch.\nExpected: {test_message}\nGot: {result}"
        
        page.close()

