import pytest
import base64
import json
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_pastebin_payload(data: bytes, password: str) -> str:
    """
    Replicate the JS encryption logic from pastebin.html in Python.
    Uses AES-GCM with PBKDF2 key derivation (matching the JS Web Crypto API).
    """
    salt = os.urandom(16)
    iv = os.urandom(12)

    # Derive key using PBKDF2 (400000 iterations, SHA-256)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=400000,
    )
    key = kdf.derive(password.encode('utf-8'))

    # Encrypt using AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, data, None)

    # Prepare payload as JSON (matching JS structure)
    payload = {
        "iv": base64.b64encode(iv).decode('utf-8'),
        "salt": base64.b64encode(salt).decode('utf-8'),
        "data": base64.b64encode(ciphertext).decode('utf-8'),
    }
    return json.dumps(payload)


def decrypt_pastebin_payload(json_str: str, password: str) -> bytes:
    """
    Replicate the JS decryption logic from decrypt.html in Python.
    Uses AES-GCM with PBKDF2 key derivation to decrypt the payload.
    """
    payload = json.loads(json_str)
    iv = base64.b64decode(payload["iv"])
    salt = base64.b64decode(payload["salt"])
    ciphertext = base64.b64decode(payload["data"])

    # Derive key using PBKDF2 (same parameters as encryption)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=400000,
    )
    key = kdf.derive(password.encode('utf-8'))

    # Decrypt using AES-GCM
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)

    return plaintext


@pytest.mark.moss_args("-e", "pastebin")
class TestPastebin:
    def test_get_form(cls, http_client):
        r = http_client.get("/pastebin")
        assert r.status_code == 200
        assert r.headers.get("content-type", "").startswith("text/html")

    def test_post_and_decrypt_precise(cls, http_client):
        """Test server-side logic: encrypt → POST → retrieve → decrypt → verify exact match."""
        password = "test-password-123"
        original_data = b"hello world from pastebin - exact content verification!"

        # Generate encrypted payload
        payload = generate_pastebin_payload(original_data, password)

        # POST to pastebin
        r = http_client.post(
            "/pastebin",
            content=payload,
            headers={"Content-Type": "application/json"}
        )
        assert r.status_code == 201
        json_data = r.json()
        assert json_data["message"] == "Success!"

        # Retrieve the paste page
        paste_url = json_data["url"]
        r2 = http_client.get(paste_url)
        assert r2.status_code == 200

        # Extract the encrypted data from the HTML (it's in a <script> tag as JSON)
        import re
        match = re.search(r'<script id="encrypted-data" type="application/json">(.*?)</script>', r2.text, re.DOTALL)
        assert match is not None, "Could not find encrypted data in response"
        encrypted_json = match.group(1).strip()

        # Decrypt and verify exact content match
        decrypted_data = decrypt_pastebin_payload(encrypted_json, password)
        assert decrypted_data == original_data, f"Decrypted data does not match original.\nOriginal: {original_data}\nDecrypted: {decrypted_data}"

    def test_post_paste(cls, http_client):
        """Test server-side logic by sending properly encrypted payload."""
        password = "test-password-123"
        original_data = b"hello world from pastebin"
        payload = generate_pastebin_payload(original_data, password)
        r = http_client.post(
            "/pastebin",
            content=payload,
            headers={"Content-Type": "application/json"}
        )
        assert r.status_code == 201
        json_data = r.json()
        assert "url" in json_data
        assert json_data["message"] == "Success!"
        # Verify the paste is retrievable
        paste_url = json_data["url"]
        r2 = http_client.get(paste_url)
        assert r2.status_code == 200
        # The retrieved page should contain the encrypted data
        assert b"encrypted" in r2.content.lower() or b"decrypt" in r2.content.lower()

    def test_nonexistent_paste(cls, http_client):
        r = http_client.get("/pastebin/nonexistent123")
        assert r.status_code == 404

    def test_invalid_json(cls, http_client):
        r = http_client.post(
            "/pastebin",
            content=b"not json",
            headers={"Content-Type": "application/json"}
        )
        assert r.status_code == 403
        json_data = r.json()
        assert "message" in json_data


@pytest.mark.moss_args("-e", "pastebin", "--pastebin-max-size", "100")
class TestPastebinMaxSize:
    def test_exceed_max_size(cls, http_client):
        """Test that payloads exceeding max size are rejected."""
        password = "test-password-123"
        large_data = b"a" * 80  # Will exceed 100 bytes after encryption overhead
        payload = generate_pastebin_payload(large_data, password)
        r = http_client.post(
            "/pastebin",
            content=payload,
            headers={"Content-Type": "application/json"}
        )
        assert r.status_code == 413
        json_data = r.json()
        assert "message" in json_data


@pytest.mark.moss_args("-e", "pastebin", "--pastebin-fixed", "test-paste-fixed")
class TestPastebinFixedPath:
    def test_fixed_path(cls, http_client):
        """Test that --pastebin-fixed uses a fixed path."""
        password = "test-password-123"
        original_data = b"fixed path test"
        payload = generate_pastebin_payload(original_data, password)
        r = http_client.post(
            "/pastebin",
            content=payload,
            headers={"Content-Type": "application/json"}
        )
        assert r.status_code == 201
        json_data = r.json()
        assert json_data["url"].endswith("/test-paste-fixed")


# @pytest.mark.moss_https
# @pytest.mark.moss_args("-e", "pastebin", "-vv")
# @pytest.mark.override_moss_port(8000)
# class TestPastebinHeadlessBrowser:
#     """Use playwright headless browser to emulate user submitting data via the web interface.
#     Uses HTTPS (SSL works - the server handles it properly on the second connection).
#     Tests real user interaction: typing in textarea, clicking buttons."""

#     def test_submit_via_browser(self, moss_runner, moss_url):
#         """Test end-to-end pastebin submission using headless browser with real interaction."""
#         try:
#             from playwright.sync_api import sync_playwright
#         except ImportError:
#             pytest.skip("playwright not installed")

#         import time

#         password = "e2e-test-password"
#         test_message = "Hello from headless browser test!"

#         with sync_playwright() as p:
#             browser = p.chromium.launch(headless=False)
#             context = browser.new_context(ignore_https_errors=True)

#             page = context.new_page()

#             # Navigate to pastebin page using HTTPS
#             page.goto(f"{moss_url}/pastebin", timeout=15000)

#             # Wait for page to load
#             page.wait_for_load_state("networkidle")

#             # Enter the test message - REAL USER INTERACTION
#             page.fill("textarea#message", test_message)

#             # Set up dialog handler for password prompt BEFORE clicking
#             page.on("dialog", lambda dialog: dialog.accept(password))

#             # Click the Encrypt & Send button - REAL USER INTERACTION
#             page.click("button:has-text('Encrypt & Send')")

#             # Wait for the link to appear (success)
#             page.wait_for_selector("a#link[href]", timeout=10000)

#             # Get the paste URL
#             paste_url = page.get_attribute("a#link", "href")
#             assert paste_url is not None, "No paste URL generated"
#             assert paste_url.startswith("/pastebin/"), f"Unexpected URL: {paste_url}"

#             # Navigate to the paste URL
#             page.goto(f"{moss_url}{paste_url}", timeout=15000)

#             # Wait for page to load
#             page.wait_for_load_state("networkidle")

#             # Click "Re-Enter Password" button to trigger decryption - REAL USER INTERACTION
#             page.on("dialog", lambda dialog: dialog.accept(password))
#             page.click("button:has-text('Re-Enter Password')")

#             # Wait for decryption to complete
#             page.wait_for_selector("textarea#result:not([disabled])", timeout=10000)

#             # Get the decrypted text
#             result = page.get_attribute("textarea#result", "value") or page.evaluate("() => document.getElementById('result').value")
#             assert result is not None, "No decrypted result found"

#             # Verify the content matches
#             assert result == test_message, f"Decrypted content mismatch.\nExpected: {test_message}\nGot: {result}"

#             browser.close()
