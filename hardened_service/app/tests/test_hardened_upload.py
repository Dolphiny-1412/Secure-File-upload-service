import base64
import hmac
import hashlib
import json
import os
import time
import requests
import pytest

BASE = os.environ.get("HARD_BASE_URL", "http://localhost:8000")
SECRET = os.environ.get("SECRET_KEY", "change-me")


def wait_ready():
    for _ in range(120):
        try:
            r = requests.get(f"{BASE}/")
            if r.status_code < 500:
                return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError("hardened service not ready")


def sign_token(file_id: str, exp_seconds: int = 300) -> str:
    payload = {"file_id": file_id, "exp": int(time.time()) + exp_seconds}
    msg = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(SECRET.encode(), msg, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(msg + b"." + sig).decode().rstrip("=")
    return token


@pytest.fixture(scope="module")
def samples(tmp_path_factory):
    d = tmp_path_factory.mktemp("samples")
    (d / "sample.jpg").write_bytes(b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xFF\xD9")
    (d / "sample.pdf").write_text("%PDF-1.4\n%EOF\n")
    (d / "php_shell_disguised.jpg").write_text("<?php echo 'pwned'; ?>")
    return d


def test_benign_uploads(samples):
    wait_ready()
    # JPEG
    files = {"file": ("sample.jpg", (samples / "sample.jpg").read_bytes(), "image/jpeg")}
    r = requests.post(f"{BASE}/upload", files=files)
    assert r.status_code == 200, r.text
    jpg_id = r.json()["id"]

    # PDF
    files = {"file": ("sample.pdf", (samples / "sample.pdf").read_bytes(), "application/pdf")}
    r = requests.post(f"{BASE}/upload", files=files)
    assert r.status_code == 200, r.text
    pdf_id = r.json()["id"]

    # Download jpg using token
    token = sign_token(jpg_id, 120)
    dr = requests.get(f"{BASE}/download/{jpg_id}", params={"token": token})
    assert dr.status_code == 200
    assert "nosniff" in dr.headers.get("X-Content-Type-Options", "").lower()


def test_malicious_rejected_or_quarantined(samples):
    wait_ready()
    files = {"file": ("php_shell_disguised.jpg", (samples / "php_shell_disguised.jpg").read_bytes(), "image/jpeg")}
    r = requests.post(f"{BASE}/upload", files=files)
    # Depending on ClamAV signature timing (first run), the file may be rejected by content sniffing (415)
    # or quarantined as infected (451) if signatures flag PHP as dangerous content type.
    assert r.status_code in (415, 451), r.text


