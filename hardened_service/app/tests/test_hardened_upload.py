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


import base64
import hmac
import hashlib
import io
import json
import os
import time
import requests
import pytest
from PIL import Image

BASE = os.environ.get("HARD_BASE_URL", "http://localhost:8000")
SECRET = os.environ.get("SECRET_KEY", "change-me")

_MINIMAL_PDF = """%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>
endobj
xref
0 4
0000000000 65535 f 
0000000010 00000 n 
0000000061 00000 n 
0000000120 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
180
%%EOF
"""


def _make_sample_jpeg() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (1, 1), color=(255, 0, 0)).save(buf, format="JPEG")
    return buf.getvalue()


@pytest.fixture(scope="module")
def samples(tmp_path_factory):
    d = tmp_path_factory.mktemp("samples")
    (d / "sample.jpg").write_bytes(_make_sample_jpeg())
    (d / "sample.pdf").write_text(_MINIMAL_PDF)
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


