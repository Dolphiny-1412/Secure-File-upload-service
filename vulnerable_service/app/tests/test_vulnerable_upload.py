import os
import time
import requests

BASE = os.environ.get("VULN_BASE_URL", "http://localhost:8001")

def wait_ready():
    for _ in range(60):
        try:
            r = requests.get(f"{BASE}/")
            if r.status_code < 500:
                return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError("vulnerable service not ready")

def test_vulnerable_accepts_malicious(tmp_path):
    wait_ready()
    # Create a "jpg" file with PHP content
    malicious_name = "php_shell_disguised.jpg"
    malicious_file = tmp_path / malicious_name
    malicious_file.write_text("<?php echo 'pwned'; ?>")

    files = {"file": (malicious_name, malicious_file.read_bytes(), "image/jpeg")}
    data = {"uploader_id": "tester"}
    resp = requests.post(f"{BASE}/upload", files=files, data=data)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    # Attempt to retrieve it directly from static serving
    url = f"{BASE}/uploads/{malicious_name}"
    get_resp = requests.get(url)
    assert get_resp.status_code == 200
    # Content should be what we uploaded (since it's static serving)
    assert "pwned" in get_resp.text


