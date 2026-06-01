import os
import time
import requests
from pathlib import Path

VULN = os.environ.get("VULN_BASE_URL", "http://localhost:8001")
HARD = os.environ.get("HARD_BASE_URL", "http://localhost:8000")

REPORT = Path("report.txt")


def wait(url: str, tries: int = 120):
    for _ in range(tries):
        try:
            r = requests.get(url, timeout=3)
            if r.status_code < 500:
                return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError(f"Service not ready: {url}")


def main():
    wait(f"{VULN}/")
    wait(f"{HARD}/")

    # Prepare files
    base_dir = Path("scripts/demo_attack_files/malicious_samples")
    if not base_dir.exists():
        base_dir = Path("scripts/demo_attack_files")
        os.system("bash scripts/demo_attack_files/generate_malicious_files.sh")
        base_dir = Path("scripts/demo_attack_files/malicious_samples")

    php_shell = base_dir / "php_shell_disguised.jpg"
    sample_jpg = base_dir / "sample.jpg"

    # Attack against vulnerable
    v_files = {"file": (php_shell.name, php_shell.read_bytes(), "image/jpeg")}
    v_resp = requests.post(f"{VULN}/upload", files=v_files, data={"uploader_id": "harness"})
    v_ok = v_resp.status_code == 200
    v_get = requests.get(f"{VULN}/uploads/{php_shell.name}")
    v_accessible = v_get.status_code == 200

    # Same attack against hardened
    h_files = {"file": (php_shell.name, php_shell.read_bytes(), "image/jpeg")}
    h_resp = requests.post(f"{HARD}/upload", files=h_files, data={"uploader_id": "harness"})
    h_code = h_resp.status_code
    hardened_blocked = h_code in (415, 451, 503)

    # Benign upload hardened
    b_files = {"file": (sample_jpg.name, sample_jpg.read_bytes(), "image/jpeg")}
    b_resp = requests.post(f"{HARD}/upload", files=b_files, data={"uploader_id": "harness"})
    b_ok = b_resp.status_code == 200

    report = f"""
Vulnerable service:
  Upload malicious: {'OK' if v_ok else 'FAIL'} (status {v_resp.status_code})
  Direct access to uploaded file: {'OK' if v_accessible else 'BLOCKED'} (status {v_get.status_code})

Hardened service:
  Upload malicious blocked: {'YES' if hardened_blocked else 'NO'} (status {h_code})
  Upload benign file: {'OK' if b_ok else 'FAIL'} (status {b_resp.status_code})
""".strip()

    REPORT.write_text(report)
    print(report)


if __name__ == "__main__":
    main()


