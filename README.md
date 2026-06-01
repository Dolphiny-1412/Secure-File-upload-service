# Secure File Upload Service — Educational Demo

A side-by-side comparison of **insecure vs secure** HTTP file upload 
patterns, built for a cybersecurity course at MAHE–ISAC, Manipal.

Two FastAPI microservices run simultaneously — one intentionally 
vulnerable, one hardened — so you can observe real attack vectors 
and their mitigations in action.

⚠️ NOT production-ready. The vulnerable service is insecure by design.

# Secure File Upload Service (Hardened vs Vulnerable)

Two FastAPI-based HTTP services demonstrate insecure and secure file upload patterns side-by-side:
- vulnerable-service: intentionally insecure; accepts any file, stores under webroot, serves directly.
- hardened-service: fully mitigated; validates content and type, scans with ClamAV (optional), limits size, uses safe storage, signed downloads, rate limiting, and secure headers.

Both run natively with Python or via Docker Compose. A test harness and CI verify behavior.

## Quickstart (Native)

Prereqs: Python 3.10+, Git. Optional: ClamAV for virus scanning.

1) Clone and configure:
```bash
git clone https://github.com/your-org/secure-file-upload-demo.git
cd secure-file-upload-demo
cp .env.example .env
# Generate a strong secret:
python -c "import secrets; print(secrets.token_urlsafe(32))"
# Put the printed value into SECRET_KEY in .env
```

2) Install dependencies and run:
```bash
pip install -r requirements.txt
python start_services.py
```

On Linux, install `libmagic1` if `python-magic` fails (e.g. `sudo apt install libmagic1`).

3) Wait for readiness. Then try endpoints.

### Vulnerable service (localhost:8001)
- Upload:
```bash
curl -F "file=@scripts/demo_attack_files/malicious_samples/php_shell_disguised.jpg" -F "uploader_id=tester" http://localhost:8001/upload
```
- Direct download (static):
```bash
curl -v http://localhost:8001/uploads/php_shell_disguised.jpg
```

### Hardened service (localhost:8000)
- Upload a benign file:
```bash
curl -F "file=@scripts/demo_attack_files/malicious_samples/sample.jpg" -F "uploader_id=tester" http://localhost:8000/upload
# => {"status":"ok","id":"<file-id>","message":"uploaded"}
```

- Generate a signed download token (locally, not via API):
```bash
# Replace <file-id> with response id and SECRET_KEY with your .env value
python - <<'PY'
import base64, hmac, json, os, time, hashlib
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me")
file_id = "<file-id>"
expiry = int(time.time()) + 300
msg = json.dumps({"file_id":file_id,"exp":expiry}, separators=(',',':')).encode()
sig = hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).digest()
token = base64.urlsafe_b64encode(msg + b"." + sig).decode().rstrip("=")
print(token)
PY
```

- Download with token:
```bash
curl -OJ "http://localhost:8000/download/<file-id>?token=<token>"
```

- Upload a malicious file (should quarantine or reject):
```bash
curl -F "file=@scripts/demo_attack_files/malicious_samples/php_shell_disguised.jpg" http://localhost:8000/upload -v
# => 415 unsupported media type, 451 quarantined (if ClamAV flags it), or 503 if AV is configured but down
```

## Docker

Prereqs: Docker and Docker Compose v2.

1) Configure environment:
```bash
cp .env.example .env
# Set SECRET_KEY in .env
```

2) Start all services (without ClamAV — virus scanning disabled):
```bash
docker compose up --build
```

3) Start with optional ClamAV scanning:
```bash
# In .env, set: CLAMAV_HOST=clamav
docker compose --profile with-clamav up --build
```

Services:
- Vulnerable: http://localhost:8001
- Hardened: http://localhost:8000
- Streamlit UI: http://localhost:8501
- ClamAV (with profile): port 3310

Hardened service data (`data/storage`, `data/quarantine`, `data/meta.db`) persists in the `hardened_data` Docker volume.

## Windows note

Native bash demo scripts (`scripts/run_demo.sh`, `generate_malicious_files.sh`) require a Unix shell. On Windows, use **WSL2** to run them, or use `python setup.py` / `python start_services.py` with PowerShell for native Python workflows. Docker Desktop with WSL2 backend is recommended for the Docker path.

## Tests and Demo

- Generate sample and malicious files:
```bash
bash scripts/demo_attack_files/generate_malicious_files.sh
```

- Run demo (builds, waits, runs tests, summarizes, tears down):
```bash
bash scripts/run_demo.sh
```

- Or run tests locally while services are up:
```bash
python start_services.py &
pytest -q
```

CI runs on push/PR: validates `docker-compose.yml`, starts the services, runs tests, and performs basic curl-based security checks.

## Services Overview

- vulnerable-service
  - POST /upload: stores file under `webroot/uploads/<original-filename>`.
  - Static files served at `/`, so `/uploads/<original-filename>` is publicly accessible.
  - No size limits, no content checks, no AV scan, no tokens.

- hardened-service
  - POST /upload: enforces size limit (default 5 MB), content sniffing (python-magic), validates images with Pillow, validates PDFs with PyPDF2, extension whitelist (configurable via `ALLOWED_EXTENSIONS`), virus scanning via clamd (pyclamd) when enabled, safe randomized storage outside webroot, logs decisions, metadata stored in SQLite.
  - GET /download/{id}?token=...: requires signed token (HMAC-SHA256) with file_id and expiry; sets secure headers; returns as attachment with verified content-type.
  - Rate limiting: simple per-IP limiter with in-memory counters.

## Configuration

`.env` drives the hardened service and Streamlit UI (also used by docker-compose):

- SECRET_KEY: HMAC secret for tokens. Generate with
  `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
- MAX_UPLOAD_SIZE: bytes, default 5242880 (5 MB).
- ALLOWED_EXTENSIONS: comma-separated list, default `png,jpg,jpeg,pdf`.
- CLAMAV_HOST (or CLAMD_HOST): ClamAV host. **Leave empty to disable virus scanning.** When set (e.g. `clamav` or `localhost`), clamd must be reachable or uploads are rejected with HTTP 503.
- CLAMAV_PORT (or CLAMD_PORT): default `3310`.
- TOKEN_EXP_SECONDS: default 300.
- RATE_LIMIT_REQUESTS: default 20 per window.
- RATE_LIMIT_WINDOW_SECONDS: default 60.

DB: SQLite via Python's `sqlite3`. Metadata path: `data/meta.db` in project root. Storage: `data/storage/`; Quarantine: `data/quarantine/`.

## ClamAV fail-safe behavior

- **CLAMAV_HOST empty:** virus scanning is skipped; uploads proceed after content validation only.
- **CLAMAV_HOST set and clamd reachable:** files are scanned; infected files are quarantined (HTTP 451).
- **CLAMAV_HOST set but clamd unreachable:** upload is **rejected** with HTTP 503 and `{"status":"error","reason":"Antivirus service unavailable"}`.

This fail-closed policy ensures scanning is never silently skipped when AV is expected to be running.

## Threat Model & Limitations

- Focus: basic upload risks: arbitrary file upload, content-type spoofing, serving user-supplied files, malware handling.
- Not covered: user auth, multi-tenant isolation, encrypted at rest, DLP, advanced malware (sandboxing), distributed rate limits, large file chunking.
- Tokens: HMAC-based tokens without audience binding; use TLS in production.

## Remediation Summary

Compare `vulnerable_service/app/main.py` with `hardened_service/app/main.py` and supporting modules. See `docs/remediation_patch.diff` for a concise diff showing key mitigations.

## License

MIT. See `LICENSE`.
