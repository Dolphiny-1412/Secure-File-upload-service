# Security Policy

## Supported Versions
This repository is a demo for educational purposes. It is not intended for production use. There are no supported versions.

## Reporting a Vulnerability
Please open a private disclosure by emailing `youssof.ahmed.aly@gmail.com` with:
- Description of the issue
- Steps to reproduce
- Potential impact
- Any suggested remediation

Please do not include any secrets or private data.

## Known Limitations and Caveats
- ClamAV can be slow to initialize on first run while downloading definition databases.
- When `CLAMAV_HOST` is set, the hardened service rejects uploads with HTTP 503 if clamd is unreachable (fail-closed). Leave `CLAMAV_HOST` empty to disable scanning entirely.
- Rate limiting is in-memory and per-instance; it resets on restart and is not distributed.
- Tokens are HMAC-based and not bound to user accounts; use HTTPS and rotate secrets.
- SQLite is used for simplicity; migrate to a managed RDBMS for production.

