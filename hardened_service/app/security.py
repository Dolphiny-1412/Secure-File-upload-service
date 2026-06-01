import base64
import hashlib
import hmac
import json
import time
from typing import Dict

from starlette.datastructures import Headers


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64u_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def sign_token(secret: str, file_id: str, exp_seconds: int) -> str:
    payload = {"file_id": file_id, "exp": int(time.time()) + exp_seconds}
    msg = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return _b64u_encode(msg + b"." + sig)


def verify_token(token: str, secret: str) -> Dict:
    raw = _b64u_decode(token)
    try:
        msg, sig = raw.rsplit(b".", 1)
    except ValueError:
        raise ValueError("invalid token")
    expected = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("invalid token")
    payload = json.loads(msg.decode())
    if int(payload.get("exp", 0)) < int(time.time()):
        raise ValueError("expired")
    return payload


class SecureHeaders:
    @staticmethod
    def build_download_headers(suggested_name: str, content_type: str) -> dict:
        safe_name = suggested_name or "download"
        return {
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "private, max-age=300",
            "Content-Type": content_type,
        }


