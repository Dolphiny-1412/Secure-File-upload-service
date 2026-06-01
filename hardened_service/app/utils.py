import time
from typing import Tuple

from fastapi import HTTPException, Request

from .config import get_settings

# Simple in-memory rate limiter { key: (count, reset_at) }
_rate_state = {}


def _now() -> int:
    return int(time.time())


def rate_limiter_dependency(request: Request):
    settings = get_settings()
    window = settings.RATE_LIMIT_WINDOW_SECONDS
    max_req = settings.RATE_LIMIT_REQUESTS
    ip = request.client.host if request.client else "unknown"

    count, reset_at = _rate_state.get(ip, (0, _now() + window))
    now = _now()
    if now > reset_at:
        count, reset_at = 0, now + window
    count += 1
    _rate_state[ip] = (count, reset_at)
    if count > max_req:
        raise HTTPException(status_code=429, detail="rate limit exceeded")


