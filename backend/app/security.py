import hmac
import os
import secrets
import time
from collections import defaultdict
from threading import Lock
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from .config import TOKEN_TTL_SECONDS, TRUSTED_PROXY_HOPS, UIPASS, UIUSER
from .db import engine


class RateLimiter:
    def __init__(self, max_calls: int, period: float):
        self._max    = max_calls
        self._period = period
        self._hits: Dict[str, list] = defaultdict(list)
        self._lock   = Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            window = [t for t in self._hits[key] if now - t < self._period]
            if len(window) >= self._max:
                self._hits[key] = window
                return False
            window.append(now)
            self._hits[key] = window
            return True

    def remaining(self, key: str) -> int:
        now = time.time()
        with self._lock:
            window = [t for t in self._hits.get(key, []) if now - t < self._period]
            return max(0, self._max - len(window))


sms_limiter  = RateLimiter(int(os.environ.get("BMSMSRATELIMIT",  "10")), float(os.environ.get("BMSMSRATEPERIOD",  "60")))
dial_limiter = RateLimiter(int(os.environ.get("BMDIALRATELIMIT",  "5")), float(os.environ.get("BMDIALRATEPERIOD", "60")))
login_limiter= RateLimiter(int(os.environ.get("BMLOGINRATELIMIT", "5")), float(os.environ.get("BMLOGINRATEPERIOD","60")))
ota_limiter  = RateLimiter(int(os.environ.get("BMOTARATELIMIT",  "4")), float(os.environ.get("BMOTARATEPERIOD",  "60")))


def cleanup_expired_tokens(now: int) -> None:
    try:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM auth_tokens WHERE exp <= :n"), {"n": now})
    except Exception:
        pass


def get_token_record(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT username, exp FROM auth_tokens WHERE token = :t"),
                {"t": token},
            ).first()
            if not row:
                return None
            return {"username": row[0] or "", "exp": int(row[1] or 0)}
    except Exception:
        return None


def insert_token(token: str, username: str, exp: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            text("INSERT OR REPLACE INTO auth_tokens(token, username, exp) VALUES(:t, :u, :e)"),
            {"t": token, "u": username, "e": exp},
        )


def delete_token(token: str) -> None:
    if not token:
        return
    try:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM auth_tokens WHERE token = :t"), {"t": token})
    except Exception:
        pass


def issue_token(username: str, now: int) -> str:
    cleanup_expired_tokens(now)
    token = secrets.token_urlsafe(32)
    insert_token(token, username, now + TOKEN_TTL_SECONDS)
    return token


def extract_bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "").strip()
    if not auth.startswith("Bearer "):
        return ""
    return auth[7:].strip()


def unauthorized_json(detail: str = "未登录或登录已失效") -> JSONResponse:
    return JSONResponse(status_code=401, content={"detail": detail})


def require_token(request: Request, now: int) -> Dict[str, Any]:
    token = extract_bearer_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="未登录或登录已失效")
    payload = get_token_record(token)
    if not payload:
        raise HTTPException(status_code=401, detail="未登录或登录已失效")
    if payload.get("exp", 0) <= now:
        delete_token(token)
        raise HTTPException(status_code=401, detail="登录已过期，请重新登录")
    return payload


def check_login_credentials(username: str, password: str) -> bool:
    return hmac.compare_digest(username, UIUSER) and hmac.compare_digest(password, UIPASS)


def client_ip(request: Request) -> str:
    if TRUSTED_PROXY_HOPS > 0:
        xff = request.headers.get("x-forwarded-for", "") or request.headers.get("X-Forwarded-For", "")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                idx = max(0, len(parts) - TRUSTED_PROXY_HOPS)
                return parts[idx]
        real = request.headers.get("x-real-ip", "") or request.headers.get("X-Real-IP", "")
        if real:
            return real.strip()
    return request.client.host if request.client else "unknown"


def env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def validate_startup_security() -> None:
    if (not UIPASS or UIPASS == "admin") and not env_truthy("BMINSECURE_DEFAULT_PASSWORD"):
        raise RuntimeError(
            "BMUIPASS must be set to a strong non-default password. "
            "Set BMINSECURE_DEFAULT_PASSWORD=1 only for local development."
        )
