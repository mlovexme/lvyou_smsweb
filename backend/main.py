import asyncio
import json
import os
import re
import threading
import time
from datetime import datetime
from ipaddress import ip_address, ip_network, IPv4Network
from itertools import islice
from typing import Any, Dict, List, Optional, Tuple
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request, Depends, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

import concurrent.futures
import hashlib
import hmac
import logging
import uuid as _uuid
from collections import defaultdict
from logging.handlers import RotatingFileHandler
from threading import Lock as _Lock

# FIX(P2#4): leaf modules (config / db / security) own the SQLAlchemy
# engine, models, token CRUD, SSRF allowlist and network helpers. Routes
# and middleware stay in this file for now; subsequent PRs can split
# them into devices/scan/ota/config_io APIRouters.
from backend.config import (
    AUTH_COOKIE_NAME,
    CIDRFALLBACKLIMIT,
    CONCURRENCY,
    CONFIG_MAX_CHARS,
    DBPATH,
    COOKIE_SAMESITE,
    COOKIE_SECURE,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    DEFAULTPASS,
    DEFAULTUSER,
    FORWARD_METHOD_BASIC,
    OTA_BATCH_MAX,
    SCAN_RETRIES,
    SCAN_RETRY_SLEEP_MS,
    SCAN_TTL,
    SMS_MAX_LEN,
    STATICDIR,
    TIMEOUT,
    TOKEN_TTL_SECONDS,
    UIPASS,
    UIUSER,
)
from backend.db import (
    Device,
    SessionLocal,
    cleanup_expired_tokens as _cleanup_expired_tokens,
    delete_token as _delete_token,
    get_db,
    get_token_record as _get_token_record,
    issue_token as _issue_token,
    nowts,
)
from backend.security import (
    client_ip_from_request as _client_ip,
    get_arp_table as getarptable,
    guess_ipv4_cidr as guessipv4cidr,
    is_device_ip_allowed as _is_device_ip_allowed,
    prewarm_neighbors,
    tcp_port_open as _tcp_port_open,
    validate_startup_security as _validate_startup_security,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("board-manager")


def _env_truthy(name: str) -> bool:
    """FIX(P2#12): forward-declared so the BMDEBUG check below treats
    BMDEBUG=0 as false. Previously the bare ``os.environ.get("BMDEBUG")``
    truthiness test enabled debug logging when an operator wrote
    ``BMDEBUG=0`` (a non-empty string is truthy in Python). The same
    helper is reused later for BMINSECURE_DEFAULT_PASSWORD and friends."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


logger.setLevel(logging.DEBUG if _env_truthy("BMDEBUG") else logging.INFO)

# Constants, engine, and ORM models now live in backend.config / backend.db
# and are re-imported above. The names are unchanged so the rest of this
# module reads identically.


class RateLimiter:
    def __init__(self, max_calls: int, period: float):
        self._max    = max_calls
        self._period = period
        self._hits: Dict[str, list] = defaultdict(list)
        self._lock   = _Lock()

    def _prune_locked(self, key: str, now: float) -> list:
        window = [t for t in self._hits.get(key, []) if now - t < self._period]
        self._hits[key] = window
        return window

    def allow(self, key: str) -> bool:
        """Check the limit and record this attempt atomically."""
        now = time.time()
        with self._lock:
            window = self._prune_locked(key, now)
            if len(window) >= self._max:
                return False
            window.append(now)
            return True

    def check_only(self, key: str) -> bool:
        """FIX(P2#2): non-recording probe. Used by the login flow to gate
        before validating credentials so a flood of well-formed login
        requests does not consume the budget for legitimate users."""
        now = time.time()
        with self._lock:
            return len(self._prune_locked(key, now)) < self._max

    def record(self, key: str) -> None:
        """FIX(P2#2): record an event without a guard check. Paired with
        check_only() the caller can implement count-failures-only
        semantics: fat-fingering a password and then succeeding does not
        eat the budget, but failed attempts do."""
        now = time.time()
        with self._lock:
            window = self._prune_locked(key, now)
            window.append(now)

    def reset(self, key: str) -> None:
        """FIX(P2#2): clear the failure window after a successful login."""
        with self._lock:
            self._hits.pop(key, None)

    def remaining(self, key: str) -> int:
        now = time.time()
        with self._lock:
            window = [t for t in self._hits.get(key, []) if now - t < self._period]
            return max(0, self._max - len(window))


_sms_limiter  = RateLimiter(int(os.environ.get("BMSMSRATELIMIT",  "10")), float(os.environ.get("BMSMSRATEPERIOD",  "60")))
_dial_limiter = RateLimiter(int(os.environ.get("BMDIALRATELIMIT",  "5")), float(os.environ.get("BMDIALRATEPERIOD", "60")))
# FIX(P2#2): two-dimensional login rate limit. The IP limiter catches one
# attacker probing many usernames; the username limiter catches a
# distributed bruteforce of a single known account from many addresses.
# Both are count-failures-only so legitimate users with one or two typos
# are not locked out alongside attackers. Defaults stay at 5 failures /
# 60s for IP (preserves the previous BMLOGINRATELIMIT/PERIOD knobs) and
# 10 / 600 for username (looser but with a much wider window so a slow
# distributed attack still hits the cap before exhausting the password
# space).
_login_limiter_ip = RateLimiter(
    int(os.environ.get("BMLOGINRATELIMIT", "5")),
    float(os.environ.get("BMLOGINRATEPERIOD", "60")),
)
_login_limiter_user = RateLimiter(
    int(os.environ.get("BMLOGINUSERRATELIMIT", "10")),
    float(os.environ.get("BMLOGINUSERRATEPERIOD", "600")),
)
# FIX(N5): OTA batch rate limiter (per user), prevents using it as an internal reboot-storm
_ota_limiter  = RateLimiter(int(os.environ.get("BMOTARATELIMIT",  "4")), float(os.environ.get("BMOTARATEPERIOD",  "60")))

PHONE_RE = re.compile(r"^\+?[0-9]{5,15}$")


def _validate_phone(phone: str) -> str:
    p = (phone or "").strip()
    if not p or not PHONE_RE.match(p):
        raise HTTPException(status_code=400, detail="手机号格式不正确")
    return p


def _validate_sms_content(content: str) -> str:
    c = (content or "").strip()
    if not c:
        raise HTTPException(status_code=400, detail="短信内容不能为空")
    if len(c) > SMS_MAX_LEN:
        raise HTTPException(status_code=400, detail=f"短信内容超出长度限制（最多{SMS_MAX_LEN}字）")
    return c


# FIX(P2#3): file-backed structured audit log with size-based rotation.
# Defaults colocate audit.log next to the SQLite DB so the systemd unit's
# existing ReadWritePaths covers it without further changes; operators
# can redirect via BMAUDITLOGFILE (e.g. to /var/log/board-manager/) or
# disable file logging entirely with BMAUDITLOGDISABLE=1 (e.g. inside a
# container where stdout shipping is preferred).
_audit_default_dir = os.path.dirname(DBPATH) or "/var/log/board-manager"
AUDIT_LOG_FILE         = os.environ.get("BMAUDITLOGFILE", os.path.join(_audit_default_dir, "audit.log"))
AUDIT_LOG_MAX_BYTES    = int(os.environ.get("BMAUDITLOGMAXBYTES",    str(10 * 1024 * 1024)))
AUDIT_LOG_BACKUP_COUNT = int(os.environ.get("BMAUDITLOGBACKUPCOUNT", "5"))
AUDIT_LOG_DISABLE      = os.environ.get("BMAUDITLOGDISABLE", "").strip().lower() in {"1", "true", "yes", "on"}


class _JsonAuditFormatter(logging.Formatter):
    """FIX(P2#3): emit one JSON object per line so log shippers (Loki,
    ELK, Datadog, journald JSON parser) can index fields without the
    fragile `key=value` regex parsing the legacy text format required."""

    def format(self, record):
        ts = datetime.utcfromtimestamp(record.created).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        payload = {
            "ts":     ts,
            "level":  record.levelname,
            "action": getattr(record, "audit_action", record.getMessage()),
            "user":   getattr(record, "audit_user", "-"),
            "detail": getattr(record, "audit_detail", ""),
        }
        ip = getattr(record, "audit_ip", "")
        if ip:
            payload["ip"] = ip
        result = getattr(record, "audit_result", "")
        if result:
            payload["result"] = result
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _setup_audit_logger() -> logging.Logger:
    """FIX(P2#3): configure the audit logger with two sinks: (a) a stream
    handler so journalctl still shows recent activity, and (b) a rotating
    file handler with the JSON formatter so the audit trail survives
    journal rotation and can be shipped externally. The function is
    idempotent so repeated imports (eg. pytest collection) don't pile up
    duplicate handlers."""

    aud = logging.getLogger("audit")
    aud.setLevel(logging.INFO)
    aud.propagate = False  # don't double-emit through the root logger
    if aud.handlers:
        return aud

    stream = logging.StreamHandler()
    # FIX(P2#3): include ip + result so the journal-readable form does
    # not drop the structured fields the JSON formatter persists.
    stream.setFormatter(logging.Formatter(
        "audit ts=%(asctime)s action=%(audit_action)s user=%(audit_user)s "
        "ip=%(audit_ip)s result=%(audit_result)s detail=%(audit_detail)s"
    ))
    aud.addHandler(stream)

    if AUDIT_LOG_DISABLE:
        return aud

    try:
        log_dir = os.path.dirname(AUDIT_LOG_FILE)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        fh = RotatingFileHandler(
            AUDIT_LOG_FILE,
            maxBytes=AUDIT_LOG_MAX_BYTES,
            backupCount=AUDIT_LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        fh.setFormatter(_JsonAuditFormatter())
        aud.addHandler(fh)
    except OSError as exc:
        # Don't fail startup just because the audit dir isn't writable;
        # the stream handler keeps records visible and the warning lands
        # in the operator's main service log.
        logger.warning("audit file logger disabled (%s): %s", AUDIT_LOG_FILE, exc)
    return aud


_audit_logger = _setup_audit_logger()


def _audit(action: str, user: str = "-", detail: str = "", ip: str = "", result: str = ""):
    """FIX(P2#3): all audit call sites now flow through structured fields
    (`extra=...`) instead of being baked into the message string. The
    JSON formatter consumes those fields directly; the legacy stream
    formatter renders them as the old `key=value` shape so existing
    journal greps keep working during the transition."""
    _audit_logger.info(
        action,
        extra={
            "audit_action": action,
            "audit_user":   user,
            "audit_detail": detail,
            "audit_ip":     ip,
            "audit_result": result,
        },
    )


# FIX(P1#16): only swallow truly unhandled Exceptions. HTTPExceptions
# originate from validation / auth code paths and should keep their intended
# status codes; Starlette's default handler already handles them correctly.
def _setup_exception_handlers(_app: FastAPI):
    @_app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        if isinstance(exc, HTTPException):
            raise exc
        err_id = _uuid.uuid4().hex[:8]
        logger.error("unhandled [%s] %s %s: %s", err_id, request.method, request.url.path, exc, exc_info=True)
        return JSONResponse(status_code=500, content={"detail": f"服务器内部错误 (ref: {err_id})"})


class ScanState:
    def __init__(self):
        self.status    = "pending"
        self.progress  = ""
        self.results: List[Dict[str, Any]] = []
        self.found     = 0
        self.scanned   = 0
        self.total_ips = 0
        self.cidr      = ""
        self.finished_at: float = 0.0
        self._lock     = _Lock()

    # FIX(P1#7): all mutators serialised under the same lock used by to_dict
    def set_status(self, status: str, progress: Optional[str] = None) -> None:
        with self._lock:
            self.status = status
            if progress is not None:
                self.progress = progress

    def set_progress(self, progress: str) -> None:
        with self._lock:
            self.progress = progress

    def set_counts(self, *, scanned: Optional[int] = None, found: Optional[int] = None, total_ips: Optional[int] = None) -> None:
        with self._lock:
            if scanned is not None:
                self.scanned = scanned
            if found is not None:
                self.found = found
            if total_ips is not None:
                self.total_ips = total_ips

    def set_results(self, results: List[Dict[str, Any]]) -> None:
        with self._lock:
            self.results = results
            self.found = len(results)

    def set_cidr(self, cidr: str) -> None:
        with self._lock:
            self.cidr = cidr

    def mark_done(self) -> None:
        with self._lock:
            self.finished_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "status":    self.status,
                "progress":  self.progress,
                "found":     self.found,
                "scanned":   self.scanned,
                "total_ips": self.total_ips,
                "cidr":      self.cidr,
                "devices":   [{"ip": r["ip"], "devId": r.get("devId", "")} for r in self.results],
            }


_active_scans: Dict[str, ScanState] = {}
_active_scans_lock = _Lock()


def _cleanup_old_scans() -> None:
    now = time.time()
    with _active_scans_lock:
        expired = [sid for sid, st in _active_scans.items()
                   if st.finished_at > 0 and now - st.finished_at > SCAN_TTL]
        for sid in expired:
            _active_scans.pop(sid, None)


# ``_run_migrations`` runs at import time inside backend.db; ``get_db``,
# ``nowts``, the token CRUD and ``_issue_token`` are imported above and
# remain available under their original ``_-prefixed`` names for the
# rest of this file.


def _extract_bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "").strip()
    if not auth.startswith("Bearer "):
        return ""
    return auth[7:].strip()


def _extract_request_token(request: Request) -> Tuple[str, bool]:
    """FIX(P2#1): return (token, via_cookie). Authorization header takes
    precedence (CLI / programmatic clients keep working), falling back to
    the AUTH_COOKIE_NAME cookie for browser sessions. The boolean tells
    the caller whether the token came from a cookie -- only cookie auth
    is vulnerable to CSRF and therefore requires the X-CSRF-Token check."""
    bearer = _extract_bearer_token(request)
    if bearer:
        return bearer, False
    cookie_token = request.cookies.get(AUTH_COOKIE_NAME, "")
    return cookie_token.strip(), True


def _csrf_for_token(token: str) -> str:
    """FIX(P2#1): deterministic CSRF derivation. We do not persist a
    separate CSRF column; rotating BMUIPASS rotates the HMAC key and
    therefore invalidates every previously-issued CSRF cookie."""
    if not token:
        return ""
    key = hashlib.sha256(b"board-mgr-csrf-v1::" + UIPASS.encode("utf-8")).digest()
    return hmac.new(key, token.encode("utf-8"), hashlib.sha256).hexdigest()


def _set_auth_cookies(response, token: str) -> None:
    """FIX(P2#1): write both auth (httpOnly) and CSRF (JS-readable) cookies."""
    csrf = _csrf_for_token(token)
    response.set_cookie(
        AUTH_COOKIE_NAME, token,
        max_age=TOKEN_TTL_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME, csrf,
        max_age=TOKEN_TTL_SECONDS,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
    )


def _clear_auth_cookies(response) -> None:
    response.delete_cookie(AUTH_COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")


def _unauthorized_json(detail: str = "未登录或登录已失效") -> JSONResponse:
    return JSONResponse(status_code=401, content={"detail": detail})


def _forbidden_json(detail: str) -> JSONResponse:
    return JSONResponse(status_code=403, content={"detail": detail})


def _require_token(request: Request) -> Dict[str, Any]:
    token, _ = _extract_request_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="未登录或登录已失效")
    payload = _get_token_record(token)
    if not payload:
        raise HTTPException(status_code=401, detail="未登录或登录已失效")
    if payload.get("exp", 0) <= nowts():
        _delete_token(token)
        raise HTTPException(status_code=401, detail="登录已过期，请重新登录")
    return payload


def _check_login_credentials(username: str, password: str) -> bool:
    return hmac.compare_digest(username, UIUSER) and hmac.compare_digest(password, UIPASS)


# `_validate_startup_security` and `_client_ip` are imported from
# ``backend.security`` and remain available under their original names.
# The cookie SameSite/Secure consistency check that lived here previously
# now also lives in ``backend.security.validate_startup_security``.


# ── Shared httpx client + executor (managed by lifespan) ─────────────────────
_sync_client: Optional[httpx.Client] = None
_shared_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
_cleanup_task: Optional[asyncio.Task] = None


def _get_sync_client() -> httpx.Client:
    """Return the shared sync client; fall back to creating a fresh one if the
    lifespan manager has not run yet (e.g. during tests)."""
    global _sync_client
    if _sync_client is None:
        _sync_client = httpx.Client(
            timeout=TIMEOUT,
            limits=httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=20),
            follow_redirects=False,
        )
    return _sync_client


def _get_shared_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _shared_executor
    if _shared_executor is None:
        _shared_executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(CONCURRENCY, 32))
    return _shared_executor


async def _scan_cleanup_loop() -> None:
    while True:
        try:
            _cleanup_old_scans()
            _cleanup_expired_tokens()
        except Exception:
            logger.debug("background cleanup error", exc_info=True)
        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _sync_client, _shared_executor, _cleanup_task
    # FIX(P0#1): refuse to start with an unset / default BMUIPASS.
    _validate_startup_security()
    # FIX(P1#9): one sync client for the whole process, connection pooled.
    _sync_client = httpx.Client(
        timeout=TIMEOUT,
        limits=httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=20),
        follow_redirects=False,
    )
    # FIX(P1#10): one ThreadPoolExecutor for all batch endpoints / scans.
    _shared_executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(CONCURRENCY, 32))
    # FIX(P1#6): the previous AsyncClient on app.state was created but never
    # used by any endpoint. Removed to avoid leaking connections at shutdown
    # and to make it obvious which client is the production code path.
    app.state.sync_http_client = _sync_client
    app.state.executor = _shared_executor
    # FIX(P1#12): periodic cleanup task for finished scan tasks and expired tokens.
    _cleanup_task = asyncio.create_task(_scan_cleanup_loop())
    try:
        yield
    finally:
        if _cleanup_task:
            _cleanup_task.cancel()
            try:
                await _cleanup_task
            except (asyncio.CancelledError, Exception):
                pass
        try:
            _sync_client.close()
        except Exception:
            pass
        try:
            _shared_executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass


app = FastAPI(title="Board LAN Hub", version="5.0", lifespan=lifespan)
_setup_exception_handlers(app)


def _configure_cors(_app: FastAPI) -> None:
    raw = os.environ.get("BMALLOWORIGINS", "")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    # FIX(P0#6): refuse the insecure combination of wildcard origin with
    # credentials. Starlette silently allows it but browsers will reject the
    # response, which bakes a subtle CSRF-enabling footgun into the API.
    if "*" in origins:
        raise RuntimeError(
            "BMALLOWORIGINS='*' is incompatible with allow_credentials=True. "
            "Either specify explicit origins or unset BMALLOWORIGINS."
        )
    _app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        # FIX(P2#1): allow X-CSRF-Token so the SPA can attach the double-
        # submit value on cross-origin state-changing requests.
        allow_headers=["Authorization", "Content-Type", CSRF_HEADER_NAME],
    )


# FIX(P0#1): expose /api/health so container/compose HEALTHCHECK works without
# needing a Bearer token. The endpoint returns only liveness info.
# FIX(P2#8): /metrics is added to this set inside _wire_prometheus()
# only when BMMETRICS_TOKEN is set. Leaving it out when metrics are
# disabled means the main token_auth_mw still rejects requests instead
# of letting them fall through to a confusing 404.
_PUBLIC_PATHS = {"/", "/api/login", "/api/health"}

# FIX(P2#1): methods that mutate state and therefore must carry a valid
# X-CSRF-Token header when the caller authenticated via a cookie. Bearer-
# header authentication does not need CSRF since CSRF is specifically
# about cookies-attached-by-the-browser.
_CSRF_REQUIRED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@app.middleware("http")
async def token_auth_mw(request: Request, call_next):
    path = request.url.path
    if request.method == "OPTIONS" or path.startswith("/static/") or path in _PUBLIC_PATHS:
        return await call_next(request)
    token, via_cookie = _extract_request_token(request)
    if not token:
        return _unauthorized_json("未登录或登录已失效")
    record = _get_token_record(token)
    if not record:
        return _unauthorized_json("未登录或登录已失效")
    if record.get("exp", 0) <= nowts():
        _delete_token(token)
        return _unauthorized_json("登录已过期，请重新登录")
    # FIX(P2#1): CSRF gate. Only enforced on cookie-auth + state-changing
    # methods so that bearer-token CLIs and read-only GETs are unaffected.
    if via_cookie and request.method in _CSRF_REQUIRED_METHODS:
        provided = request.headers.get(CSRF_HEADER_NAME, "").strip()
        expected = _csrf_for_token(token)
        if not provided or not hmac.compare_digest(provided, expected):
            return _forbidden_json("CSRF token 缺失或不匹配")
    return await call_next(request)


# FIX(P1#5): register CORS *after* the token middleware so it is the
# outermost wrapper. Starlette runs middlewares in last-added-first order,
# so by adding CORS after the @app.middleware("http") decorator above we
# guarantee that 401 responses returned directly from the auth middleware
# still carry Access-Control-Allow-* headers (otherwise the browser hides
# them as a generic network error and the SPA cannot prompt for re-login).
_configure_cors(app)


# FIX(P2#8): Prometheus instrumentation. The default instrumentator
# emits per-request HTTP histogram + counter under
# `http_request_duration_seconds` / `http_requests_total`. We add three
# custom gauges that are cheap to keep up to date:
#   - bm_devices_total   (refreshed lazily inside /metrics)
#   - bm_devices_online  (same)
#   - bm_login_failures  (incremented in the login endpoint via
#                         _bm_login_failures.labels(reason=...).inc())
# /metrics is still routed through the auth middleware bypass list, but
# we additionally require a bearer token (BMMETRICS_TOKEN). If the env
# var is not set, /metrics is *not registered at all* -- safer default
# than "everyone on the LAN can scrape device counts".
def _wire_prometheus(_app: FastAPI) -> None:
    metrics_token = os.environ.get("BMMETRICS_TOKEN", "").strip()
    if not metrics_token:
        return  # opt-in only; absent env var = no /metrics endpoint
    _PUBLIC_PATHS.add("/metrics")

    try:
        from prometheus_client import Counter, Gauge
        from prometheus_fastapi_instrumentator import Instrumentator
    except ImportError:
        # The dependency is in requirements.txt but in the unlikely case
        # an operator strips it from a custom build, fail loudly during
        # setup rather than mysteriously at scrape time.
        raise RuntimeError(
            "BMMETRICS_TOKEN is set but prometheus_fastapi_instrumentator "
            "is not installed. Install backend/requirements.txt or unset "
            "BMMETRICS_TOKEN."
        )

    _app.state.bm_devices_total = Gauge("bm_devices_total", "Total devices currently registered")
    _app.state.bm_devices_online = Gauge("bm_devices_online", "Devices currently marked online")
    _app.state.bm_login_failures = Counter(
        "bm_login_failures_total",
        "Failed login attempts grouped by reason",
        ["reason"],
    )

    instrumentator = Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        excluded_handlers=["/metrics", "/api/health"],
    )
    instrumentator.instrument(_app)

    # Refresh the device gauges on every scrape via a tiny middleware on
    # the metrics route itself. Cheap (two .count() queries) and avoids
    # having to hook every place that mutates a device.
    def _refresh_device_gauges() -> None:
        try:
            with SessionLocal() as session:
                total = session.query(Device).count()
                online = session.query(Device).filter(Device.status == "online").count()
            _app.state.bm_devices_total.set(total)
            _app.state.bm_devices_online.set(online)
        except Exception:
            # Don't let a slow / locked DB block scraping.
            pass

    @_app.middleware("http")
    async def _metrics_auth_mw(request: Request, call_next):
        if request.url.path == "/metrics":
            auth = request.headers.get("authorization", "")
            if not auth.startswith("Bearer "):
                return _unauthorized_json("metrics token required")
            supplied = auth[len("Bearer "):].strip()
            import hmac as _hmac
            if not _hmac.compare_digest(supplied, metrics_token):
                return _unauthorized_json("metrics token invalid")
            _refresh_device_gauges()
        return await call_next(request)

    # Expose at /metrics. Must be called after instrument() above.
    instrumentator.expose(_app, endpoint="/metrics", include_in_schema=False)


_wire_prometheus(app)


def _bm_login_failure(reason: str) -> None:
    """Increment the login-failure counter when /metrics is enabled.
    No-op when BMMETRICS_TOKEN is unset (the counter wasn't created)."""
    counter = getattr(app.state, "bm_login_failures", None)
    if counter is not None:
        try:
            counter.labels(reason=reason).inc()
        except Exception:
            pass


os.makedirs(STATICDIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATICDIR), name="static")


@app.get("/")
def uiindex():
    index_path = os.path.join(STATICDIR, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="UI not built")
    return FileResponse(index_path)


# Network-level helpers (SSRF allowlist, ARP table, prewarm, TCP probe,
# default CIDR guess) live in ``backend.security``; only the thin
# HTTP-aware wrapper that converts allowlist failures into HTTPException
# stays here so it can use FastAPI's exception machinery.
def _ensure_device_ip_allowed(ip: str) -> None:
    if not _is_device_ip_allowed(ip):
        logger.warning("blocked outbound device request to non-whitelisted ip: %s", ip)
        raise HTTPException(status_code=400, detail="设备 IP 不在允许的内网范围内")


def _bm_op_from_sta(sta: str) -> str:
    return (sta or "").strip()


# FIX(P1#9): reuse shared httpx.Client instead of creating one per call.
def istargetdevice(ip: str, user: str, pw: str) -> Tuple[bool, Optional[str]]:
    _ensure_device_ip_allowed(ip)
    url = f"http://{ip}/mgr"
    last_realm: Optional[str] = None
    client = _get_sync_client()
    for attempt in range(max(1, SCAN_RETRIES)):
        try:
            resp = client.get(url)
            if resp.status_code != 401:
                raise RuntimeError(f"unexpected status {resp.status_code}")
            header = resp.headers.get("www-authenticate", "")
            if "Digest" not in header:
                raise RuntimeError("digest auth missing")
            match = re.search(r'realm="([^"]+)"', header)
            realm = match.group(1) if match else None
            last_realm = realm
            if realm != "asyncesp":
                return False, realm
            resp2 = client.get(url, auth=httpx.DigestAuth(user, pw))
            if resp2.status_code == 200:
                return True, realm
            raise RuntimeError(f"auth status {resp2.status_code}")
        except Exception as _scan_exc:
            if attempt < max(1, SCAN_RETRIES) - 1:
                logger.debug("scan %s attempt %d failed: %s", ip, attempt + 1, _scan_exc)
                time.sleep(max(0, SCAN_RETRY_SLEEP_MS) / 1000.0)
    return False, last_realm


def getdevicedata(ip: str, user: str, pw: str) -> Optional[Dict[str, Any]]:
    _ensure_device_ip_allowed(ip)
    keys_list = ["DEV_ID", "DEV_VER", "SIM1_PHNUM", "SIM2_PHNUM", "SIM1_OP", "SIM2_OP", "SIM1_STA", "SIM2_STA", "SIM1_SIGNAL", "SIM2_SIGNAL", "WIFI_NAME", "WIFI_DBM"]
    body = f"keys={json.dumps({'keys': keys_list}, ensure_ascii=False)}"
    try:
        resp = _get_sync_client().post(
            f"http://{ip}/mgr",
            params={"a": "getHtmlData_index"},
            auth=httpx.DigestAuth(user, pw),
            content=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if isinstance(data, dict) and data.get("success") and isinstance(data.get("data"), dict):
            return data["data"]
    except Exception:
        pass
    return None


def get_wifi_info(ip: str, user: str, pw: str) -> Dict[str, str]:
    _ensure_device_ip_allowed(ip)
    keys_list = ["WIFI_NAME", "WIFI_DBM"]
    body = f"keys={json.dumps({'keys': keys_list}, ensure_ascii=False)}"
    try:
        resp = _get_sync_client().post(
            f"http://{ip}/mgr",
            params={"a": "getHtmlData_index"},
            auth=httpx.DigestAuth(user, pw),
            content=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and data.get("success") and isinstance(data.get("data"), dict):
                return {
                    "wifiName": data["data"].get("WIFI_NAME", ""),
                    "wifiDbm": data["data"].get("WIFI_DBM", ""),
                }
    except Exception:
        pass
    return {"wifiName": "", "wifiDbm": ""}


def read_device_config(ip: str, user: str, pw: str) -> Optional[str]:
    _ensure_device_ip_allowed(ip)
    body = f"keys={json.dumps({'keys': ['PROPF_1_1_1']}, ensure_ascii=False)}"
    try:
        resp = _get_sync_client().post(
            f"http://{ip}/mgr",
            params={"a": "getHtmlData_propfMgr"},
            auth=httpx.DigestAuth(user, pw),
            content=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=TIMEOUT + 5,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if isinstance(data, dict) and data.get("success") and isinstance(data.get("data"), dict):
            propf = data["data"].get("PROPF", "")
            if isinstance(propf, str):
                return propf
            return json.dumps(propf, ensure_ascii=False)
    except Exception:
        pass
    return None


def write_device_config(ip: str, user: str, pw: str, content: str) -> bool:
    _ensure_device_ip_allowed(ip)
    try:
        resp = _get_sync_client().post(
            f"http://{ip}/mgr",
            params={"a": "updateProf"},
            data={
                "hiddenWifi": "1",
                "hiddenAdminPwd": "1",
                "hiddenUserPwd": "1",
                "propf": content,
            },
            auth=httpx.DigestAuth(user, pw),
            timeout=TIMEOUT + 10,
        )
        return resp.status_code == 200
    except Exception:
        pass
    return False


def _device_to_dict(device: Device) -> Dict[str, Any]:
    return {
        "id":      device.id,
        "devId":   device.devId or "",
        "alias":   device.alias or "",
        "grp":     device.grp or "auto",
        "ip":      device.ip,
        "mac":     device.mac or "",
        "status":  device.status or "unknown",
        "lastSeen":device.lastSeen or 0,
        "created": device.created or "",
        "firmwareVersion": getattr(device, "firmware_version", "") or "",
        "sims": {
            "sim1": {"number": device.sim1number or "", "operator": device.sim1operator or "", "signal": device.sim1signal or 0, "label": device.sim1number or device.sim1operator or "SIM"},
            "sim2": {"number": device.sim2number or "", "operator": device.sim2operator or "", "signal": device.sim2signal or 0, "label": device.sim2number or device.sim2operator or "SIM"},
        },
        "wifiName": "",
        "wifiDbm": "",
    }


# FIX(P1#8): robust upsert that tolerates the UNIQUE(ip) constraint without
# silently deleting an unrelated row and without leaving the session in a
# rolled-back state.
def upsertdevice(db: Session, ip: str, mac: str, user: str, pw: str, grp: Optional[str] = None) -> Dict[str, Any]:
    data   = getdevicedata(ip, user, pw) or {}
    devid  = (data.get("DEV_ID") or "").strip() or None
    sim1num= (data.get("SIM1_PHNUM") or "").strip()
    sim2num= (data.get("SIM2_PHNUM") or "").strip()
    sim1op = (data.get("SIM1_OP") or "").strip() or _bm_op_from_sta(data.get("SIM1_STA") or "")
    sim2op = (data.get("SIM2_OP") or "").strip() or _bm_op_from_sta(data.get("SIM2_STA") or "")
    sim1sig= int(data.get("SIM1_SIGNAL") or 0)
    sim2sig= int(data.get("SIM2_SIGNAL") or 0)
    fw_ver = (data.get("DEV_VER") or "").strip()
    mac    = (mac or "").strip().upper() or None

    device: Optional[Device] = None
    if devid:
        device = db.query(Device).filter(Device.devId == devid).first()
    if not device and mac:
        device = db.query(Device).filter(Device.mac == mac).first()
    if not device:
        device = db.query(Device).filter(Device.ip == ip).first()

    if device and device.ip != ip:
        other = db.query(Device).filter(Device.ip == ip).first()
        if other and other.id != device.id:
            # Another DB row already owns the target IP (DHCP rotation).
            # Clear its ip to release the UNIQUE slot before reassigning.
            other.ip = f"__stale_{other.id}_{nowts()}"
            try:
                db.flush()
            except Exception:
                db.rollback()
                return _device_to_dict(device)

    if device:
        device.devId = devid if devid else device.devId
        if grp is not None and str(grp).strip():
            device.grp = grp
        device.ip          = ip
        device.mac         = mac if mac else (device.mac or None)
        device.user        = user
        device.passwd      = pw
        device.status      = "online"
        device.lastSeen    = nowts()
        device.sim1number  = sim1num
        device.sim1operator= sim1op
        device.sim1signal  = sim1sig
        device.sim2number  = sim2num
        device.sim2operator= sim2op
        device.sim2signal  = sim2sig
        if fw_ver:
            device.firmware_version = fw_ver
    else:
        device = Device(
            devId=devid, grp=(grp if grp is not None and str(grp).strip() else "auto"),
            ip=ip, mac=mac, user=user, passwd=pw, status="online", lastSeen=nowts(),
            sim1number=sim1num, sim1operator=sim1op, sim1signal=sim1sig,
            sim2number=sim2num, sim2operator=sim2op, sim2signal=sim2sig,
            firmware_version=fw_ver,
            created=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        db.add(device)

    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.warning("upsert %s failed: %s", ip, exc)
        return {"ip": ip, "error": f"数据库写入失败: {exc}"}
    db.refresh(device)
    return _device_to_dict(device)


# FIX(N1): revert to a pure DB read. The previous implementation performed a
# blocking HTTP call per device (O(N) outbound requests per /api/devices hit,
# plus an SSRF amplifier); real-time status now happens via explicit
# /detail / /refresh endpoints or the scan flow.
def listdevices(db: Session) -> List[Dict[str, Any]]:
    devices = db.query(Device).order_by(Device.created.desc(), Device.id.desc()).all()
    return [_device_to_dict(d) for d in devices]


def getallnumbers(db: Session, group: str = "") -> List[Dict[str, Any]]:
    # FIX(P2#7, Devin Review #8): optional group filter so the dashboard
    # SIM count can stay consistent with the group-filtered device counts.
    query = db.query(Device)
    gval = (group or "").strip()
    if gval and gval != "all":
        query = query.filter(Device.grp == gval)
    numbers = []
    for device in query.all():
        for num, op, slot in [(device.sim1number, device.sim1operator, 1), (device.sim2number, device.sim2operator, 2)]:
            if num and num.strip():
                numbers.append({"deviceId": device.id, "deviceName": device.devId or device.ip,
                                "ip": device.ip, "grp": device.grp or "",
                                "number": num.strip(), "operator": op or "", "slot": slot})
    return numbers


# ── Pydantic Models ───────────────────────────────────────────────────────────
class LoginReq(BaseModel):
    username: str
    password: str


class DirectSmsReq(BaseModel):
    deviceId: int
    phone: str
    content: str
    slot: int

    @field_validator("phone")
    @classmethod
    def _check_phone(cls, v):
        v = (v or "").strip()
        if not v or not PHONE_RE.match(v):
            raise ValueError("手机号格式不正确")
        return v

    @field_validator("content")
    @classmethod
    def _check_content(cls, v):
        v = (v or "").strip()
        if not v:
            raise ValueError("短信内容不能为空")
        if len(v) > SMS_MAX_LEN:
            raise ValueError(f"短信内容超出长度限制（最多{SMS_MAX_LEN}字）")
        return v


class DirectDialReq(BaseModel):
    deviceId:     int
    slot:         int
    phone:        str
    tts:          str = ""
    duration:     int = 175
    tts_times:    int = 2
    tts_pause:    int = 1
    after_action: int = 1

    @field_validator("phone")
    @classmethod
    def _check_phone(cls, v):
        v = (v or "").strip()
        if not v or not PHONE_RE.match(v):
            raise ValueError("手机号格式不正确")
        return v


class AliasReq(BaseModel):
    alias: str


class GroupReq(BaseModel):
    group: str


class BatchDeleteReq(BaseModel):
    device_ids: List[int]


class BatchWifiReq(BaseModel):
    device_ids: List[int]
    ssid: str
    pwd:  str


class SimReq(BaseModel):
    sim1: str = ""
    sim2: str = ""


class BatchSimReq(BaseModel):
    device_ids: List[int]
    sim1: str = ""
    sim2: str = ""


class BatchConfigReadReq(BaseModel):
    device_ids: List[int]


class BatchConfigPreviewReq(BaseModel):
    device_ids:   List[int]
    pattern:      str
    replacement:  str = ""
    flags:        str = ""


class BatchConfigWriteReq(BaseModel):
    device_ids:   List[int]
    pattern:      str
    replacement:  str = ""
    flags:        str = ""


class BatchConfigPresetReq(BaseModel):
    device_ids: List[int]
    preset:     str = "clean_message_templates"


class BatchForwardReq(BaseModel):
    device_ids: List[int]
    forwardUrl:  str = ""
    notifyUrl:   str = ""


class EnhancedBatchForwardReq(BaseModel):
    device_ids:    List[int]
    forward_method:str
    forwardUrl:    str = ""
    notifyUrl:     str = ""
    deviceKey0:    str = ""
    deviceKey1:    str = ""
    deviceKey2:    str = ""
    smtpProvider:  str = ""
    smtpServer:    str = ""
    smtpPort:      str = ""
    smtpAccount:   str = ""
    smtpPassword:  str = ""
    smtpFromEmail: str = ""
    smtpToEmail:   str = ""
    smtpEncryption:str = ""
    webhookUrl1:   str = ""
    webhookUrl2:   str = ""
    webhookUrl3:   str = ""
    signKey1:      str = ""
    signKey2:      str = ""
    signKey3:      str = ""
    sc3ApiUrl:     str = ""
    sctSendKey:    str = ""
    PPToken:       str = ""
    PPChannel:     str = ""
    PPWebhook:     str = ""
    PPFriends:     str = ""
    PPGroupId:     str = ""
    WPappToken:    str = ""
    WPUID:         str = ""
    WPTopicId:     str = ""
    lyApiUrl:      str = ""


class ScanStartReq(BaseModel):
    cidr:     Optional[str] = None
    group:    Optional[str] = None
    user:     str = ""
    password: str = ""


# ── API Routes ──
@app.post("/api/login")
def api_login(req: LoginReq, request: Request):
    # FIX(P1#13): use X-Forwarded-For when running behind a trusted reverse
    # proxy so the login rate limiter keys on the real client IP.
    client_ip = _client_ip(request)
    username = (req.username or "").strip()
    # FIX(P2#2): username key is lower-cased so an attacker can't bypass
    # the limiter by alternating "Admin" / "ADMIN" / "admin". Empty
    # username is not subject to the per-user limit (the IP limiter still
    # catches the flood) since "" is not a real account.
    user_key = username.lower() if username else ""
    if not _login_limiter_ip.check_only(client_ip):
        # FIX(P2#3): emit a structured event for rate-limited attempts so
        # auditors can spot bruteforce activity without correlating raw
        # uvicorn logs.
        _audit("login_blocked", user=username or "-", ip=client_ip, result="ratelimit_ip")
        # FIX(P2#8): record rate-limited rejections separately from bad
        # credentials so a bursty attack is visible on the dashboard.
        _bm_login_failure("rate_limited_ip")
        raise HTTPException(status_code=429, detail="登录尝试过于频繁，请稍后再试")
    if user_key and not _login_limiter_user.check_only(user_key):
        _audit("login_blocked", user=username, ip=client_ip, result="ratelimit_user")
        _bm_login_failure("rate_limited_user")
        raise HTTPException(status_code=429, detail="该账号登录尝试过于频繁，请稍后再试")
    if not _check_login_credentials(username, req.password or ""):
        # FIX(P2#2): record the failure on both axes so a single mistake
        # eats one slot from each. A legitimate user who succeeds on the
        # next attempt gets their window reset (see below).
        _login_limiter_ip.record(client_ip)
        if user_key:
            _login_limiter_user.record(user_key)
        # FIX(P2#3): record failed credentials -- previously only successful
        # logins were audited which made post-incident investigation hard.
        _audit("login_fail", user=username or "-", ip=client_ip, result="bad_credentials")
        _bm_login_failure("bad_credentials")
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    # FIX(P2#2): clear the per-user window on successful auth so honest
    # typo cycles do not accumulate over the day. The IP window is left
    # alone -- a single shared NAT egress should not be reset by one
    # legitimate login if other accounts on that IP are being attacked.
    if user_key:
        _login_limiter_user.reset(user_key)
    token = _issue_token(username)
    _audit("login", user=username, ip=client_ip, result="ok")
    # FIX(P2#1): the auth token is set as an httpOnly cookie so it is not
    # readable from JavaScript. The token is still echoed in the response
    # body for backwards compatibility with header-based CLI callers --
    # the browser SPA ignores it now and relies on the cookie + CSRF flow.
    response = JSONResponse(content={
        "ok": True, "token": token, "username": username, "expiresIn": TOKEN_TTL_SECONDS,
    })
    _set_auth_cookies(response, token)
    return response


@app.get("/api/me")
def api_me(request: Request):
    """FIX(P2#1): SPA bootstrap probe. After the cookie migration the
    frontend can no longer read the token from JS, so it asks the server
    'am I logged in?' on app start. Returns 401 (handled by the auth
    middleware before this body even runs) when not authenticated."""
    token, _ = _extract_request_token(request)
    record = _get_token_record(token) if token else None
    if not record:
        raise HTTPException(status_code=401, detail="未登录")
    return {
        "ok": True,
        "username": record.get("username", ""),
        "expiresIn": max(0, int(record.get("exp", 0)) - nowts()),
    }


@app.post("/api/logout")
def api_logout(request: Request):
    token, _ = _extract_request_token(request)
    if token:
        _delete_token(token)
        # FIX(P2#3): logout is also an auditable event; pair it with the
        # corresponding login record on the same token to compute session
        # durations during compliance reviews.
        _audit("logout", ip=_client_ip(request), result="ok")
    response = JSONResponse(content={"ok": True})
    _clear_auth_cookies(response)
    return response


@app.get("/api/health")
def health():
    # FIX(P2#10): exercise the DB so HEALTHCHECK actually fails when the
    # SQLite file is missing / corrupt / on a stale volume mount. The
    # round-trip is two fast queries against `sqlite_master`, so
    # liveness still costs ~1 ms.
    db_status = "ok"
    db_error: Optional[str] = None
    try:
        with SessionLocal() as session:
            session.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = "error"
        db_error = type(exc).__name__
    payload: Dict[str, Any] = {
        "status": "ok" if db_status == "ok" else "degraded",
        "db": db_status,
        "version": app.version,
        "message": "Board LAN Hub API is running",
    }
    if db_error:
        payload["db_error"] = db_error
    return JSONResponse(
        payload,
        status_code=200 if db_status == "ok" else 503,
    )


# FIX(P1#7): bound list endpoints. Previously page_size=0 (default) returned
# every row in one shot; with even a few hundred devices this dominates the
# dashboard refresh time and copies the entire table into memory. Default
# now caps at BMDEVICESPAGESIZE (500), and clients must opt into paginated
# windows by passing page_size explicitly.
DEVICES_DEFAULT_PAGE_SIZE = int(os.environ.get("BMDEVICESPAGESIZE", "500"))
DEVICES_MAX_PAGE_SIZE     = int(os.environ.get("BMDEVICESMAXPAGESIZE", "1000"))


# FIX(P2#7): the search and group filters that App.vue used to apply
# client-side now move into the backend so /api/devices?q=...&group=...
# can drive real server-side pagination. Without this, true pagination
# would interact badly with client-side filters: a user could see
# "0 results" on page 3 of 10 simply because the matching devices fell
# on other pages.
def _escape_like(value: str) -> str:
    # FIX(P2#7, Devin Review #8): SQL LIKE special characters % and _
    # have to be escaped or a search for an alias like "dev_01" matches
    # "dev101" / "devX01" too. We pair this with .ilike(..., escape='\\').
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _apply_devices_filter(query, q: str, group: str):
    qval = (q or "").strip().lower()
    if qval:
        # SQLite LIKE is case-insensitive for ASCII by default. Match the
        # same fields the old client-side filter looked at: ip, mac,
        # devId, alias, sim1/sim2 numbers and operators.
        like = f"%{_escape_like(qval)}%"
        query = query.filter(
            (Device.ip.ilike(like, escape="\\"))
            | (Device.mac.ilike(like, escape="\\"))
            | (Device.devId.ilike(like, escape="\\"))
            | (Device.alias.ilike(like, escape="\\"))
            | (Device.sim1number.ilike(like, escape="\\"))
            | (Device.sim2number.ilike(like, escape="\\"))
            | (Device.sim1operator.ilike(like, escape="\\"))
            | (Device.sim2operator.ilike(like, escape="\\"))
        )
    gval = (group or "").strip()
    if gval and gval != "all":
        query = query.filter(Device.grp == gval)
    return query


@app.get("/api/devices")
def apidevices(
    page: int = Query(1, ge=1),
    page_size: int = Query(DEVICES_DEFAULT_PAGE_SIZE, ge=1, le=DEVICES_MAX_PAGE_SIZE),
    q: str = Query("", max_length=128),
    group: str = Query("", max_length=64),
    db: Session = Depends(get_db),
):
    query = db.query(Device).order_by(Device.created.desc(), Device.id.desc())
    query = _apply_devices_filter(query, q, group)
    total = query.count()
    # FIX(P2#7, Devin Review #8): online/offline counts must be computed
    # against the full filtered set, not just the visible page, so the
    # dashboard header (online + offline = total) doesn't drift once
    # there are multiple pages.
    online = query.filter(Device.status == "online").count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items":         [_device_to_dict(d) for d in items],
        "total":         total,
        "online_count":  online,
        "offline_count": max(total - online, 0),
        "page":          page,
        "page_size":     page_size,
        "pages":         (total + page_size - 1) // page_size if total else 0,
    }


@app.get("/api/devices/groups")
def apidevicesgroups(db: Session = Depends(get_db)):
    """Return the distinct, non-empty group names so the dashboard can
    populate the group dropdown without paging through every device."""
    rows = (
        db.query(Device.grp)
        .filter(Device.grp.isnot(None), Device.grp != "")
        .distinct()
        .all()
    )
    groups = sorted({row[0] for row in rows if row[0]})
    return {"items": groups}


@app.get("/api/numbers")
def apinumbers(
    page: int = Query(1, ge=1),
    page_size: int = Query(DEVICES_DEFAULT_PAGE_SIZE, ge=1, le=DEVICES_MAX_PAGE_SIZE),
    q: str = Query("", max_length=128),
    group: str = Query("", max_length=64),
    db: Session = Depends(get_db),
):
    all_nums = getallnumbers(db, group=group)
    qval = (q or "").strip().lower()
    if qval:
        all_nums = [
            n for n in all_nums
            if qval in (n.get("number") or "").lower()
            or qval in (n.get("operator") or "").lower()
            or qval in (n.get("deviceName") or "").lower()
        ]
    total = len(all_nums)
    start = (page - 1) * page_size
    return {
        "items":     all_nums[start:start + page_size],
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "pages":     (total + page_size - 1) // page_size if total else 0,
    }


@app.get("/api/devices/{devid}/detail")
def api_device_detail(devid: int, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == devid).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    payload = _device_to_dict(device)
    payload["sim1number"]   = device.sim1number or ""
    payload["sim1operator"] = device.sim1operator or ""
    payload["sim1signal"]   = device.sim1signal or 0
    payload["sim2number"]   = device.sim2number or ""
    payload["sim2operator"] = device.sim2operator or ""
    payload["sim2signal"]   = device.sim2signal or 0
    sig_data = getdevicedata(device.ip, device.user or DEFAULTUSER, device.passwd or DEFAULTPASS) or {}
    payload["wifiName"] = sig_data.get("WIFI_NAME", "")
    payload["wifiDbm"]  = sig_data.get("WIFI_DBM", "")
    return {"device": payload, "forwardconfig": {}, "wifilist": []}


@app.post("/api/devices/{devid}/alias")
def api_set_alias(devid: int, req: AliasReq, db: Session = Depends(get_db)):
    alias = (req.alias or "").strip()
    if len(alias) > 24:
        raise HTTPException(status_code=400, detail="alias too long")
    device = db.query(Device).filter(Device.id == devid).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    device.alias = alias
    db.commit()
    return {"ok": True}


@app.post("/api/devices/{devid}/group")
def api_set_group(devid: int, req: GroupReq, db: Session = Depends(get_db)):
    group = (req.group or "").strip() or "auto"
    device = db.query(Device).filter(Device.id == devid).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    device.grp = group
    db.commit()
    return {"ok": True}


@app.delete("/api/devices/{dev_id}")
def deletedevice(dev_id: int, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == dev_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    db.delete(device)
    db.commit()
    return {"ok": True}


@app.post("/api/devices/batch/delete")
def api_batch_delete(req: BatchDeleteReq, db: Session = Depends(get_db)):
    if not req.device_ids:
        raise HTTPException(status_code=400, detail="device_ids required")
    deleted = 0
    for dev_id in req.device_ids:
        device = db.query(Device).filter(Device.id == dev_id).first()
        if device:
            db.delete(device)
            deleted += 1
    db.commit()
    return {"ok": True, "deleted": deleted}


def _safe_ip_in_net(ip: str, net: IPv4Network) -> bool:
    try:
        return ip_address(ip) in net
    except Exception:
        return False


def _scan_worker(cidr: str, group: Optional[str], user: str, password: str, state: ScanState):
    try:
        state.set_status("scanning", "解析网段...")
        net = ip_network(cidr, strict=False)

        state.set_progress("预热邻居...")
        prewarm_neighbors(net)
        arptable = getarptable()

        seen: set = set()
        iplist: List[str] = []
        arp_ips = [ip for ip in arptable if _safe_ip_in_net(ip, net)]
        for ip in arp_ips + [str(host) for host in islice(net.hosts(), CIDRFALLBACKLIMIT)]:
            if ip not in seen:
                seen.add(ip)
                iplist.append(ip)
            if len(iplist) >= CIDRFALLBACKLIMIT:
                break
        state.set_counts(total_ips=len(iplist))
        state.set_progress(f"TCP 探测 {len(iplist)} 个 IP...")

        open80: List[str] = []
        olock = threading.Lock()

        def _tcp(ip: str):
            if _tcp_port_open(ip, 80):
                with olock:
                    open80.append(ip)

        # FIX(P1#10): reuse the process-wide executor.
        executor = _get_shared_executor()
        list(executor.map(_tcp, iplist))
        state.set_counts(scanned=len(open80))
        state.set_progress(f"验证 {len(open80)} 台设备...")

        found: List[Dict[str, Any]] = []
        flock = threading.Lock()

        def _probe(ip: str):
            try:
                ok, _ = istargetdevice(ip, user, password)
            except HTTPException:
                return
            if ok:
                mac = arptable.get(ip, "")
                with flock:
                    found.append({"ip": ip, "mac": mac, "devId": "", "grp": group})

        list(executor.map(_probe, open80))

        state.set_results(found)
        state.set_progress(f"完成，发现 {len(found)} 台")
    except Exception as exc:
        state.set_status("error", f"扫描出错: {exc}")
        logger.error("scan error for %s: %s", cidr, exc, exc_info=True)
        return
    state.set_status("done")


def _run_scan_bg(scan_id: str, cidr: str, group: Optional[str], user: str, password: str):
    with _active_scans_lock:
        state = _active_scans.get(scan_id)
    if not state:
        return

    try:
        _scan_worker(cidr, group, user, password, state)

        if state.status == "error":
            state.mark_done()
            return

        state.set_status("saving", "保存设备到数据库...")
        db = SessionLocal()
        try:
            saved: List[Dict[str, Any]] = []
            failed: List[Dict[str, Any]] = []
            for item in state.results:
                try:
                    d = upsertdevice(db, item["ip"], item["mac"], DEFAULTUSER, DEFAULTPASS, item.get("grp"))
                    if d.get("error"):
                        failed.append(d)
                    else:
                        saved.append(d)
                except Exception as exc:
                    failed.append({"ip": item["ip"], "error": str(exc)})
                    logger.warning("save device %s failed: %s", item["ip"], exc)
            state.set_results(saved)
            if failed:
                failed_text = "；".join(f"{x.get('ip', '')}: {x.get('error', '')}" for x in failed[:3])
                state.set_status("error", f"发现 {len(saved) + len(failed)} 台，成功添加 {len(saved)} 台，失败 {len(failed)} 台：{failed_text}")
            else:
                state.set_status("done", f"完成，发现 {len(saved)} 台设备")
        finally:
            db.close()
    except Exception as exc:
        state.set_status("error", f"保存失败: {exc}")
        logger.error("scan save error: %s", exc, exc_info=True)
    finally:
        state.mark_done()


def _submit_scan(cidr: Optional[str], group: Optional[str], user: str, password: str, background_tasks: BackgroundTasks) -> str:
    if not cidr:
        cidr = guessipv4cidr()
    try:
        net = ip_network(cidr, strict=False)
        if not isinstance(net, IPv4Network):
            raise ValueError("only IPv4 supported")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"无效的网段: {exc}")
    scan_id = _uuid.uuid4().hex[:12]
    state = ScanState()
    state.set_cidr(cidr)
    with _active_scans_lock:
        _active_scans[scan_id] = state
    background_tasks.add_task(_run_scan_bg, scan_id, cidr, group, user, password)
    _audit("scan_start", detail=f"cidr={cidr}")
    return scan_id


@app.post("/api/scan/start")
def scanstart(req: ScanStartReq, background_tasks: BackgroundTasks):
    user     = req.user.strip()     or DEFAULTUSER
    password = req.password.strip() or DEFAULTPASS
    scan_id  = _submit_scan(req.cidr, req.group, user, password, background_tasks)
    return {"ok": True, "scanId": scan_id}


@app.get("/api/scan/status/{scan_id}")
def scanstatus(scan_id: str):
    _cleanup_old_scans()
    with _active_scans_lock:
        state = _active_scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    return state.to_dict()


@app.post("/api/sms/send-direct")
def smssenddirect(req: DirectSmsReq, request: Request, db: Session = Depends(get_db)):
    if req.slot not in (1, 2):
        raise HTTPException(status_code=400, detail="slot must be 1 or 2")
    phone   = _validate_phone(req.phone)
    content = _validate_sms_content(req.content)
    rl_key  = f"sms:{req.deviceId}"
    if not _sms_limiter.allow(rl_key):
        remaining = _sms_limiter.remaining(rl_key)
        raise HTTPException(status_code=429, detail=f"发送过于频繁，请稍后再试（剩余{remaining}次/分钟）")
    device = db.query(Device).filter(Device.id == req.deviceId).first()
    if not device:
        raise HTTPException(status_code=404, detail="设备不存在")
    ip   = device.ip
    _ensure_device_ip_allowed(ip)
    user = (device.user   or DEFAULTUSER).strip()
    pw   = (device.passwd or DEFAULTPASS).strip()
    try:
        ok, _ = istargetdevice(ip, user, pw)
        if not ok:
            raise HTTPException(status_code=400, detail="设备认证失败")
        resp = _get_sync_client().get(
            f"http://{ip}/mgr",
            params={"a": "sendsms", "sid": str(req.slot), "phone": phone, "content": content},
            auth=httpx.DigestAuth(user, pw),
            timeout=TIMEOUT + 3,
        )
        if resp.status_code == 200:
            try:
                body = resp.json()
                if isinstance(body, dict) and body.get("success") is True:
                    _audit("sms_send", detail=f"device={req.deviceId} slot={req.slot} phone={phone[:4]}***")
                    return {"ok": True}
                return {"ok": False, "error": "设备返回发送失败"}
            except Exception:
                return {"ok": False, "error": "设备返回异常"}
        return {"ok": False, "error": f"设备通信失败 (HTTP {resp.status_code})"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("sms send error device=%s: %s", req.deviceId, exc, exc_info=True)
        return {"ok": False, "error": "短信发送失败，请稍后重试"}


def wifi_task_sync(device_info: Dict[str, Any], ssid: str, pwd: str) -> Dict[str, Any]:
    ip   = device_info["ip"]
    user = device_info["user"]
    pw   = device_info["pw"]
    try:
        _ensure_device_ip_allowed(ip)
        ok, _ = istargetdevice(ip, user, pw)
        if not ok:
            return {"id": device_info["id"], "ip": ip, "ok": False, "error": "设备认证失败"}
        resp = _get_sync_client().get(
            f"http://{ip}/ap",
            params={"a": "apadd", "ssid": ssid, "pwd": pwd},
            auth=httpx.DigestAuth(user, pw),
            timeout=TIMEOUT + 5,
        )
        return {"id": device_info["id"], "ip": ip, "ok": resp.status_code == 200}
    except HTTPException as exc:
        return {"id": device_info["id"], "ip": ip, "ok": False, "error": exc.detail}
    except Exception as exc:
        logger.warning("wifi config %s failed: %s", ip, exc)
        return {"id": device_info["id"], "ip": ip, "ok": False, "error": "WiFi配置失败"}


def _device_conn_info(device: Device) -> Dict[str, Any]:
    return {
        "id": device.id,
        "ip": device.ip,
        "alias": device.alias or "",
        "grp": device.grp or "auto",
        "user": (device.user or DEFAULTUSER).strip(),
        "pw":   (device.passwd or DEFAULTPASS).strip(),
    }


# FIX(N7): real preview that actually fetches the current WiFi from each
# device (was a fake hardcoded "(待获取)" value that the frontend then forced
# operators to click through).
@app.post("/api/devices/batch/wifi/preview")
def api_batch_wifi_preview(req: BatchWifiReq, db: Session = Depends(get_db)):
    if not req.device_ids:
        raise HTTPException(status_code=400, detail="device_ids required")
    devices = db.query(Device).filter(Device.id.in_(req.device_ids)).all()
    infos = [_device_conn_info(d) for d in devices]
    if not infos:
        return {"results": [], "preview": True}

    def _preview(info: Dict[str, Any]) -> Dict[str, Any]:
        current = ""
        try:
            _ensure_device_ip_allowed(info["ip"])
            wifi = get_wifi_info(info["ip"], info["user"], info["pw"])
            current = wifi.get("wifiName", "")
        except HTTPException:
            current = ""
        except Exception:
            current = ""
        return {
            "id": info["id"],
            "ip": info["ip"],
            "alias": info["alias"],
            "grp":   info["grp"],
            "current_wifi": current or "(未知)",
            "new_wifi": req.ssid,
            "status": "preview",
        }

    executor = _get_shared_executor()
    results = list(executor.map(_preview, infos))
    return {"results": results, "preview": True}


@app.post("/api/devices/batch/wifi")
def api_batch_wifi(req: BatchWifiReq, db: Session = Depends(get_db)):
    if not req.device_ids:
        raise HTTPException(status_code=400, detail="device_ids required")
    devices = db.query(Device).filter(Device.id.in_(req.device_ids)).all()
    infos = [_device_conn_info(d) for d in devices]
    if not infos:
        return {"results": []}
    executor = _get_shared_executor()
    results = list(executor.map(lambda info: wifi_task_sync(info, req.ssid, req.pwd), infos))
    return {"results": results}


@app.post("/api/devices/{devid}/sim")
def api_set_sim(devid: int, req: SimReq, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == devid).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    ip   = device.ip
    _ensure_device_ip_allowed(ip)
    user = (device.user   or DEFAULTUSER).strip()
    pw   = (device.passwd or DEFAULTPASS).strip()
    try:
        resp = _get_sync_client().post(
            f"http://{ip}/mgr",
            params={"a": "updatePhnum"},
            data={"sim1Phnum": req.sim1, "sim2Phnum": req.sim2},
            auth=httpx.DigestAuth(user, pw),
            timeout=TIMEOUT + 5,
        )
        if resp.status_code == 200:
            device.sim1number = req.sim1
            device.sim2number = req.sim2
            db.commit()
            return {"ok": True}
        return {"ok": False, "status": resp.status_code}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("set sim error device=%s: %s", devid, exc, exc_info=True)
        return {"ok": False, "error": "SIM配置失败，请稍后重试"}


def sim_task_sync(device_info: Dict[str, Any], sim1: str, sim2: str) -> Dict[str, Any]:
    ip   = device_info["ip"]
    user = device_info["user"]
    pw   = device_info["pw"]
    try:
        _ensure_device_ip_allowed(ip)
        resp = _get_sync_client().post(
            f"http://{ip}/mgr",
            params={"a": "updatePhnum"},
            data={"sim1Phnum": sim1, "sim2Phnum": sim2},
            auth=httpx.DigestAuth(user, pw),
            timeout=TIMEOUT + 5,
        )
        return {"id": device_info["id"], "ip": ip, "ok": resp.status_code == 200}
    except HTTPException as exc:
        return {"id": device_info["id"], "ip": ip, "ok": False, "error": exc.detail}
    except Exception as exc:
        logger.warning("sim config %s failed: %s", ip, exc)
        return {"id": device_info["id"], "ip": ip, "ok": False, "error": "SIM配置失败"}


@app.post("/api/devices/batch/sim")
def api_batch_sim(req: BatchSimReq, db: Session = Depends(get_db)):
    if not req.device_ids:
        raise HTTPException(status_code=400, detail="device_ids required")
    devices = db.query(Device).filter(Device.id.in_(req.device_ids)).all()
    infos = [_device_conn_info(d) for d in devices]
    if not infos:
        return {"results": []}
    executor = _get_shared_executor()
    results = list(executor.map(lambda info: sim_task_sync(info, req.sim1, req.sim2), infos))
    for r in results:
        if r.get("ok"):
            dev = db.query(Device).filter(Device.id == r["id"]).first()
            if dev:
                dev.sim1number = req.sim1
                dev.sim2number = req.sim2
    db.commit()
    return {"results": results}


def enhanced_forward_task_sync(device_info: Dict[str, Any], req: EnhancedBatchForwardReq) -> Dict[str, Any]:
    ip   = device_info["ip"]
    user = device_info["user"]
    pw   = device_info["pw"]
    try:
        _ensure_device_ip_allowed(ip)
        ok, _ = istargetdevice(ip, user, pw)
        if not ok:
            return {"id": device_info["id"], "ip": ip, "ok": False, "error": "设备认证失败"}
        form: Dict[str, str] = {"method": req.forward_method}
        method = req.forward_method
        if method == "0":
            pass
        elif method in ("1", "2"):
            form.update(BARK_DEVICE_KEY0=req.deviceKey0, BARK_DEVICE_KEY1=req.deviceKey1, BARK_DEVICE_KEY2=req.deviceKey2)
        elif method == "8":
            form.update(SMTP_PROVIDER=req.smtpProvider, SMTP_SERVER=req.smtpServer, SMTP_PORT=req.smtpPort,
                        SMTP_ACCOUNT=req.smtpAccount, SMTP_PASSWORD=req.smtpPassword,
                        SMTP_FROM_EMAIL=req.smtpFromEmail, SMTP_TO_EMAIL=req.smtpToEmail, SMTP_ENCRYPTION=req.smtpEncryption)
        elif method in ("10", "11", "16"):
            form.update(WDF_CWH_URL1=req.webhookUrl1, WDF_CWH_URL2=req.webhookUrl2, WDF_CWH_URL3=req.webhookUrl3)
        elif method == "13":
            form.update(WDF_CWH_URL1=req.webhookUrl1, WDF_CWH_URL2=req.webhookUrl2, WDF_CWH_URL3=req.webhookUrl3,
                        WDF_SIGN_KEY1=req.signKey1, WDF_SIGN_KEY2=req.signKey2, WDF_SIGN_KEY3=req.signKey3)
        elif method == "21":
            form.update(SCT_SEND_KEY=req.sctSendKey)
        elif method == "22":
            form.update(SC3_URL=req.sc3ApiUrl)
        elif method == "30":
            form.update(PPToken=req.PPToken, PPChannel=req.PPChannel, PPWebhook=req.PPWebhook, PPFriends=req.PPFriends, PPGroupId=req.PPGroupId)
        elif method == "35":
            form.update(WPappToken=req.WPappToken, WPUID=req.WPUID, WPTopicId=req.WPTopicId)
        elif method == "90":
            form.update(LYWEB_API_URL=req.lyApiUrl)
        else:
            form.update(forwardUrl=req.forwardUrl, notifyUrl=req.notifyUrl)
        resp = _get_sync_client().post(
            f"http://{ip}/saveForwardConfig",
            data=form,
            auth=httpx.DigestAuth(user, pw),
            timeout=TIMEOUT + 5,
        )
        return {"id": device_info["id"], "ip": ip, "ok": resp.status_code == 200, "status": resp.status_code}
    except HTTPException as exc:
        return {"id": device_info["id"], "ip": ip, "ok": False, "error": exc.detail}
    except Exception as exc:
        logger.warning("forward config %s failed: %s", ip, exc)
        return {"id": device_info["id"], "ip": ip, "ok": False, "error": "转发配置失败"}


@app.post("/api/devices/batch/enhanced-forward")
def api_enhanced_batch_forward(req: EnhancedBatchForwardReq, db: Session = Depends(get_db)):
    if not req.device_ids:
        raise HTTPException(status_code=400, detail="device_ids required")
    devices = db.query(Device).filter(Device.id.in_(req.device_ids)).all()
    infos = [_device_conn_info(d) for d in devices]
    executor = _get_shared_executor()
    results = list(executor.map(lambda info: enhanced_forward_task_sync(info, req), infos))
    return {"results": results}


@app.post("/api/devices/batch/forward")
def api_batch_forward(req: BatchForwardReq, db: Session = Depends(get_db)):
    if not req.device_ids:
        raise HTTPException(status_code=400, detail="device_ids required")
    # FIX(P1#17): reuse enhanced backend with a named constant instead of the
    # bare "99" magic string.
    fake = EnhancedBatchForwardReq(
        device_ids=req.device_ids,
        forward_method=FORWARD_METHOD_BASIC,
        forwardUrl=req.forwardUrl,
        notifyUrl=req.notifyUrl,
    )
    devices = db.query(Device).filter(Device.id.in_(req.device_ids)).all()
    infos = [_device_conn_info(d) for d in devices]
    executor = _get_shared_executor()
    results = list(executor.map(lambda info: enhanced_forward_task_sync(info, fake), infos))
    return {"results": results}


# FIX(P1#8): user-supplied regex on /api/devices/batch/config/{preview,write}
# was previously evaluated by the stdlib `re` module which has no timeout,
# so a pathological pattern like (a+)+ on a 500 KB input could pin a worker
# thread for minutes and deadlock the shared executor. Use the third-party
# `regex` module (PyPI: regex) which supports a per-call timeout that aborts
# catastrophic backtracking with a TimeoutError.
import regex as _user_regex  # noqa: E402

REGEX_TIMEOUT = float(os.environ.get("BMUSERREGEXTIMEOUT", "1.0"))


def _apply_regex(config: str, pattern: str, replacement: str, flags_str: str) -> Optional[str]:
    try:
        flags = 0
        for f in flags_str.lower():
            if f == "i":
                flags |= _user_regex.IGNORECASE
            elif f == "m":
                flags |= _user_regex.MULTILINE
            elif f == "s":
                flags |= _user_regex.DOTALL
            elif f.strip():
                return None
        return _user_regex.sub(pattern, replacement, config, flags=flags, timeout=REGEX_TIMEOUT)
    except (_user_regex.error, TimeoutError):
        return None


def _config_main_json(content: str) -> Optional[Dict[str, Any]]:
    main_part = (content or "").split("~~--==~~--==", 1)[0].strip()
    if not main_part:
        return None
    try:
        parsed = json.loads(main_part)
    except Exception:
        return None
    if not isinstance(parsed, dict) or not parsed:
        return None
    return parsed


def _validate_config_content(original: str, replaced: str) -> Optional[str]:
    original_main = _config_main_json(original)
    replaced_main = _config_main_json(replaced)
    if original_main and replaced_main is None:
        return "替换后开头主配置 JSON 无效，已阻止写入"
    if original_main and "~~--==~~--==" in original and "~~--==~~--==" not in replaced:
        return "替换后消息模板分隔符丢失，已阻止写入"
    if replaced.strip() in ("{}", ""):
        return "替换结果为空配置，已阻止写入"
    if replaced_main is not None:
        required_keys = {"wps", "uip"}
        if not required_keys.issubset(replaced_main.keys()):
            return "替换后主配置缺少关键字段，已阻止写入"
    return None


CLEAN_MESSAGE_TEMPLATES = """~~--==~~--==
502
{
  "msgtype": "text",
  "text": {
    "content": "【短信外发成功】{{LN}}对方号码：{{phNum|$jsonEscape()}}{{LN}}短信内容：{{smsBd|$jsonEscape()}}{{LN}}发出时间：{{YMDHMS}}{{LN}}{{LN}}发出设备：{{{devName|$jsonEscape()}}}{{LN}}发出卡槽：{{msIsdn}}（卡{{slot}}）{{scName|$jsonEscape()}}"
  }
}
~~--==~~--==
603
{
  "msgtype": "text",
  "text": {
    "content": "【来电提醒】{{LN}}号码：{{phNum|$jsonEscape()}}{{LN}}通话时间：{{telStartTs|$ts2hhmmss(':')}} 至 {{telEndTs|$ts2hhmmss(':')}}{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：{{msIsdn}}（卡{{slot}}）{{scName|$jsonEscape()}}"
  }
}
~~--==~~--==
695
{
  "msgtype": "voice",
  "voice": { "media_id": "{{telMediaId}}" }
}
~~--==~~--==
501
{
  "msgtype": "text",
  "text": {
    "content": "{{smsBd|$jsonEscape()}}{{LN}}短信号码：{{phNum|$jsonEscape()}}{{LN}}短信时间：{{smsTs|$ts2yyyymmddhhmmss('-',':')}}{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：{{msIsdn}}（卡{{slot}}）{{scName|$jsonEscape()}}"
  }
}
~~--==~~--==
209
{
  "msgtype": "text",
  "text": {
    "content": "卡{{slot}}存在故障，请将卡放入手机检查原因！{{LN}}{{LN}}SIM卡信息：{{LN}}ICCID：{{iccId}}{{LN}}IMSI：{{imsi}}{{LN}}卡号：{{msIsdn}} {{scName|$jsonEscape()}}{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：卡{{slot}}"
  }
}
~~--==~~--==
205
{
  "msgtype": "text",
  "text": {
    "content": "卡{{slot}}已从设备中取出！{{LN}}{{LN}}SIM卡信息：{{LN}}ICCID：{{iccId}}{{LN}}IMSI：{{imsi}}{{LN}}卡号：{{msIsdn}} {{scName|$jsonEscape()}}{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：卡{{slot}}"
  }
}
~~--==~~--==
204
{
  "msgtype": "text",
  "text": {
    "content": "卡{{slot}}已就绪！{{LN}}{{LN}}SIM卡信息：{{LN}}ICCID：{{iccId}}{{LN}}IMSI：{{imsi}}{{LN}}卡号：{{msIsdn}} {{scName|$jsonEscape()}}{{LN}}信号强度：{{dbm}}%{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：卡{{slot}}"
  }
}
~~--==~~--==
102
{
  "msgtype": "text",
  "text": {
    "content": "【设备上线提醒】{{LN}}设备已通过 卡2 上线！{{LN}}{{LN}}SIM卡信息：{{LN}}ICCID：{{iccId}}{{LN}}IMSI：{{imsi}}{{LN}}卡号：{{msIsdn}} {{scName|$jsonEscape()}}{{LN}}信号强度：{{dbm}}%{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：卡{{slot}}"
  }
}
~~--==~~--==
101
{
  "msgtype": "text",
  "text": {
    "content": "【设备上线提醒】{{LN}}设备已通过 卡1 上线！{{LN}}{{LN}}SIM卡信息：{{LN}}ICCID：{{iccId}}{{LN}}IMSI：{{imsi}}{{LN}}卡号：{{msIsdn}} {{scName|$jsonEscape()}}{{LN}}信号强度：{{dbm}}%{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：卡{{slot}}"
  }
}
~~--==~~--==
100
{
  "msgtype": "text",
  "text": {
    "content": "【设备上线提醒】{{LN}}设备已通过 WiFi 上线！{{LN}}{{LN}}本机IP：{{ip}}{{LN}}WiFi热点：{{ssid|$jsonEscape()}}{{LN}}信号强度：{{dbm}}%{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}"
  }
}"""


def _apply_clean_message_template(config: str) -> Optional[str]:
    main = (config or "").split("~~--==~~--==", 1)[0].rstrip()
    if _config_main_json(main) is None:
        return None
    return f"{main}\n\n{CLEAN_MESSAGE_TEMPLATES}"


def config_read_task_sync(device_info: Dict[str, Any]) -> Dict[str, Any]:
    ip   = device_info["ip"]
    user = device_info["user"]
    pw   = device_info["pw"]
    try:
        config = read_device_config(ip, user, pw)
        if config is None:
            return {"id": device_info["id"], "ip": ip, "ok": False, "error": "读取配置失败"}
        return {"id": device_info["id"], "ip": ip, "ok": True, "config": config}
    except HTTPException as exc:
        return {"id": device_info["id"], "ip": ip, "ok": False, "error": exc.detail}
    except Exception as exc:
        return {"id": device_info["id"], "ip": ip, "ok": False, "error": str(exc)}


def config_preview_task_sync(device_info: Dict[str, Any], pattern: str, replacement: str, flags_str: str) -> Dict[str, Any]:
    result = config_read_task_sync(device_info)
    if not result.get("ok"):
        return result
    config = result.get("config", "")
    replaced = _apply_regex(config, pattern, replacement, flags_str)
    if replaced is None:
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "正则表达式或标志位无效"}
    return {
        "id": device_info["id"],
        "ip": device_info["ip"],
        "ok": True,
        "original": config,
        "replaced": replaced,
        "changed": config != replaced,
    }


def config_preset_preview_task_sync(device_info: Dict[str, Any], preset: str) -> Dict[str, Any]:
    result = config_read_task_sync(device_info)
    if not result.get("ok"):
        return result
    config = str(result.get("config", ""))
    if preset != "clean_message_templates":
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "未知配置预设"}
    replaced = _apply_clean_message_template(config)
    if replaced is None:
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "主配置 JSON 无效，不能应用预设"}
    return {
        "id": device_info["id"],
        "ip": device_info["ip"],
        "ok": True,
        "original": config,
        "replaced": replaced,
        "changed": config != replaced,
    }


def config_write_task_sync(device_info: Dict[str, Any], pattern: str, replacement: str, flags_str: str) -> Dict[str, Any]:
    preview = config_preview_task_sync(device_info, pattern, replacement, flags_str)
    if not preview.get("ok"):
        return preview
    if not preview.get("changed"):
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": True, "changed": False}
    replaced = str(preview.get("replaced", ""))
    original = str(preview.get("original", ""))
    validation_error = _validate_config_content(original, replaced)
    if validation_error:
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": validation_error}
    if not write_device_config(device_info["ip"], device_info["user"], device_info["pw"], replaced):
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "写入配置失败"}
    saved = read_device_config(device_info["ip"], device_info["user"], device_info["pw"])
    if saved is None:
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "写入后读取校验失败"}
    saved_error = _validate_config_content(original, saved)
    if saved_error:
        write_device_config(device_info["ip"], device_info["user"], device_info["pw"], original)
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": f"写入后校验失败，已尝试恢复原配置：{saved_error}"}
    _audit("config_write", detail=f"device={device_info['id']} ip={device_info['ip']}")
    return {"id": device_info["id"], "ip": device_info["ip"], "ok": True, "changed": True}


def config_preset_write_task_sync(device_info: Dict[str, Any], preset: str) -> Dict[str, Any]:
    preview = config_preset_preview_task_sync(device_info, preset)
    if not preview.get("ok"):
        return preview
    if not preview.get("changed"):
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": True, "changed": False}
    replaced = str(preview.get("replaced", ""))
    original = str(preview.get("original", ""))
    validation_error = _validate_config_content(original, replaced)
    if validation_error:
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": validation_error}
    if not write_device_config(device_info["ip"], device_info["user"], device_info["pw"], replaced):
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "写入配置失败"}
    saved = read_device_config(device_info["ip"], device_info["user"], device_info["pw"])
    if saved is None:
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "写入后读取校验失败"}
    saved_error = _validate_config_content(original, saved)
    if saved_error:
        write_device_config(device_info["ip"], device_info["user"], device_info["pw"], original)
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": f"写入后校验失败，已尝试恢复原配置：{saved_error}"}
    _audit("config_preset_write", detail=f"device={device_info['id']} ip={device_info['ip']} preset={preset}")
    return {"id": device_info["id"], "ip": device_info["ip"], "ok": True, "changed": True}


def _validate_config_regex(pattern: str, replacement: str) -> None:
    if not pattern:
        raise HTTPException(status_code=400, detail="正则表达式不能为空")
    if len(pattern) > 10000:
        raise HTTPException(status_code=400, detail="正则表达式过长")
    if len(replacement) > CONFIG_MAX_CHARS:
        raise HTTPException(status_code=400, detail="替换内容过长")


def _check_config_device_ids(device_ids: List[int]) -> None:
    if not device_ids:
        raise HTTPException(status_code=400, detail="device_ids required")
    if len(device_ids) > OTA_BATCH_MAX:
        raise HTTPException(status_code=400, detail=f"单次批量配置不得超过 {OTA_BATCH_MAX} 台")


@app.post("/api/devices/batch/config/read")
def api_batch_config_read(req: BatchConfigReadReq, db: Session = Depends(get_db)):
    _check_config_device_ids(req.device_ids)
    devices = db.query(Device).filter(Device.id.in_(req.device_ids)).all()
    infos = [_device_conn_info(d) for d in devices]
    executor = _get_shared_executor()
    configs = list(executor.map(config_read_task_sync, infos))
    return {"configs": configs}


@app.post("/api/devices/batch/config/preview")
def api_batch_config_preview(req: BatchConfigPreviewReq, db: Session = Depends(get_db)):
    _validate_config_regex(req.pattern, req.replacement)
    _check_config_device_ids(req.device_ids)
    devices = db.query(Device).filter(Device.id.in_(req.device_ids)).all()
    infos = [_device_conn_info(d) for d in devices]
    executor = _get_shared_executor()
    previews = list(executor.map(lambda info: config_preview_task_sync(info, req.pattern, req.replacement, req.flags), infos))
    return {"previews": previews}


@app.post("/api/devices/batch/config/preset/preview")
def api_batch_config_preset_preview(req: BatchConfigPresetReq, db: Session = Depends(get_db)):
    _check_config_device_ids(req.device_ids)
    devices = db.query(Device).filter(Device.id.in_(req.device_ids)).all()
    infos = [_device_conn_info(d) for d in devices]
    executor = _get_shared_executor()
    previews = list(executor.map(lambda info: config_preset_preview_task_sync(info, req.preset), infos))
    return {"previews": previews}


@app.post("/api/devices/batch/config/write")
def api_batch_config_write(req: BatchConfigWriteReq, db: Session = Depends(get_db)):
    _validate_config_regex(req.pattern, req.replacement)
    _check_config_device_ids(req.device_ids)
    devices = db.query(Device).filter(Device.id.in_(req.device_ids)).all()
    infos = [_device_conn_info(d) for d in devices]
    _audit("batch_config_write", detail=f"count={len(infos)} pattern_len={len(req.pattern)}")
    executor = _get_shared_executor()
    results = list(executor.map(lambda info: config_write_task_sync(info, req.pattern, req.replacement, req.flags), infos))
    return {"results": results}


@app.post("/api/devices/batch/config/preset/write")
def api_batch_config_preset_write(req: BatchConfigPresetReq, db: Session = Depends(get_db)):
    _check_config_device_ids(req.device_ids)
    devices = db.query(Device).filter(Device.id.in_(req.device_ids)).all()
    infos = [_device_conn_info(d) for d in devices]
    _audit("batch_config_preset_write", detail=f"count={len(infos)} preset={req.preset}")
    executor = _get_shared_executor()
    results = list(executor.map(lambda info: config_preset_write_task_sync(info, req.preset), infos))
    return {"results": results}


def _get_timeout_default() -> int:
    return int(TIMEOUT)


def fetch_device_token(ip: str, user: str, pw: str) -> str:
    _ensure_device_ip_allowed(ip)
    body = b"keys=%7B%22keys%22%3A%5B%22TOKEN%22%5D%7D"
    resp = _get_sync_client().post(
        f"http://{ip}/mgr",
        params={"a": "getHtmlData_passwdMgr"},
        content=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        auth=httpx.DigestAuth(user, pw),
        timeout=_get_timeout_default() + 5,
    )
    resp.raise_for_status()
    payload = resp.json()
    token = (payload.get("data", {}) or {}).get("TOKEN", "") or ""
    return re.sub(r"<[^>]+>", "", str(token)).strip()


def ensure_device_token(db: Session, device: Device) -> str:
    token = (getattr(device, "token", "") or "").strip()
    if token:
        return token
    user = (getattr(device, "user",   "") or DEFAULTUSER).strip()
    pw   = (getattr(device, "passwd", "") or DEFAULTPASS).strip()
    _ensure_device_ip_allowed(device.ip)
    ok, _ = istargetdevice(device.ip, user, pw)
    if not ok:
        raise HTTPException(status_code=400, detail="Device authentication failed")
    token = fetch_device_token(device.ip, user, pw)
    if not token:
        raise HTTPException(status_code=400, detail="Failed to fetch token")
    try:
        device.token = token
        db.commit()
    except Exception:
        pass
    return token


@app.post("/api/tel/dial")
def tel_dial(req: DirectDialReq, db: Session = Depends(get_db)):
    if req.slot not in (1, 2):
        raise HTTPException(status_code=400, detail="slot must be 1 or 2")
    phone  = _validate_phone(req.phone)
    rl_key = f"dial:{req.deviceId}"
    if not _dial_limiter.allow(rl_key):
        raise HTTPException(status_code=429, detail="拨号过于频繁，请稍后再试")
    device = db.query(Device).filter(Device.id == req.deviceId).first()
    if not device:
        raise HTTPException(status_code=404, detail="设备不存在")
    _ensure_device_ip_allowed(device.ip)
    token   = ensure_device_token(db, device)
    timeout = _get_timeout_default()
    params  = {
        "token": token, "cmd": "teldial",
        "p1": str(req.slot), "p2": phone,
        "p3": str(max(10, int(req.duration or 175))),
        "p4": (req.tts or "").strip(),
        "p5": str(max(0, int(req.tts_times or 0))),
        "p6": str(max(0, int(req.tts_pause or 0))),
        "p7": str(int(req.after_action or 0)),
    }
    try:
        resp = _get_sync_client().get(f"http://{device.ip}/ctrl", params=params, timeout=timeout + 8)
        try:
            payload = resp.json()
        except Exception:
            payload = {"raw": resp.text}
        if resp.status_code == 200 and isinstance(payload, dict) and payload.get("code", 0) == 0:
            _audit("tel_dial", detail=f"device={req.deviceId} slot={req.slot} phone={phone[:4]}***")
            return {"ok": True, "resp": payload}
        return {"ok": False, "error": "设备返回拨号失败"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("dial error device=%s: %s", req.deviceId, exc, exc_info=True)
        return {"ok": False, "error": "拨号失败，请稍后重试"}


# ── OTA 批量升级 ──────────────────────────────────────────────────────────────

class BatchOtaReq(BaseModel):
    device_ids: List[int]


def _ota_check(ip: str, user: str, pw: str) -> Dict[str, Any]:
    """Raw OTA version check used by both `check` and `upgrade` flows."""
    _ensure_device_ip_allowed(ip)
    resp = _get_sync_client().get(
        f"http://{ip}/ota",
        params={"a": "chkNewVer"},
        auth=httpx.DigestAuth(user, pw),
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json() if resp.content else {}
    return data if isinstance(data, dict) else {}


# FIX(N3+N4): each worker opens its own Session (SQLAlchemy Session is not
# thread-safe); store the reported version in firmware_version instead of
# overwriting the device's stable identifier devId.
def check_ota_task(device_id: int) -> Dict[str, Any]:
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return {"id": device_id, "ok": False, "error": "设备不存在"}
        ip   = device.ip
        user = (device.user   or DEFAULTUSER).strip()
        pw   = (device.passwd or DEFAULTPASS).strip()
        try:
            data = _ota_check(ip, user, pw)
        except HTTPException as exc:
            return {"id": device.id, "ip": ip, "ok": False, "error": exc.detail}
        except Exception as exc:
            return {"id": device.id, "ip": ip, "ok": False, "error": str(exc)}
        cur_ver = str(data.get("curVer", "") or "")
        new_ver = str(data.get("newVer", "") or "")
        if cur_ver:
            device.firmware_version = cur_ver
            try:
                db.commit()
            except Exception:
                db.rollback()
        return {
            "id":         device.id,
            "ip":         ip,
            "ok":         True,
            "hasUpdate":  bool(data.get("hasUpdate", False)) or (bool(new_ver) and new_ver != cur_ver),
            "currentVer": cur_ver,
            "newVer":     new_ver,
        }
    finally:
        db.close()


# FIX(N6): only call chkNewVer once per device. If the caller already has the
# newVer from a prior check, the check phase here can be used directly for the
# decision. We intentionally do not re-query if the cached device row already
# has a known firmware_version and the caller didn't force a recheck.
def upgrade_ota_task(device_id: int) -> Dict[str, Any]:
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return {"id": device_id, "ok": False, "error": "设备不存在"}
        ip   = device.ip
        user = (device.user   or DEFAULTUSER).strip()
        pw   = (device.passwd or DEFAULTPASS).strip()
        try:
            data    = _ota_check(ip, user, pw)
            cur_ver = str(data.get("curVer", "") or "")
            new_ver = str(data.get("newVer", "") or "")
            if cur_ver:
                device.firmware_version = cur_ver
                try:
                    db.commit()
                except Exception:
                    db.rollback()
            if not new_ver or new_ver == cur_ver:
                return {"id": device.id, "ip": ip, "ok": False, "error": "已是最新版本"}
            upgrade_resp = _get_sync_client().get(
                f"http://{ip}/ota",
                params={"a": "updOtaOnline"},
                auth=httpx.DigestAuth(user, pw),
                timeout=TIMEOUT,
            )
            return {
                "id":     device.id,
                "ip":     ip,
                "ok":     upgrade_resp.status_code == 200,
                "newVer": new_ver,
            }
        except HTTPException as exc:
            return {"id": device.id, "ip": ip, "ok": False, "error": exc.detail}
        except Exception as exc:
            return {"id": device.id, "ip": ip, "ok": False, "error": str(exc)}
    finally:
        db.close()


def _check_ota_batch_allowed(request: Request, device_ids: List[int]) -> None:
    if not device_ids:
        raise HTTPException(status_code=400, detail="device_ids required")
    if len(device_ids) > OTA_BATCH_MAX:
        raise HTTPException(status_code=400, detail=f"单次 OTA 批量不得超过 {OTA_BATCH_MAX} 台")
    # FIX(N5): per-caller rate limit so OTA can't be weaponised as a reboot storm.
    key = f"ota:{_client_ip(request)}"
    if not _ota_limiter.allow(key):
        raise HTTPException(status_code=429, detail="OTA 操作过于频繁，请稍后再试")


@app.post("/api/devices/batch/ota/check")
def api_batch_ota_check(req: BatchOtaReq, request: Request, db: Session = Depends(get_db)):
    _check_ota_batch_allowed(request, req.device_ids)
    existing_ids = [row.id for row in db.query(Device.id).filter(Device.id.in_(req.device_ids)).all()]
    executor = _get_shared_executor()
    results = list(executor.map(check_ota_task, existing_ids))
    return {"results": results}


@app.post("/api/devices/batch/ota/upgrade")
def api_batch_ota_upgrade(req: BatchOtaReq, request: Request, db: Session = Depends(get_db)):
    _check_ota_batch_allowed(request, req.device_ids)
    existing_ids = [row.id for row in db.query(Device.id).filter(Device.id.in_(req.device_ids)).all()]
    executor = _get_shared_executor()
    results = list(executor.map(upgrade_ota_task, existing_ids))
    _audit("ota_upgrade", detail=f"count={len(existing_ids)} ips={[r.get('ip') for r in results]}")
    return {"results": results}
