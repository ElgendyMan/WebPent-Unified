# src/webpent/api/app.py
"""webpent.api.app

FastAPI application exposing the WebPent Framework V3 as a backend
service with HITL approval, auto_approve bypass, and status monitoring.

Endpoints:
  * ``POST /api/v1/scans`` — trigger a new pentest engagement.
  * ``GET /api/v1/scans/{thread_id}/status`` — check engagement status.
  * ``POST /api/v1/scans/{thread_id}/approve`` — approve a paused engagement.
  * ``GET /api/v1/scans/{thread_id}/findings`` — retrieve persisted findings.
  * ``GET/POST /api/oob/{finding_id}/{secret}`` — V5 Sprint 5 OOB callback
    receiver used to confirm SSRF/RCE findings whose exploitation causes
    the target to call back to this framework instance.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, field_validator

from webpent.api.auth import (
    User,
    get_current_user,
    login_for_access_token,
    require_role,
)
from webpent.api.rate_limit import RateLimiter
from webpent.api.scan_registry import (
    claim_resume_capability,
    get_thread_ids_by_engagement_id,
    release_resume_claim,
    scan_registry_health,
    update_scan_status,
)
from webpent.config.settings import activate_settings, get_settings
from webpent.graph.builder import NODE_EXECUTION_SANDBOX, build_graph
from webpent.graph.checkpoints import get_checkpointer
from webpent.memory.db import get_db_manager
from webpent.models.findings import Finding
from webpent.production.autonomous_recon import run_autonomous_recon_campaign
from webpent.production.product_layer import estimate_campaign_cost, render_campaign_dashboard
from webpent.recon.autonomous_crawler import CrawlConfig
from webpent.reporter.bounty_report import generate_bounty_reports
from webpent.scope import GLOBAL_SCOPE_REGISTRY, ScopeEnforcer, parse_scope_text
from webpent.shared.action_ledger import SQLiteActionLedger
from webpent.shared.engagement_scope import (
    admission_target_check,  # F-06 (0.33.0)
    normalize_declared_origins,
)
from webpent.shared.finding_aggregation import aggregate_findings, default_engagement_id
from webpent.shared.package_execution_intake import (
    PackageExecutionIntakeError,
    ensure_package_request_fields,
    validate_package_for_dispatch,
)
from webpent.shared.persistent_finding_ledger import PersistentFindingLedger
from webpent.shared.preflight import run_startup_preflight
from webpent.shared.resume_capability import issue_resume_capability
from webpent.shared.target_workspace import TargetWorkspace, build_target_workspace
from webpent.shared.target_workspace_context import activate_target_workspace
from webpent.workers.pentest_worker import resume_pentest_task, run_pentest_task

logger = logging.getLogger(__name__)

# R3 E-1 (Ruling R3-002 §3.2): the OOB confirmation payload marker was
# removed together with the seal-and-confirm behavior. The demoted
# callback path writes authority-neutral advisory records only and never
# tags the finding payload with confirmation markers (T-04 contract).

# Hard ceiling on the size of an OOB callback body. The endpoint records
# a short digest of the body into the reasoning trail; large payloads are
# truncated to prevent a malicious target from blowing up the DB row.
_OOB_BODY_MAX_BYTES = 4_096
_OOB_BODY_DIGEST_LEN = 256

app = FastAPI(
    title="WebPent Framework V5 API",
    description=(
        "Autonomous web application pentesting backend with HITL approval, "
        "auto_approve bypass, Multi-Agent Systems, LangGraph orchestration, "
        "JWT authentication, RBAC, and rate limiting."
    ),
    version="1.0.0",
)

# Additive product service routes. The existing trust-chain routes and
# promotion pipeline remain the authority for execution and findings. Add the
# already-prefixed routes directly so every app route retains the standard
# FastAPI route shape expected by existing governance tests.
from webpent.service.api import router as multi_campaign_service_router

app.router.routes.extend(multi_campaign_service_router.routes)

# ULTIMATE PLAN 2026-10-27, proposal 9: the workers monitoring router
# (GET /api/v1/workers/status + /health). Read-only, self-contained,
# honest when the broker is unavailable (available:false, HTTP 200) —
# monitoring must never crash the API. Same additive include pattern.
from webpent.api.workers_status import router as workers_status_router

app.router.routes.extend(workers_status_router.routes)


class ScopeLoadRequest(BaseModel):
    engagement_id: str = Field(..., min_length=1, max_length=128)
    content: str = Field(..., min_length=1, max_length=1_000_000)


@app.post("/api/v1/scope/load")
def load_program_scope(
    request: ScopeLoadRequest,
    user: User = Depends(require_role("admin", "service")),  # noqa: B008
) -> dict[str, Any]:
    """Compile and register a redacted operator program-scope policy."""
    try:
        policy = parse_scope_text(request.content, source=f"api:{user.username}")
        GLOBAL_SCOPE_REGISTRY.load(policy, engagement_id=request.engagement_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="invalid scope policy") from exc
    return {"engagement_id": request.engagement_id, "policy": policy.as_dict()}


@app.get("/api/v1/scope")
def list_program_scopes(
    user: User = Depends(require_role("admin", "service")),  # noqa: B008
) -> dict[str, Any]:
    """Return only redacted active program-scope policies."""
    return {"scopes": GLOBAL_SCOPE_REGISTRY.redacted()}


@app.get("/api/v1/scope/check")
def check_program_scope(
    engagement_id: str,
    url: str,
    method: str = "GET",
    user: User = Depends(require_role("admin", "service")),  # noqa: B008
) -> dict[str, Any]:
    policy = GLOBAL_SCOPE_REGISTRY.get(engagement_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="scope policy not loaded")
    return ScopeEnforcer(policy).check_url(url, method=method).as_dict()


@app.delete("/api/v1/scope/{engagement_id}")
def clear_program_scope(
    engagement_id: str,
    user: User = Depends(require_role("admin", "service")),  # noqa: B008
) -> dict[str, Any]:
    return {"engagement_id": engagement_id, "cleared": GLOBAL_SCOPE_REGISTRY.clear(engagement_id)}

# ===========================================================================
# V5 Sprint 13/14: CORS Middleware
# ===========================================================================
_settings = get_settings()

# V5 Sprint 14 P1: CORS Misconfiguration Remediation.
# If cors_origins contains "*" (wildcard), we CANNOT allow credentials
# — browsers reject this combination. We either:
#   1. Disable credentials when wildcard is used (permissive but safe).
#   2. Log a WARNING so the operator knows to set explicit origins.
_cors_origins = _settings.cors_origins
_cors_allow_credentials = True
if "*" in _cors_origins:
    _cors_allow_credentials = False
    logger.warning(
        "CORS Misconfiguration Remediation: cors_origins contains '*' "
        "(wildcard). allow_credentials has been DISABLED to comply with "
        "the CORS spec (browsers reject credentials with wildcard origins). "
        "For production, set WEBPENT_CORS_ORIGINS to explicit origins: "
        "['https://app.example.com']"
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===========================================================================
# V9 FIX-5: Module-level graph cache to avoid rebuilding on every status poll.
# ===========================================================================
_GRAPH_CACHE: dict[str, Any] = {}
# V10 AUDIT FIX (H5): threading lock to protect the _GRAPH_CACHE dict
# and the .checkpointer reassignment from concurrent status-poll
# requests. FastAPI runs sync def endpoints in a threadpool, so two
# concurrent get_scan_status requests can race on the check-then-set
# pattern below — double build_graph, or thread A reading thread B's
# checkpointer (which B closes on with-exit) before A calls get_state.
_GRAPH_CACHE_LOCK = threading.Lock()


def _get_cached_graph(checkpointer: Any) -> Any:
    """Return a cached compiled graph, rebuilding only if auto_approve changed.

    V9 HOSTILE-AUDIT FIX (FIX-5 regression): the original version cached
    the graph object returned by ``build_graph(checkpointer=checkpointer)``
    on the FIRST call and reused it forever, silently ignoring the
    ``checkpointer`` argument on every subsequent call. Every caller
    (``_get_graph_status``) opens its checkpointer via
    ``with get_checkpointer() as checkpointer:`` — a fresh, per-request
    connection that is CLOSED when that ``with`` block exits. Because the
    cached graph kept a permanent reference to the first request's
    (now-closed) checkpointer, every status poll after the first raised
    ``sqlite3.ProgrammingError: Cannot operate on a closed database``,
    which the outer handler silently caught and reported as
    ``{"status": "error"}`` for the remaining lifetime of the worker
    process — i.e. this "fix" broke status polling after exactly one
    call.

    Fix: still build (and cache) the compiled graph TOPOLOGY only once —
    that is the expensive part FIX-5 was trying to avoid rebuilding —
    but rebind the cheap ``.checkpointer`` attribute to the CURRENT,
    live checkpointer on every call, cache hit or not. Verified against
    langgraph 1.2.10 / langgraph-checkpoint-sqlite 3.1.1: a compiled
    ``CompiledStateGraph`` exposes ``.checkpointer`` as a plain, settable
    attribute that ``get_state``/``invoke`` read at call time, so this
    reassignment is honored correctly. Re-verify this attribute name
    against whatever langgraph version this project's environment
    actually resolves (pyproject.toml only pins ``>=0.2.0``) before
    relying on it in production.

    V10 AUDIT FIX (H5): the cache dict and .checkpointer reassignment
    are now protected by ``_GRAPH_CACHE_LOCK`` to prevent the
    check-then-set race between concurrent status-poll requests.
    """
    key = "default"  # auto_approve doesn't change at runtime
    with _GRAPH_CACHE_LOCK:
        if key not in _GRAPH_CACHE:
            _GRAPH_CACHE[key] = build_graph(checkpointer=checkpointer)
        else:
            _GRAPH_CACHE[key].checkpointer = checkpointer
        return _GRAPH_CACHE[key]


def _effective_scan_client_id(requested_client_id: str | None, user: User) -> str:
    """Return the client scope allowed for a newly-created scan."""
    requested = (requested_client_id or "").strip()
    if user.role == "admin" and not user.is_global_admin:
        if not user.tenant_id:
            raise HTTPException(status_code=403, detail="Admin tenant scope is not configured")
        if requested and requested != user.tenant_id:
            raise HTTPException(status_code=403, detail="Scan client is outside your tenant")
        return user.tenant_id
    return requested


def _persisted_finding_count(thread_id: str) -> int | None:
    """POST-P0 Phase 9: best-effort count of persisted findings for a thread.

    Returns ``None`` when persistence state cannot be verified (e.g. no
    workspace context) — callers must treat that as "unverified", not as
    zero.
    """
    try:
        from webpent.memory.db import get_db_manager

        db = get_db_manager()
        return len(db.get_findings_by_thread(thread_id) or [])
    except Exception:
        return None


def _authorize_scan_resource(thread_id: str, user: User) -> dict[str, Any]:
    """Authorize access to a scan resource by ownership and tenant scope.

    Administrators retain global visibility. Every other authenticated caller
    must match the registry owner exactly; missing registry metadata is treated
    as not found so legacy or partially-created scans cannot become an
    unscoped data-access path.
    """
    from webpent.api.scan_registry import get_scan_record

    record = get_scan_record(thread_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if user.role == "admin":
        if user.is_global_admin:
            return record
        client_id = str(record.get("client_id") or "")
        if not user.tenant_id or not client_id or client_id != user.tenant_id:
            raise HTTPException(status_code=404, detail="Scan not found")
        return record

    owner = str(record.get("owner_username") or "")
    if not owner or owner != user.username:
        # Do not disclose whether another user's thread_id exists.
        raise HTTPException(status_code=404, detail="Scan not found")

    client_id = str(record.get("client_id") or "")
    engagement_id = str(record.get("engagement_id") or "")
    if not engagement_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    if client_id and any(char in client_id for char in "\r\n"):
        raise HTTPException(status_code=404, detail="Scan not found")

    return record


def _workspace_for_record(record: dict[str, Any]) -> TargetWorkspace:
    """Build the isolated storage namespace for an authorized scan record."""
    return build_target_workspace(
        get_settings(),
        target_origin=record["target_url"],
        client_id=str(record.get("client_id") or ""),
        engagement_id=record["engagement_id"],
    ).ensure()


def _settings_for_workspace(workspace: TargetWorkspace) -> Any:
    """Return a Settings copy with only workspace storage paths overridden."""
    return get_settings().model_copy(update=workspace.settings_overrides())


# ===========================================================================
# V5 Sprint 13: Rate Limiter Middleware
# ===========================================================================
_rate_limiter = RateLimiter(
    enabled=_settings.rate_limit_enabled,
    global_per_minute=_settings.rate_limit_global_per_minute,
    scan_per_minute=_settings.rate_limit_scan_per_minute,
    redis_url=_settings.rate_limit_redis_url,
    login_per_minute=_settings.rate_limit_login_per_minute,
)

# ===========================================================================
# V10 P0-0 AUDIT FIX (C1): initialize the scan_engagements registry table
# at import time so register_scan / lookup_task_id work in production.
# Previously init_scan_registry() was defined but NEVER called from app
# startup — the table didn't exist, every register_scan INSERT failed
# silently, lookup_task_id always returned None, and the entire
# AsyncResult cross-check was dead code.
# ===========================================================================
try:
    from webpent.api.scan_registry import init_scan_registry as _init_scan_registry

    _registry_ready = _init_scan_registry()
    if not _registry_ready:
        logger.error("scan_registry is not ready; ownership/status paths will fail closed")
except Exception as _registry_init_exc:
    logger.error(
        "scan_registry init failed at app startup; ownership/status paths will fail closed: %s",
        _registry_init_exc,
    )

# V10 P0-1/P0-3: startup capability preflight. Emits an INFO-level
# capability report and fail-closes an explicitly public bind with the
# insecure API quartet unless the operator acknowledges the lab override.
run_startup_preflight(host=os.getenv("WEBPENT_API_HOST"))


# ===========================================================================
# RESIDUAL CLOSURE 2026-10-29 (Track 9.5 residual): the stalled-worker
# alert existed only as a helper nothing called on a schedule — the
# roadmap wanted "تنبيه تشغيلي عند التعثر" wired for real. This loop
# polls the real /workers status view on an operator-chosen interval
# (WEBPENT_WORKER_ALERT_INTERVAL_S, seconds; 0/default = DISABLED — the
# repo's consistent opt-in posture) and emits the log-based alerts via
# check_stalled_and_alert. Monitoring only: it never mutates campaign
# state, never sends network traffic beyond the local broker inspect,
# and every failure is swallowed into a log line so monitoring can
# never kill the API.
# ===========================================================================
def _start_stalled_worker_alert_loop() -> None:
    import threading
    import time as _time

    from webpent.workers.monitor_alerts import check_stalled_and_alert

    raw = os.getenv("WEBPENT_WORKER_ALERT_INTERVAL_S", "0").strip()
    try:
        interval = max(0, int(float(raw)))
    except ValueError:
        interval = 0
    if interval <= 0:

        def _disabled() -> None:
            return None

        return _disabled()

    def _loop() -> None:
        while True:
            try:
                from webpent.api.workers_status import workers_status

                status = workers_status()
                alerts = check_stalled_and_alert(status)
                if alerts:
                    logger.warning(
                        "stalled-worker monitor emitted %d alert(s)", len(alerts)
                    )
            except Exception:  # monitoring must never break the API
                logger.debug("stalled-worker monitor cycle failed", exc_info=True)
            _time.sleep(interval)

    thread = threading.Thread(target=_loop, name="worker-stall-alerts", daemon=True)
    thread.start()


_start_stalled_worker_alert_loop()


def _extract_trusted_client_ip(request: Request, trusted_ips: list[str]) -> str:
    """V6 DX-Final P1: Shared trusted-proxy IP extraction.

    Returns the real client IP address, honoring ``X-Forwarded-For``
    and ``X-Real-IP`` headers **only** when the direct TCP peer is in
    ``trusted_ips``. This closes a regression in ``start_scan`` that
    allowed any client to spoof its IP via the ``X-Forwarded-For``
    header and bypass the per-IP scan rate limit.

    The same logic was originally implemented inline in
    ``rate_limit_middleware``. It is now extracted into this helper
    so the middleware and ``start_scan`` cannot drift out of sync.

    V6 DX-Final P1 FIX (CISO audit): The previous implementation read
    the **leftmost** ``X-Forwarded-For`` entry, which is fully
    attacker-controlled — any client could prepend an arbitrary IP
    to the header to spoof its identity and bypass per-IP rate
    limiting. The corrected implementation iterates the XFF chain
    **right-to-left**, skipping every entry that belongs to a
    configured trusted proxy. The first non-trusted IP encountered
    from the right is the authentic client IP. If every entry is a
    trusted proxy (unusual but valid for multi-hop reverse-proxy
    chains), we fall back to ``xff_entries[0]`` to preserve the
    original-client semantics for fully-trusted chains.

    Args:
        request: The incoming FastAPI ``Request``.
        trusted_ips: List of CIDR strings (e.g. ``["10.0.0.0/8"]``)
            representing reverse proxies whose ``X-Forwarded-For``
            header is trusted. An empty list disables header trust
            entirely (every request is attributed to its TCP peer).

    Returns:
        The client IP string to use for rate-limit keying. Falls back
        to the direct TCP peer (or ``"unknown"``) when no trusted
        proxy is in the loop or the headers are absent.
    """
    import ipaddress

    direct_ip = request.client.host if request.client else "unknown"

    if not trusted_ips:
        # No trusted proxies configured — never trust forwarded headers.
        return direct_ip

    def _is_trusted(ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in ipaddress.ip_network(cidr, strict=False) for cidr in trusted_ips)
        except (ValueError, TypeError):
            return False

    # Check if the direct connection is from a trusted proxy.
    if not _is_trusted(direct_ip):
        # Direct client is not a trusted proxy — use the TCP peer IP
        # verbatim. This prevents spoofing via X-Forwarded-For.
        return direct_ip

    # Build the XFF chain. ``X-Forwarded-For`` is comma-separated,
    # left-to-right = original client → ... → closest proxy. The
    # rightmost entry is the proxy that actually handed the request
    # to us (i.e. ``direct_ip``); we walk left from there.
    raw_xff = request.headers.get("X-Forwarded-For", "")
    xff_entries = [e.strip() for e in raw_xff.split(",") if e.strip()] if raw_xff else []

    if xff_entries:
        # Walk right-to-left, skipping trusted-proxy hops. The first
        # non-trusted entry is the authentic client IP.
        for entry in reversed(xff_entries):
            if not _is_trusted(entry):
                return entry
        # All entries are trusted proxies — this happens when the
        # entire chain consists of our own reverse proxies (e.g.
        # cloud LB → nginx → app). Fall back to the leftmost entry,
        # which is the original client as seen by the first proxy.
        return xff_entries[0]

    # Fallback to X-Real-IP if X-Forwarded-For is absent (some proxies
    # only set X-Real-IP).
    xri = request.headers.get("X-Real-IP", "").strip()
    if xri:
        return xri

    # Trusted proxy but no forwarded headers — fall back to the TCP peer.
    return direct_ip


async def security_headers_middleware(request, call_next):
    """Defensive response headers, always; HSTS only over TLS.

    The HSTS signal is the PROXY's own X-Forwarded-Proto: a plain-HTTP
    hop must not receive an HSTS header (it would be ignored by
    conformant clients and misleading to operators). CSP sets
    default-src 'self' without clobbering an already-present policy.

    UNIFIED MERGE (2026-11-02, Phase 2): restored per
    tests/test_r4_production_hardening.py (TestSecurityHeadersMiddleware).
    """
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    csp = response.headers.get("Content-Security-Policy", "")
    if "default-src 'self'" not in csp:
        response.headers["Content-Security-Policy"] = (
            f"{csp}; default-src 'self'" if csp else "default-src 'self'"
        )
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").lower()
    if forwarded_proto == "https" and (
        "Strict-Transport-Security" not in response.headers
    ):
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


@app.middleware("http")
async def reject_tunneled_requests_when_auth_disabled(request: Request, call_next):
    """M1-A (H-1, 2026-11-05): fail-closed against tunnel/proxy exposure.

    ``auth_enabled=False`` is only safe for DIRECT loopback connections.
    A request that arrives carrying proxy/tunnel indicators (the headers
    cloudflared and reverse proxies add) proves the API is reachable
    through something other than a local bind — exactly the deployment
    the preflight bind check tried to prevent, defeated by tunneling a
    loopback service. Reject it with 401 while auth is off.

    Exemptions:
      * ``/api/oob/*`` — OOB callback endpoints are unauthenticated BY
        DESIGN with their own compensating controls (32-hex token,
        constant-time compare, 64KB cap, advisory-only evidence). The
        tunnel exists FOR these callbacks.
      * ``auth_enabled=True`` — proxied deployments with authentication
        are legitimate; the middleware is a no-op.

    Direct local requests (no proxy headers) are unaffected — local dev
    flow unchanged.
    """
    if _settings.auth_enabled:
        return await call_next(request)

    path = request.url.path
    if path.startswith("/api/oob"):
        return await call_next(request)

    tunnel_indicators = (
        "x-forwarded-host",
        "x-forwarded-for",
        "cf-ray",
        "cf-visitor",
        "cf-connecting-ip",
        "x-real-ip",
    )
    if any(request.headers.get(header) for header in tunnel_indicators):
        return Response(
            content=(
                '{"detail":"API is running with authentication disabled; '
                'requests arriving via a proxy/tunnel are refused. Enable '
                'AUTH_ENABLED=true with real secrets to expose the API '
                'through a proxy (M1-A/H-1)."}'
            ),
            status_code=401,
            media_type="application/json",
        )
    return await call_next(request)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """V6.1: Enforce per-IP rate limits with trusted-proxy awareness.

    V6.1 P1: Only trusts X-Forwarded-For if request.client.host is in
    settings.trusted_proxy_ips. Prevents spoofing by direct clients.

    V6 DX-Final P1: Now uses the shared ``_extract_trusted_client_ip``
    helper so the middleware and ``start_scan`` cannot drift out of
    sync (the original cause of the regression).
    """
    if not _settings.rate_limit_enabled:
        return await call_next(request)

    client_ip = _extract_trusted_client_ip(request, _settings.trusted_proxy_ips)

    if not _rate_limiter.check_global(client_ip):
        return Response(
            content='{"detail":"Rate limit exceeded (global). Try again later."}',
            status_code=429,
            media_type="application/json",
            headers={"Retry-After": "60"},
        )
    response = await call_next(request)
    return response


class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL (must include http:// or https://).")
    # F-06 (0.33.0): server-side admission gate — private/loopback target
    # literals require explicit operator confirmation; link-local
    # (169.254.0.0/16, fe80::/10) is refused unconditionally.
    allow_private_target: bool = Field(
        default=False,
        description=(
            "Operator confirmation that a private/loopback target literal "
            "is an authorized engagement target. Cloud-metadata link-local "
            "targets are refused regardless of this flag."
        ),
    )
    portswigger: bool = Field(default=False, description="PortSwigger lab mode.")
    auto_approve: bool = Field(
        default=False,
        description=(
            "If True, bypass the HITL pause before execution_sandbox. "
            "The engagement runs to completion without human approval."
        ),
    )
    # V6.1: Phase skipping — bypass recon/crawler for fast targeted scans.
    skip_recon: bool = Field(
        default=False,
        description=(
            "V6.1: If True, bypass the recon and crawler nodes and "
            "proceed directly to hypothesis_analyzer using the provided "
            "URL as the sole endpoint."
        ),
    )
    # Product-layer planning inputs; these never grant execution authority.
    endpoint_count: int = Field(default=1, ge=0, le=100000)
    form_count: int = Field(default=0, ge=0, le=100000)
    auth_complexity: int = Field(default=0, ge=0, le=1000)
    estimated_llm_calls: int = Field(default=12, ge=0, le=100000)
    llm_cost_per_call: float = Field(default=0.003, ge=0.0, le=1000.0)

    # V8 Phase 4a: Optional username/password credentials for authenticated
    # scanning. Shape matches CLI's --creds output: {"username": "...",
    # "password": "..."}. Threaded through to auth_node via
    # initial_state["credentials"]. If session_cookies is also provided,
    # session_cookies take precedence (Phase 4b).
    credentials: dict[str, str] | None = Field(
        default=None,
        description=(
            "V8: Optional username/password for authenticated scanning. "
            'Shape: {"username": "admin", "password": "password"}. '
            "If omitted, the engagement runs unauthenticated unless "
            "session_cookies is provided."
        ),
    )
    second_credentials: list[dict[str, str]] = Field(
        default_factory=list,
        description=(
            "Bounded additional identities for differential IDOR/BAC probes. "
            "Each entry uses username/password and is encrypted before Celery dispatch."
        ),
    )
    # V8 Phase 4b: Optional operator-supplied session cookies. Separate
    # from credentials — NOT merged into the credentials dict. Threaded
    # into initial_state on its own key "session_cookies". If provided,
    # auth_node skips Playwright login and uses these cookies directly
    # (after validation). If both credentials and session_cookies are
    # provided, session_cookies take precedence.
    session_cookies: dict[str, str] | None = Field(
        default=None,
        description=(
            "V8: Optional operator-supplied session cookies for "
            "authenticated scanning without Playwright login. Shape: "
            '{"PHPSESSID": "abc123", "security": "impossible"}. '
            "If provided, auth_node validates the session via a "
            "lightweight request and skips Playwright login. Takes "
            "precedence over credentials if both are provided."
        ),
    )
    # V13: bounded offline JWT analysis inputs. These are operator-supplied
    # test candidates, never captured target secrets; raw values are not logged
    # or placed in report-facing state.
    jwt_weak_secret_candidates: list[str] | None = Field(
        default=None,
        description="Optional bounded candidate list for offline JWT signature verification.",
    )
    jwt_public_key_available: bool = Field(
        default=False,
        description="Whether the operator has supplied a public key for advisory JWT analysis.",
    )
    # V13: local disclosed-report corpus only; no remote HackerOne/Bugcrowd
    # retrieval is performed by the application.
    disclosed_report_corpus: list[str | dict[str, Any]] | None = Field(
        default=None,
        description=(
            "Optional operator-supplied local report text/records used only for advisory leads."
        ),
    )
    client_id: str | None = Field(
        default=None,
        max_length=128,
        description=(
            "Stable customer/client identifier used to isolate advisory lessons. "
            "If omitted, lesson persistence and retrieval fail closed."
        ),
    )
    engagement_id: str | None = Field(
        default=None,
        max_length=128,
        description=("Optional logical engagement scope. Defaults to the generated thread_id."),
    )
    additional_target_origins: list[str] = Field(
        default_factory=list,
        description=(
            "Explicit companion HTTP(S) origins used by the target flow. "
            "They are allowlisted only when supplied by the operator."
        ),
    )
    scope_entries: list[str] | None = Field(
        default=None,
        description=(
            "Explicit scope contract lines (same grammar as the CLI --scope-file): "
            "allow entries (host or *.wildcard), 'exclude: <host>', "
            "'include-path: /api', 'exclude-path: /admin'. When supplied, the "
            "target URL must fall inside this scope or the scan fails closed; "
            "the report labels scope_source=scope_file. When omitted, a cautious "
            "scope is inferred from the URL."
        ),
    )
    target_package: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Optional signed bbscout Target Package v2. Raw content is transient and "
            "is admitted again in the worker; it is never checkpointed."
        ),
    )
    target_package_confirmation: dict[str, Any] | None = Field(
        default=None,
        description="Explicit confirmation for this exact package, digest, engagement, and target.",
    )
    target_package_trust_map: dict[str, str] | None = Field(
        default=None,
        description="Runtime-supplied key_id to Ed25519 public-key material mapping.",
    )

    @field_validator("target_package", "target_package_confirmation", "target_package_trust_map")
    @classmethod
    def _validate_package_json_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is None:
            return None
        try:
            encoded_size = len(
                json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
                    "utf-8"
                )
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("target package fields must be JSON objects") from exc
        if encoded_size > 512 * 1024:
            raise ValueError("target package field exceeds 512 KiB")
        return v

    @field_validator("additional_target_origins")
    @classmethod
    def _validate_additional_target_origins(cls, v: list[str]) -> list[str]:
        try:
            return normalize_declared_origins(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("client_id", "engagement_id")
    @classmethod
    def _validate_scope_identifier(cls, v: str | None) -> str | None:
        if v is None:
            return None
        clean = v.strip()
        if not clean:
            raise ValueError("scope identifiers must be non-empty when supplied")
        if any(char in clean for char in "\r\n"):
            raise ValueError("scope identifiers cannot contain CR/LF")
        return clean

    @field_validator("jwt_weak_secret_candidates")
    @classmethod
    def _validate_jwt_candidates(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        if len(v) > 64:
            raise ValueError("jwt_weak_secret_candidates cannot contain more than 64 entries")
        clean: list[str] = []
        for candidate in v:
            if not isinstance(candidate, str) or not candidate or len(candidate) > 128:
                raise ValueError("each JWT candidate must be a non-empty string up to 128 chars")
            clean.append(candidate)
        return clean

    @field_validator("disclosed_report_corpus")
    @classmethod
    def _validate_report_corpus(
        cls, v: list[str | dict[str, Any]] | None
    ) -> list[str | dict[str, Any]] | None:
        if v is None:
            return v
        if len(v) > 200:
            raise ValueError("disclosed_report_corpus cannot contain more than 200 records")
        for record in v:
            if not isinstance(record, (str, dict)):
                raise ValueError("each disclosed report must be text or an object")
            if isinstance(record, str) and len(record) > 100_000:
                raise ValueError("disclosed report text exceeds 100000 characters")
        return v

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v

    # V9 FIX-2: Validate credentials shape — require "username" and
    # "password" keys with non-empty values. Reject payloads like
    # {"user":"admin","pass":"x"} that would silently fail downstream.
    @field_validator("credentials")
    @classmethod
    def _validate_credentials(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if v is None:
            return v
        if not isinstance(v, dict):
            raise ValueError("credentials must be a dict")
        required = {"username", "password"}
        missing = required - set(v.keys())
        if missing:
            raise ValueError(
                f"credentials must contain keys {sorted(required)}; "
                f"missing: {sorted(missing)}. "
                f"Got keys: {sorted(v.keys())}"
            )
        for key in ("username", "password"):
            val = v.get(key)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"credentials['{key}'] must be a non-empty string")
        # Reject extra keys that indicate a wrong schema (e.g. {"user","pass"}).
        extra = set(v.keys()) - required
        if extra:
            raise ValueError(
                f"credentials has unexpected keys: {sorted(extra)}. "
                f"Only {sorted(required)} are accepted."
            )
        return v

    @field_validator("second_credentials")
    @classmethod
    def _validate_second_credentials(cls, v: list[dict[str, str]]) -> list[dict[str, str]]:
        if len(v) > 7:
            raise ValueError("second_credentials cannot contain more than 7 identities")
        required = {"username", "password"}
        clean: list[dict[str, str]] = []
        for item in v:
            if set(item) != required or any(
                not isinstance(item[key], str) or not item[key].strip() for key in required
            ):
                raise ValueError(
                    "each second_credentials entry must contain non-empty "
                    "username and password only"
                )
            clean.append(dict(item))
        return clean

    # V9 FIX-9: Validate session_cookies — names must be safe (no
    # CR/LF/;/=/whitespace), total serialized length capped.
    @field_validator("session_cookies")
    @classmethod
    def _validate_session_cookies(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if v is None:
            return v
        if not isinstance(v, dict):
            raise ValueError("session_cookies must be a dict")
        import re as _re

        bad_cookie_name = _re.compile(r"[\r\n;=\s]")
        total_len = 0
        for name, value in v.items():
            if not isinstance(name, str) or not name:
                raise ValueError(f"session_cookies key {name!r} must be a non-empty string")
            if bad_cookie_name.search(name):
                raise ValueError(
                    f"session_cookies key {name!r} contains illegal characters "
                    f"(CR/LF/semicolon/equals/whitespace)"
                )
            if len(name) > 256:
                raise ValueError(f"session_cookies key {name!r} exceeds 256 chars")
            val = str(value) if value is not None else ""
            total_len += len(name) + len(val) + 2  # name=value;
            if total_len > 8192:
                raise ValueError("session_cookies total serialized length exceeds 8192 chars")
        return v


class ScanResponse(BaseModel):
    task_id: str
    thread_id: str
    auto_approve: bool
    estimate: dict[str, Any] = Field(default_factory=dict)


class AdapterFreeReconRequest(BaseModel):
    url: str = Field(..., description="In-scope HTTP(S) target URL.")
    # F-06 (0.33.0): same admission contract as ScanRequest.
    allow_private_target: bool = Field(
        default=False,
        description=(
            "Operator confirmation that a private/loopback target literal "
            "is an authorized recon target. Link-local is refused always."
        ),
    )
    engagement_id: str | None = Field(default=None, max_length=128)
    scope_entries: list[str] | None = Field(default=None, max_length=32)
    scope: list[str] | None = Field(default=None, max_length=32)
    principal_count: int = Field(default=0, ge=0, le=8)
    max_pages: int = Field(default=50, ge=1, le=500)
    max_depth: int = Field(default=2, ge=0, le=10)
    rate_limit: float = Field(default=0.15, ge=0.0, le=60.0)
    max_hypotheses: int = Field(default=50, ge=1, le=500)
    max_decisions: int = Field(default=30, ge=1, le=100)

    @field_validator("url")
    @classmethod
    def _validate_recon_url(cls, value: str) -> str:
        clean = value.strip()
        if not clean.startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        return clean


class StatusResponse(BaseModel):
    thread_id: str
    status: str
    next: list[str]
    is_paused_at_sandbox: bool


class ApproveResponse(BaseModel):
    thread_id: str
    task_id: str
    message: str


class FindingsResponse(BaseModel):
    thread_id: str
    count: int
    findings: list[dict[str, Any]]


class CampaignControlResponse(BaseModel):
    campaign_id: str
    engagement_id: str
    state: str
    message: str


_INCOMPLETE_WORKER_STATUSES = frozenset(
    {
        "completed_incomplete_chain",
        "terminated_recursion_limit",
        "terminated_zombie_running",
        "soft_timeout",
    }
)


def _apply_worker_result_status(
    state_info: dict[str, Any], worker_result: Any
) -> dict[str, Any]:
    """Project a successful Celery result without turning partial work into success.

    Celery ``SUCCESS`` only means the task returned a value; it does not mean
    the engagement completed its proof/research chain. A worker terminal
    result other than the explicit clean ``completed`` marker is therefore
    exposed as ``incomplete``. Unknown future worker statuses fail closed in
    the same way instead of silently inheriting a graph ``completed`` value.
    """
    if not isinstance(worker_result, dict):
        return state_info
    worker_status = str(worker_result.get("status") or "").strip()
    if not worker_status or worker_status == "completed":
        return state_info
    # Keep the named set explicit as documentation; the final condition is
    # intentionally fail-closed for any newly introduced non-success status.
    if worker_status in _INCOMPLETE_WORKER_STATUSES or worker_status:
        state_info["status"] = "incomplete"
        state_info["next"] = [f"(worker:{worker_status})"]
    return state_info


def _get_graph_status(thread_id: str) -> dict[str, Any]:
    """Read the LangGraph checkpoint state for ``thread_id``.

    V10 P0-0 FIX: the previous version conflated two distinct conditions
    into a single ``status="completed"`` return:
      (a) the engagement ran to completion (checkpoint exists, ``next == ()``)
      (b) NO checkpoint exists yet for this thread_id (worker still
          queued or starting up — ``get_state`` returns None or an empty
          StateSnapshot with ``next=()``)
    Both produced ``next_nodes == []`` and the handler returned
    ``"completed"`` for case (b), causing the live operator symptom:
    POST /scans → ~1s later GET /status returns ``completed`` while the
    worker is still actively running.

    Fix: distinguish "no checkpoint" (``state_snapshot is None`` OR
    ``not state_snapshot.values``) from "checkpoint with empty next"
    (genuine completion). The former returns ``"pending"`` (a NEW
    status value meaning "engagement queued or worker starting —
    no checkpoint written yet"); the latter returns ``"completed"``.
    The Celery cross-check in ``get_scan_status`` then overrides
    ``"pending"`` to ``"running"`` if AsyncResult.state confirms the
    task is in-flight.
    """
    from webpent.config.settings import get_settings

    settings = get_settings()
    config = {
        "recursion_limit": settings.max_graph_steps,
        "configurable": {"thread_id": thread_id},
    }

    try:
        with get_checkpointer() as checkpointer:
            # V9 FIX-5: Use the module-level cached graph instead of
            # rebuilding on every status poll. The graph topology never
            # changes at runtime; only the checkpointer connection is
            # per-request.
            graph = _get_cached_graph(checkpointer)
            try:
                state_snapshot = graph.get_state(config)
            except Exception as exc:
                logger.error("Failed to get graph state: %s", exc)
                # V10 P0-0: do NOT default to "completed" on get_state
                # failure — "error" is the safe default (the caller's
                # Celery cross-check may still override to "running").
                return {"status": "error", "next": [], "is_paused_at_sandbox": False}

            # V10 P0-0: distinguish "no checkpoint" from "completed".
            # state_snapshot is None on older langgraph for unknown
            # thread_ids; on newer langgraph it's a StateSnapshot with
            # empty values + next=() for an unknown thread_id. Both
            # mean the worker has NOT yet written a checkpoint for this
            # engagement — return "pending", NOT "completed".
            if state_snapshot is None or not state_snapshot.values:
                return {
                    "status": "pending",
                    "next": [],
                    "is_paused_at_sandbox": False,
                }

            next_nodes = list(state_snapshot.next) if state_snapshot else []
            if not next_nodes:
                # Genuine completion: checkpoint exists with values AND
                # no remaining nodes. This is the ONLY path that returns
                # "completed" from the graph layer.
                return {"status": "completed", "next": [], "is_paused_at_sandbox": False}

            is_paused = NODE_EXECUTION_SANDBOX in next_nodes
            return {
                "status": "paused" if is_paused else "running",
                "next": next_nodes,
                "is_paused_at_sandbox": is_paused,
            }
    except Exception as exc:
        logger.error("Failed to initialise checkpointer for status check: %s", exc)
        # V10 P0-0: never default to "completed" on exception. "error"
        # is the safe default — the Celery cross-check below may still
        # override to "running" if the task is in-flight.
        return {"status": "error", "next": [], "is_paused_at_sandbox": False}


@app.get("/health")
def health_check() -> dict[str, Any]:
    registry = scan_registry_health()
    return {
        "status": "ok" if registry["ready"] else "degraded",
        "scan_registry": registry,
    }


# ===========================================================================
# V5 Sprint 13: JWT Authentication Endpoint
# ===========================================================================
@app.post("/token")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),  # noqa: B008
):  # noqa: B008
    """OAuth2 password flow with an independent login throttle.

    The generic 429 response intentionally does not distinguish unknown users
    from known users. FastAPI supplies ``request`` for trusted client-IP
    attribution.
    """
    if _settings.rate_limit_enabled:
        client_ip = _extract_trusted_client_ip(request, _settings.trusted_proxy_ips)
        if not _rate_limiter.check_login(client_ip, form_data.username):
            raise HTTPException(
                status_code=429,
                detail="Too many login attempts. Try again later.",
                headers={"Retry-After": "60"},
            )
    return login_for_access_token(form_data)


@app.get("/api/v1/me")
def get_current_user_info(user: User = Depends(get_current_user)) -> dict[str, str]:  # noqa: B008
    """Return the authenticated user's profile (username + role)."""
    return {"username": user.username, "role": user.role}


@app.post("/api/v1/recon", status_code=200)
def start_adapter_free_recon(
    request: AdapterFreeReconRequest,
    user: User = Depends(require_role("admin", "service")),  # noqa: B008
) -> dict[str, Any]:
    """Run bounded URL-driven recon through the existing production spine.

    This endpoint is intentionally synchronous and bounded. It returns only
    redacted discovery/campaign projections; credentials and target bodies are
    not accepted by this adapter-free entrypoint.
    """
    # F-06 (0.33.0): same admission gate as POST /scans.
    try:
        admission_target_check(request.url,
                               allow_private_target=request.allow_private_target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    resolved_engagement_id = request.engagement_id or default_engagement_id(request.url, user.username)
    try:
        result = run_autonomous_recon_campaign(
            target_url=request.url,
            engagement_id=resolved_engagement_id,
            entrypoint="api",
            scope_entries=(list(request.scope_entries or []) + list(request.scope or [])) or None,
            principal_count=request.principal_count,
            crawl_config=CrawlConfig(
                max_pages=request.max_pages,
                max_depth=request.max_depth,
                per_host_min_interval_seconds=request.rate_limit,
            ),
            max_hypotheses=request.max_hypotheses,
            max_decisions=request.max_decisions,
        )
    except Exception as exc:
        logger.warning("Adapter-free recon rejected: %s", type(exc).__name__)
        raise HTTPException(status_code=422, detail="adapter-free recon could not proceed safely") from exc
    return result


@app.post("/api/v1/scans", response_model=ScanResponse, status_code=202)
def start_scan(
    request: ScanRequest,
    http_request: Request,
    user: User = Depends(require_role("admin", "service")),  # noqa: B008
) -> ScanResponse:
    """Trigger a new pentest engagement.

    V5 Sprint 13: Requires ``admin`` or ``service`` role. ``viewer``
    users receive HTTP 403. Rate-limited to
    ``Settings.rate_limit_scan_per_minute`` requests per minute per IP.
    """
    # V5 Sprint 14 P1: scan-specific rate limit (stricter than global).
    # V6 DX-Final P1: Use the shared ``_extract_trusted_client_ip``
    # helper so the scan-specific rate limiter uses the same trusted-
    # proxy logic as the global middleware. Previously this endpoint
    # trusted raw ``X-Forwarded-For`` / ``X-Real-IP`` headers from any
    # client, allowing spoofing to bypass the per-IP scan rate limit.
    client_ip = _extract_trusted_client_ip(http_request, _settings.trusted_proxy_ips)

    if _settings.rate_limit_enabled and not _rate_limiter.check_scan(client_ip):
        raise HTTPException(
            status_code=429,
            detail=(
                f"Scan rate limit exceeded ({_settings.rate_limit_scan_per_minute}/min). "
                "Try again later."
            ),
            headers={"Retry-After": "60"},
        )

    effective_client_id = _effective_scan_client_id(request.client_id, user)
    # F-06 (0.33.0): server-side admission gate BEFORE any dispatch —
    # private/loopback target literals need the operator confirmation flag;
    # link-local (cloud metadata) is refused unconditionally.
    try:
        admission_target_check(request.url,
                               allow_private_target=request.allow_private_target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    thread_id = str(uuid4())
    resolved_engagement_id = request.engagement_id or default_engagement_id(
        request.url,
        effective_client_id,
    )
    # Pre-flight planning happens before any LLM call or target action.
    estimate = estimate_campaign_cost(
        endpoint_count=request.endpoint_count,
        form_count=request.form_count,
        auth_complexity=request.auth_complexity,
        estimated_llm_calls=request.estimated_llm_calls,
        per_call_cost=request.llm_cost_per_call,
    ).as_dict()
    validated_package: dict[str, Any] | None = None
    if any(
        value is not None
        for value in (
            request.target_package,
            request.target_package_confirmation,
            request.target_package_trust_map,
        )
    ):
        try:
            ensure_package_request_fields(
                request.target_package,
                request.target_package_confirmation,
                request.target_package_trust_map,
            )
            validated_package, _context, package_engagement_id = validate_package_for_dispatch(
                request.target_package or {},
                request.target_package_confirmation or {},
                trusted_public_keys=request.target_package_trust_map or {},
            )
            if package_engagement_id != resolved_engagement_id:
                raise PackageExecutionIntakeError("confirmation_engagement_id_mismatch")
            confirmation = request.target_package_confirmation or {}
            confirmation_target = str(
                confirmation.get("target_url") or confirmation.get("target_origin") or ""
            ).strip()
            if confirmation_target != request.url:
                raise PackageExecutionIntakeError("confirmation_target_url_mismatch")
        except (PackageExecutionIntakeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="target package admission blocked") from exc
    logger.info(
        "Dispatching pentest task: url=%s portswigger=%s auto_approve=%s "
        "thread_id=%s client_id=%s engagement_id=%s user=%s role=%s",
        request.url,
        request.portswigger,
        request.auto_approve,
        thread_id,
        effective_client_id,
        resolved_engagement_id,
        user.username,
        user.role,
    )

    try:
        # V10 HOSTILE-AUDIT FIX (CH-2): encrypt the password before it
        # transits the Celery/Redis broker as a task kwarg. See
        # webpent.utils.task_crypto for why this is necessary (Redis
        # would otherwise hold the plaintext password in its queue) and
        # workers/pentest_worker.run_pentest_task for the matching
        # decrypt call. session_cookies are NOT encrypted — see
        # task_crypto's module docstring for the scope decision.
        from webpent.utils.task_crypto import (
            encrypt_credentials_for_task,
            encrypt_identity_profiles_for_task,
            encrypt_secret_map_for_task,
        )

        identity_profiles = {
            f"identity-{index}": {
                "name": f"identity-{index}",
                "role": "secondary",
                "credentials": credentials,
            }
            for index, credentials in enumerate(request.second_credentials, start=2)
        }

        task = run_pentest_task.delay(
            target_url=request.url,
            is_portswigger=request.portswigger,
            thread_id=thread_id,
            auto_approve=request.auto_approve,
            skip_recon=request.skip_recon,
            # V8 Phase 4a/4b: thread credentials + session_cookies
            # through to the worker. Default to empty dict (not None)
            # so the worker's initial_state always has a dict, matching
            # the merge_dicts reducer's expected type.
            credentials=encrypt_credentials_for_task(request.credentials or {}),
            session_cookies=encrypt_secret_map_for_task(request.session_cookies or {}),
            identity_profiles=encrypt_identity_profiles_for_task(identity_profiles),
            jwt_weak_secret_candidates=request.jwt_weak_secret_candidates or [],
            jwt_public_key_available=request.jwt_public_key_available,
            disclosed_report_corpus=request.disclosed_report_corpus or [],
            additional_target_origins=request.additional_target_origins,
            scope_entries=(
                [str(line) for line in request.scope_entries]
                if request.scope_entries
                else None
            ),
            client_id=effective_client_id,
            engagement_id=resolved_engagement_id,
            target_package=validated_package,
            target_package_confirmation=(
                dict(request.target_package_confirmation)
                if request.target_package_confirmation is not None
                else None
            ),
            target_package_trust_map=(
                dict(request.target_package_trust_map)
                if request.target_package_trust_map is not None
                else None
            ),
        )
    except Exception as exc:
        logger.error("Failed to dispatch Celery task (type=%s)", type(exc).__name__)
        raise HTTPException(
            status_code=503,
            detail="Could not dispatch pentest task; the task broker may be unavailable.",
        ) from exc

    logger.info("Celery task dispatched: task_id=%s thread_id=%s", task.id, thread_id)

    # V10 P0-0: persist the thread_id ↔ task_id mapping so the status
    # endpoint can look up AsyncResult(task_id).state. Without this,
    # the status endpoint only has thread_id (path param) and cannot
    # consult Celery's authoritative task state — forcing it to rely
    # on inspect.active() (broadcast + string match + 5s timeout),
    # which misses queued tasks and times out on unresponsive workers,
    # causing the false-completed bug.
    try:
        from webpent.api.scan_registry import register_scan

        registered = register_scan(
            thread_id,
            task.id,
            target_url=request.url,
            owner_username=user.username,
            client_id=effective_client_id,
            engagement_id=resolved_engagement_id,
            cost_estimate=estimate,
        )
        if not registered:
            logger.error(
                "scan_registry ownership record was not persisted for thread_id=%s",
                thread_id,
            )
    except Exception as exc:
        # Non-fatal: scan_registry is best-effort. If it fails, the
        # status endpoint falls back to inspect.active() (the old path).
        logger.warning(
            "scan_registry: failed to register thread_id=%s task_id=%s: %s "
            "(non-fatal — status check will use inspect.active fallback)",
            thread_id,
            task.id,
            exc,
        )

    return ScanResponse(
        task_id=task.id,
        thread_id=thread_id,
        auto_approve=request.auto_approve,
        estimate=estimate,
    )


@app.post("/api/v1/campaigns/{campaign_id}/halt", response_model=CampaignControlResponse)
def halt_campaign(
    campaign_id: str,
    user: User = Depends(require_role("admin", "service")),  # noqa: B008
) -> CampaignControlResponse:
    """Request a clean stop at the next action-ledger checkpoint."""
    record = _authorize_scan_resource(campaign_id, user)
    engagement_id = str(record.get("engagement_id") or campaign_id)
    ledger = SQLiteActionLedger(get_settings().action_ledger_path)
    if not ledger.request_halt(engagement_id, user.username):
        raise HTTPException(status_code=503, detail="campaign control unavailable")
    update_scan_status(campaign_id, "halt_requested")
    return CampaignControlResponse(
        campaign_id=campaign_id, engagement_id=engagement_id,
        state="HALT_REQUESTED",
        message="Current action may finish; the next action checkpoint will stop the campaign.",
    )


@app.post("/api/v1/campaigns/{campaign_id}/resume", response_model=CampaignControlResponse)
def resume_campaign(
    campaign_id: str,
    user: User = Depends(require_role("admin", "service")),  # noqa: B008
) -> CampaignControlResponse:
    """Clear a cooperative halt; it never rewrites existing findings."""
    record = _authorize_scan_resource(campaign_id, user)
    engagement_id = str(record.get("engagement_id") or campaign_id)
    ledger = SQLiteActionLedger(get_settings().action_ledger_path)
    if not ledger.clear_halt(engagement_id):
        raise HTTPException(status_code=409, detail="campaign has no halt request")
    update_scan_status(campaign_id, "running")
    return CampaignControlResponse(
        campaign_id=campaign_id, engagement_id=engagement_id,
        state="RESUMED", message="Campaign may continue from its durable checkpoint.",
    )


@app.get("/api/v1/campaigns/{campaign_id}/estimate")
def get_campaign_estimate(
    campaign_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
) -> dict[str, Any]:
    """Return the pre-flight planning estimate for a campaign."""
    record = _authorize_scan_resource(campaign_id, user)
    estimate = record.get("cost_estimate") or estimate_campaign_cost().as_dict()
    return {"campaign_id": campaign_id, "engagement_id": record.get("engagement_id"), "estimate": estimate}


@app.get("/api/v1/campaigns/{campaign_id}/dashboard", response_class=HTMLResponse)
def get_campaign_dashboard(
    campaign_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
) -> HTMLResponse:
    """Render a read-only projection of already-persisted findings."""
    record = _authorize_scan_resource(campaign_id, user)
    findings_response = get_findings(campaign_id, user)
    chain_metrics: dict[str, Any] = {}
    try:
        chain_path = _workspace_for_record(record).root / "chain_summary.json"
        if chain_path.is_file():
            loaded = json.loads(chain_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                chain_metrics = {key: loaded.get(key, 0) for key in ("chains_discovered", "chains_confirmed", "combined_severity_upgrades")}
    except (OSError, ValueError, TypeError):
        chain_metrics = {}
    return HTMLResponse(
        render_campaign_dashboard(campaign_id, findings_response.findings, chain_metrics=chain_metrics),
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/v1/campaigns/{campaign_id}/reports")
def get_campaign_reports(
    campaign_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
) -> list[dict[str, Any]]:
    """Return submission-ready reports from promoted ProofBundles only."""
    _authorize_scan_resource(campaign_id, user)
    findings_response = get_findings(campaign_id, user)
    return [
        report.to_json()
        for report in generate_bounty_reports(
            findings_response.findings,
            campaign_id=campaign_id,
        )
    ]


@app.get("/api/v1/scans/{thread_id}/status", response_model=StatusResponse)
def get_scan_status(
    thread_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
) -> StatusResponse:
    """Check engagement status.

    V10 P0-0 FIX: the previous version conflated "no checkpoint yet"
    with "completed" (see ``_get_graph_status`` docstring) and relied
    on ``inspect.active()`` (a broadcast + string-match with a 5s
    timeout) to catch the false-completed case. ``inspect.active()``
    misses tasks that are still QUEUED in Redis (Celery state PENDING,
    not yet picked up by a worker) and times out on unresponsive
    workers — both leaving the false "completed" in place.

    The fix uses ``AsyncResult(task_id).state`` as the AUTHORITATIVE
    Celery signal, looked up via the thread_id → task_id mapping
    persisted by POST /scans (see ``scan_registry``). The decision
    matrix is:

      AsyncResult.state   | graph_status    | final status
      --------------------+-----------------+-------------
      PENDING / STARTED / | (any)           | "running"
      RETRY               |
      SUCCESS             | "completed"     | "completed"
      SUCCESS             | "pending"/"running"/"paused" | graph_status
      (trust graph — task returned but checkpoint may be mid-write)
      FAILURE / REVOKED   | (any)                         | "error"
      (lookup failed)     | "completed"                   | "completed"
      (fallback — trust graph, can't cross-check)
      (lookup failed)     | "pending"       | "running" (fallback — be conservative)
      (lookup failed)     | "running"/"paused"/"error" | graph_status (trust graph)

    The previous ``inspect.active()`` path is kept as a TERTIARY
    fallback for the case where both AsyncResult and the registry
    are unavailable (e.g. the scan was dispatched by an older API
    version that didn't persist the mapping).
    """
    logger.info("Status check for thread_id=%s (user=%s)", thread_id, user.username)
    record = _authorize_scan_resource(thread_id, user)
    workspace = _workspace_for_record(record)
    with activate_target_workspace(workspace), activate_settings(
        _settings_for_workspace(workspace)
    ):
        state_info = _get_graph_status(thread_id)

    # V10 P0-0: PRIMARY cross-check — AsyncResult(task_id).state via
    # the persisted thread_id → task_id mapping.
    celery_state: str | None = None
    try:
        from webpent.api.scan_registry import lookup_task_id
        from webpent.workers.pentest_worker import celery_app as _celery

        task_id = lookup_task_id(thread_id)
        if task_id:
            # AsyncResult.state is a CHEAP Redis read (no broadcast,
            # no worker round-trip) — unlike inspect.active(). It is
            # the authoritative Celery signal.
            async_result = _celery.AsyncResult(task_id)
            celery_state = async_result.state
            logger.debug(
                "Status check thread_id=%s: AsyncResult.state=%s graph_status=%s",
                thread_id,
                celery_state,
                state_info["status"],
            )
        else:
            # No mapping in the registry — either an old scan dispatched
            # before V10 P0-0, or the registry write failed. Fall through
            # to the inspect.active() tertiary path below.
            logger.debug(
                "Status check thread_id=%s: no task_id in registry — "
                "falling back to inspect.active()",
                thread_id,
            )
    except Exception as exc:
        logger.debug(
            "AsyncResult lookup failed for thread_id=%s (non-fatal): %s",
            thread_id,
            exc,
        )

    # V10 P0-0: apply the decision matrix.
    if celery_state in ("PENDING", "STARTED", "RETRY"):
        # V10 AUDIT FIX (H10): Celery's AsyncResult.state returns PENDING
        # for unknown/expired result IDs (result_expires=7 days by
        # default). After 7 days, a genuinely-completed engagement
        # (graph says "completed") would be overridden to "running"
        # forever. Fix: if the graph checkpoint has a non-empty state
        # AND says "completed" (genuine terminal state — requires
        # non-empty values + empty next per _get_graph_status), trust
        # the graph over Celery's PENDING. The graph checkpoint is the
        # durable source of truth; Celery's result backend is ephemeral.
        if celery_state == "PENDING" and state_info["status"] == "completed":
            # Graph says completed, Celery forgot — trust the graph.
            # This handles the expired-result case correctly.
            logger.info(
                "Status check thread_id=%s: Celery PENDING but graph "
                "checkpoint is completed — trusting graph (Celery "
                "result may have expired).",
                thread_id,
            )
            # POST-P0 Phase 9 (honest status): "completed" must not be
            # reported while persistence is unverified-empty. If the
            # graph finished but no findings rows exist, the run either
            # legitimately produced nothing or died between graph
            # completion and persist — the operator cannot tell from
            # "completed". Report "persisting" (persist unverified)
            # until rows exist; a verified non-empty persist reports
            # "completed". When the count cannot be verified at all
            # (no workspace context), keep the historical "completed".
            _persisted = _persisted_finding_count(thread_id)
            if _persisted == 0:
                state_info["status"] = "persisting"
                state_info["next"] = ["(persist:unverified_empty)"]
            # Leave state_info as-is when rows exist or verification is
            # unavailable.
        elif state_info["status"] != "paused":
            # Task is genuinely queued or executing — override to running.
            state_info["status"] = "running"
            state_info["next"] = [f"(celery:{celery_state})"]
    elif celery_state in ("FAILURE", "REVOKED"):
        # Task crashed or was revoked — the worker's exception handler
        # (_emergency_persist_findings) already saved what it could.
        # Report "error" so the operator knows to investigate.
        state_info["status"] = "error"
        state_info["next"] = [f"(celery:{celery_state})"]
    elif celery_state == "SUCCESS":
        # Task returned normally. The worker's return dict (stored as
        # AsyncResult.result) is the source of truth for terminal status.
        # V10 HOSTILE P0-1 FIX: previously this branch only trusted the
        # graph checkpoint. But the worker returns terminal strings
        # (terminated_recursion_limit, soft_timeout, terminated_zombie_running)
        # that the graph checkpoint does NOT reflect — the checkpoint may
        # still show "running" with next nodes, while the task has
        # actually terminated. The operator polls "running" forever.
        # Fix: read AsyncResult.result (non-blocking — result is already
        # ready because state==SUCCESS) and map terminal status strings
        # to API-visible terminal values.
        _worker_result: dict[str, Any] | None = None
        try:
            # .result is safe to read when state==SUCCESS — it's already
            # stored in the result backend, no blocking .get() needed.
            _raw_result = async_result.result if async_result else None
            if isinstance(_raw_result, dict):
                _worker_result = _raw_result
        except Exception as result_exc:
            logger.debug(
                "Status check thread_id=%s: AsyncResult.result read failed (non-fatal): %s",
                thread_id,
                result_exc,
            )

        _worker_status = ""
        if _worker_result:
            _worker_status = str(_worker_result.get("status") or "")

        # A Celery SUCCESS only means the worker returned normally. It is not
        # proof that the graph completed its chain. Preserve the explicit
        # clean marker and fail closed for every other worker status,
        # including completed_incomplete_chain and future status values.
        if _worker_status:
            _apply_worker_result_status(state_info, _worker_result)
            if _worker_status != "completed":
                logger.info(
                    "Status check thread_id=%s: Celery SUCCESS with worker "
                    "status=%s — exposing incomplete terminal status.",
                    thread_id,
                    _worker_status,
                )
        elif state_info["status"] == "pending":
            # Celery SUCCESS but graph has no checkpoint — checkpoint
            # write may have failed. Treat as error.
            logger.warning(
                "Status check thread_id=%s: Celery SUCCESS but graph has "
                "no checkpoint — checkpoint write may have failed. "
                "Reporting as 'error'.",
                thread_id,
            )
            state_info["status"] = "error"
            state_info["next"] = ["(celery:SUCCESS,no_checkpoint)"]
        # else: trust state_info["status"] as-is (completed/paused/etc.) —
        # the graph checkpoint is the source of truth for normal
        # completion and HITL pause.
    else:
        # celery_state is None (registry miss or AsyncResult failure).
        # TERTIARY fallback: inspect.active() — the old V9 path.
        # Kept for backward compat with scans dispatched before the
        # registry existed. This path is known to be weak (broadcast +
        # 5s timeout + misses queued tasks) but is strictly better than
        # returning the un-cross-checked graph status.
        try:
            import concurrent.futures as _cf

            from webpent.workers.pentest_worker import celery_app as _celery

            def _check_celery_active():
                inspect = _celery.control.inspect(timeout=5)
                return inspect.active() or {}

            executor = _cf.ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(_check_celery_active)
                try:
                    active = future.result(timeout=5.0)
                except _cf.TimeoutError:
                    logger.warning(
                        "Celery inspect timed out after 5s (thread_id=%s) — "
                        "returning partial status",
                        thread_id,
                    )
                    active = {}
            finally:
                executor.shutdown(wait=False)

            is_active = any(
                thread_id in str(task.get("kwargs", {})) or thread_id in str(task.get("args", []))
                for tasks in active.values()
                for task in tasks
            )
            if is_active and state_info["status"] != "paused":
                # Worker is still processing this thread — override to
                # 'running'. But NEVER override to 'completed'.
                state_info["status"] = "running"
                state_info["next"] = ["(worker_processing)"]
            elif not is_active and state_info["status"] == "pending":
                # V10 P0-0: inspect.active() returned nothing AND the
                # graph has no checkpoint. The task is either queued
                # (not yet picked up — invisible to inspect.active()) OR
                # already finished and the checkpoint write is in flight.
                # Be conservative: report "running" — the operator can
                # re-poll in a few seconds.
                logger.info(
                    "Status check thread_id=%s: no active worker, no "
                    "checkpoint — reporting 'running' (task may be queued "
                    "or checkpoint may be mid-write). Re-poll in 5s.",
                    thread_id,
                )
                state_info["status"] = "running"
                state_info["next"] = ["(queued_or_finishing)"]
        except Exception as exc:
            logger.debug("Celery inspect fallback failed (non-fatal): %s", exc)
            # V10 P0-0: if even inspect.active() fails, NEVER default to
            # "completed". If graph says "pending", report "running"
            # (conservative). If graph says "completed", trust it (the
            # graph layer's completion check is now strict — requires
            # non-empty values + empty next).
            if state_info["status"] == "pending":
                state_info["status"] = "running"
                state_info["next"] = ["(celery_unreachable)"]

    return StatusResponse(
        thread_id=thread_id,
        status=state_info["status"],
        next=state_info["next"],
        is_paused_at_sandbox=state_info["is_paused_at_sandbox"],
    )


@app.post("/api/v1/scans/{thread_id}/approve", response_model=ApproveResponse)
def approve_scan(
    thread_id: str,
    user: User = Depends(require_role("admin")),  # noqa: B008
) -> ApproveResponse:
    """Approve a paused engagement. V5 Sprint 13: requires ``admin`` role."""
    logger.info("Approval requested for thread_id=%s (user=%s)", thread_id, user.username)
    # POST-P0 Phase 9: durable operator audit trail (identifiers only).
    from webpent.memory.decision_log import log_operator_event

    log_operator_event(
        action="scan_approve",
        thread_id=thread_id,
        actor=user.username,
        outcome="approved",
    )
    _authorize_scan_resource(thread_id, user)
    from webpent.api.scan_registry import get_scan_record

    scan_record = get_scan_record(thread_id)
    if not scan_record:
        raise HTTPException(
            status_code=404,
            detail="Scan ownership record is unavailable; resume is denied.",
        )
    capability = issue_resume_capability(
        thread_id=thread_id,
        owner_username=str(scan_record.get("owner_username") or user.username),
        client_id=str(scan_record.get("client_id") or ""),
        engagement_id=str(scan_record.get("engagement_id") or thread_id),
    )
    state_info = _get_graph_status(thread_id)

    if state_info["status"] == "error":
        raise HTTPException(status_code=500, detail="Could not determine engagement status.")

    if state_info["status"] == "completed":
        raise HTTPException(status_code=409, detail="Engagement is already completed.")

    if not state_info["is_paused_at_sandbox"]:
        raise HTTPException(
            status_code=409,
            detail=f"Engagement is not paused at the sandbox (status={state_info['status']}).",
        )

    if not claim_resume_capability(thread_id, capability):
        raise HTTPException(
            status_code=409,
            detail="Engagement approval is already claimed or unavailable.",
        )

    log_operator_event(
        action="scan_resume_dispatch",
        thread_id=thread_id,
        actor=user.username,
        outcome="resume_task_dispatched",
    )
    try:
        task = resume_pentest_task.delay(
            thread_id=thread_id,
            resume_capability=capability,
        )
    except Exception as exc:
        release_resume_claim(thread_id, capability)
        logger.error("Failed to dispatch resume task (type=%s)", type(exc).__name__)
        raise HTTPException(
            status_code=503,
            detail="Could not dispatch resume task; the task broker may be unavailable.",
        ) from exc

    logger.info("Resume task dispatched: task_id=%s thread_id=%s", task.id, thread_id)
    return ApproveResponse(
        thread_id=thread_id,
        task_id=task.id,
        message="Engagement approved. Resume task dispatched.",
    )


@app.get("/api/v1/scans/{thread_id}/findings", response_model=FindingsResponse)
def get_findings(
    thread_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
) -> FindingsResponse:
    """Retrieve persisted findings. V5 Sprint 13: any authenticated user.

    V9 P0 Fix 3: now queries by thread_id only (WHERE thread_id = ?).
    Previously called get_all_findings() which returned ALL findings
    from ALL engagements — cross-thread bleed. Now uses
    get_findings_by_thread() for strict per-engagement isolation.
    """
    logger.info("Fetching findings for thread_id=%s (user=%s)", thread_id, user.username)
    record = _authorize_scan_resource(thread_id, user)

    workspace = _workspace_for_record(record)
    try:
        with activate_target_workspace(workspace), activate_settings(
            _settings_for_workspace(workspace)
        ):
            # Findings are isolated by the authorized engagement scope, not by the
            # latest run UUID. This preserves results across repeated scans while
            # keeping owner/client predicates in the registry lookup.
            sibling_threads = get_thread_ids_by_engagement_id(
                str(record.get("engagement_id") or ""),
                owner_username=str(record.get("owner_username") or user.username),
                client_id=str(record.get("client_id") or ""),
            )
            thread_ids = sibling_threads or [thread_id]
            db = get_db_manager()
            all_findings = aggregate_findings(db.get_findings_by_threads(thread_ids))
            try:
                ledger_findings = PersistentFindingLedger(
                    get_settings().findings_ledger_path
                ).get(
                    str(record.get("engagement_id") or ""),
                    owner_username=str(record.get("owner_username") or user.username),
                    client_id=str(record.get("client_id") or "") or None,
                )
                all_findings = aggregate_findings([*ledger_findings, *all_findings])
            except Exception:
                logger.exception("Persistent findings ledger read failed (non-fatal)")
    except Exception as exc:
        logger.error("Failed to read findings from database (type=%s)", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Failed to read findings.") from exc

    serialized: list[dict[str, Any]] = []
    for finding in all_findings:
        try:
            serialized.append(finding.model_dump(mode="json"))
        except Exception:
            logger.warning("Skipping unserialisable finding: %s", finding.id)
            continue

    return FindingsResponse(thread_id=thread_id, count=len(serialized), findings=serialized)


@app.get("/api/v1/scans/{thread_id}/risk-summary")
def get_risk_summary(
    thread_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
) -> dict[str, Any]:
    """V9 P5 FEAT-3: Minimal risk heatmap from existing findings data.

    Returns a read-only summary of findings by severity + confidence_level
    for the given thread. No fake metrics — if there are no findings,
    returns empty counts. This is a pure aggregation of existing DB data,
    no new computation or storage.
    """
    record = _authorize_scan_resource(thread_id, user)
    workspace = _workspace_for_record(record)

    try:
        with activate_target_workspace(workspace), activate_settings(
            _settings_for_workspace(workspace)
        ):
            sibling_threads = get_thread_ids_by_engagement_id(
                str(record.get("engagement_id") or ""),
                owner_username=str(record.get("owner_username") or user.username),
                client_id=str(record.get("client_id") or ""),
            )
            thread_ids = sibling_threads or [thread_id]
            db = get_db_manager()
            findings = aggregate_findings(db.get_findings_by_threads(thread_ids))
            try:
                ledger_findings = PersistentFindingLedger(
                    get_settings().findings_ledger_path
                ).get(
                    str(record.get("engagement_id") or ""),
                    owner_username=str(record.get("owner_username") or user.username),
                    client_id=str(record.get("client_id") or "") or None,
                )
                findings = aggregate_findings([*ledger_findings, *findings])
            except Exception:
                logger.exception("Persistent findings ledger read failed (non-fatal)")
    except Exception as exc:
        logger.error("Failed to read risk summary (type=%s)", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Failed to read findings.") from exc

    severity_counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    confidence_counts: dict[str, int] = {
        "Tool-Confirmed": 0,
        "AI-Assessed": 0,
        "Pending": 0,
        "Needs Human Review": 0,
        "Not Scanned": 0,
        "Clean": 0,
    }
    vuln_class_counts: dict[str, int] = {}

    for f in findings:
        sev = str(f.severity).lower() if f.severity else "info"
        if sev in severity_counts:
            severity_counts[sev] += 1
        cl = f.confidence_level or "Pending"
        if cl in confidence_counts:
            confidence_counts[cl] += 1
        vc = str(f.vuln_class or "unknown")
        vuln_class_counts[vc] = vuln_class_counts.get(vc, 0) + 1

    total = len(findings)
    confirmed = confidence_counts.get("Tool-Confirmed", 0)

    return {
        "thread_id": thread_id,
        "total_findings": total,
        "confirmed_findings": confirmed,
        "severity_counts": severity_counts,
        "confidence_counts": confidence_counts,
        "vuln_class_counts": vuln_class_counts,
        "risk_level": (
            "Critical"
            if severity_counts["critical"] > 0
            else "High"
            if severity_counts["high"] > 0
            else "Medium"
            if severity_counts["medium"] > 0
            else "Low"
            if severity_counts["low"] > 0
            else "Info"
        ),
    }


# =========================================================================== #
# V5 Sprint 5 — Out-of-Band (OOB) callback receiver                          #
# =========================================================================== #
# The OOB endpoint is what makes deterministic SSRF/RCE confirmation
# possible. The validator injects a URL pointing here into the target's
# vulnerable parameter; if the target server reaches out to fetch that
# URL, the SSRF/RCE is confirmed objectively (no LLM in the loop).
#
# Security model (defense-in-depth):
#   1. ``finding_id`` MUST be a syntactically-valid UUID. Anything else
#      is rejected with 400 before touching the DB. This blocks path
#      traversal / SQLi via the path parameter.
#   2. ``secret`` MUST match ``Settings.oob_callback_secret``. The
#      secret is part of the URL the validator itself constructs and
#      injects; an attacker who can observe the target's request log
#      would still need to guess the secret to forge a callback. When
#      the secret is empty (default), OOB confirmation is disabled
#      entirely (fail-safe — the endpoint returns 503).
#   3. The endpoint only mutates the specific finding whose UUID is in
#      the path; it does not accept any body that could override the
#      finding's identity. The request body is read with a hard 4 KB
#      ceiling and truncated before being recorded into the reasoning
#      trail, preventing a malicious target from blowing up the DB row.
#   4. The endpoint writes to the DB via the same thread-safe
#      ``DatabaseManager`` used everywhere else, so concurrent callbacks
#      cannot corrupt each other.
#   5. The endpoint returns 204 No Content with an empty body so the
#      target's HTTP client does not surface any framework internals.
# =========================================================================== #
def _validate_oob_finding_id(finding_id: str) -> UUID:
    """Strict UUID parsing for the OOB path parameter.

    Rejects anything that is not a canonical UUID string. This is the
    primary defence against path traversal / SQLi / log injection via
    the ``finding_id`` segment — FastAPI's path converter does NOT
    validate format by default.
    """
    try:
        return UUID(str(finding_id).strip().lower())
    except (ValueError, AttributeError, TypeError) as exc:
        logger.warning("OOB callback rejected: malformed finding_id=%r", finding_id)
        raise HTTPException(status_code=400, detail="finding_id must be a valid UUID.") from exc


def _validate_oob_secret(secret: str, expected: str) -> None:
    """Constant-time comparison of the OOB callback secret.

    V5 Sprint 8: This function is now used to validate the per-finding
    ``oob_token`` (passed in the URL path) against the token stored on
    the finding row in the database. The global ``oob_callback_secret``
    setting is no longer used as a credential — it serves only as an
    on/off switch for the OOB feature (checked once in
    ``_process_oob_callback`` before we even hit the DB).

    Using ``secrets.compare_digest`` rather than ``==`` prevents timing
    side-channels that would let an attacker recover the token by
    measuring response latency across many requests.
    """
    import secrets as _secrets

    if not expected:
        # Fail-safe: empty token on the finding row means either (a) the
        # finding predates Sprint 8 and was never migrated, or (b) the
        # finding was created with an explicit empty token (should never
        # happen given the default_factory). Either way, refuse to
        # confirm — we never want to issue an OOB URL that the target
        # could trivially guess.
        logger.warning(
            "OOB callback rejected: finding has no oob_token stored "
            "(pre-Sprint-8 row or corruption)."
        )
        raise HTTPException(
            status_code=503,
            detail="OOB confirmation unavailable for this finding.",
        )
    if not _secrets.compare_digest(str(secret).encode(), expected.encode()):
        logger.warning("OOB callback rejected: oob_token mismatch for finding")
        raise HTTPException(status_code=403, detail="Forbidden.")


def _digest_oob_body(body: bytes) -> str:
    """Truncate + sanitize an OOB callback body for the reasoning trail.

    We deliberately do NOT echo the raw body back into the DB or any
    log — that would let a malicious target inject arbitrary text into
    our audit trail. We only keep the first 256 bytes (URL-encoded) so
    the operator has a minimal forensic breadcrumb.
    """
    if not body:
        return "(empty body)"
    truncated = body[:_OOB_BODY_MAX_BYTES]
    # Decode defensively; some targets send binary blobs.
    try:
        text = truncated.decode("utf-8", errors="replace")
    except Exception:
        text = repr(truncated)
    # Strip newlines so the digest stays on one reasoning line.
    text = " ".join(text.split())
    return text[:_OOB_BODY_DIGEST_LEN]


# Synchronous helper that runs in a worker thread (via asyncio.to_thread)
# so the async FastAPI event loop is never blocked by SQLite I/O.
def _oob_db_lookup_and_record_advisory(
    finding_id: UUID,
    reasoning_appendix: str,
    callback_context: dict[str, Any] | None = None,
) -> Finding | None:
    """Thread-safe DB lookup + ADVISORY evidence record (R3 E-1).

    Callable from asyncio.to_thread. The caller passes the path ``secret``
    via the closure; this function reads the finding's stored ``oob_token``
    from the DB and the caller compares it in constant time.

    R3 E-1 (Ruling R3-002 §3.2 — BYP-02 advisory demotion; supersedes the
    TEAM-1 Phase 1 behavior described in earlier revisions of this
    docstring): a valid, correlated OOB callback NO LONGER builds or seals
    a ProofBundle and NO LONGER flips the finding's confidence. Instead it
    appends an ADDITIVE, OPTIONAL, AUTHORITY-NEUTRAL advisory evidence
    record (``Finding.advisory_evidence``) via the persistence layer's
    advisory sibling write:

      * ``confidence`` and ``confidence_level`` are NEVER changed here;
      * no ProofBundle is constructed, sealed, or persisted here;
      * no confirmation marker is written anywhere;
      * the append is replay-idempotent — callbacks are deduplicated per
        correlation token (RF-04), so a repeated callback collapses to the
        single existing record and reports idempotent success;
      * malformed callback input is rejected before any write opens, so a
        bad payload can never leave partial state.

    Authority stays exclusively inside the audited promotion pipeline:
    an OOB observation recorded here is advisory context for operators,
    never a confirmation. (Amendment A: this docstring replaces the stale
    handler-side description that still documented the seal-and-confirm
    behavior; the removed semantics are auditable in the R2/R3 dossiers.)

    Returns the (authority-unchanged) Finding on success, or ``None`` if
    the finding was not found (404). Token mismatch is signalled by
    raising HTTPException (403), which propagates through to_thread.
    """
    # V6 DX-Final P0 FIX (CISO audit): use shared singleton.
    db = get_db_manager()
    finding = db.get_finding(finding_id)
    if finding is None:
        return None

    context = dict(callback_context or {})
    advisory_record = {
        "type": "oob_callback_advisory",
        "note": (
            "Advisory only — correlated out-of-band observation. Does NOT "
            "affect confidence, promotion, or sealing authority."
        ),
        "evidence_refs": [
            f"oob-callback:{finding_id}",
            f"oob-token-correlated:{finding.oob_token is not None}",
            f"source:{context.get('client_host', 'unknown')}",
            f"transport:{context.get('method', 'unknown')}",
            f"body_digest:{context.get('body_digest', 'none')}",
            f"observed_at:{context.get('callback_ts', 'unknown')}",
        ],
        "transport": {
            "method": context.get("method"),
            "client_host": context.get("client_host"),
            "body_digest": context.get("body_digest"),
        },
    }
    updated, status = db.append_oob_advisory_evidence(
        finding_id,
        correlation_token=str(finding.oob_token or ""),
        record=advisory_record,
    )
    if updated is None:
        return None
    # Surface the idempotency outcome to the caller for honest logging.
    logger.info(
        "OOB callback for finding %s recorded as ADVISORY evidence "
        "(status=%s; confidence_level=%r unchanged; no ProofBundle built).",
        finding_id,
        status,
        updated.confidence_level,
    )
    return updated


def _reject_if_oob_confirm_route_disabled() -> None:
    """Sprint R1 FIX 2: fail-closed master switch for the OOB callback
    routes, default disabled. Retained unchanged under R3 E-1 §3.2(vi):
    the default-off route flag composes with the advisory demotion.

    Before R3 E-1, this helper's docstring described the seal-and-confirm
    behavior (ProofBundle construction + ``db.mark_oob_confirmed``) that
    the OOB lookup performed after this gate. Under the ruling the same
    call site now records an AUTHORITY-NEUTRAL advisory evidence record —
    no ProofBundle, no confidence mutation. The gate's contract is
    unchanged and remains load-bearing: callers of both OOB routes MUST
    invoke this before doing anything else (including audit logging) so
    that a disabled route performs zero DB activity of any kind.
    """
    settings = get_settings()
    if not settings.oob_confirm_route_enabled:
        logger.warning(
            "OOB callback rejected: oob_confirm_route_enabled is False — "
            "OOB confirmation route disabled. Set "
            "WEBPENT_OOB_CONFIRM_ROUTE_ENABLED=true to enable."
        )
        raise HTTPException(status_code=404, detail="Not Found")


def _oob_db_lookup(finding_id: UUID) -> Finding | None:
    """Thread-safe DB lookup — callable from asyncio.to_thread."""
    # V6 DX-Final P0 FIX (CISO audit): use shared singleton.
    db = get_db_manager()
    return db.get_finding(finding_id)


async def _process_oob_callback(
    finding_id: UUID,
    request: Request,
    thread_id: str | None = None,
) -> None:
    """Shared handler for GET and POST OOB callbacks.

    V5 Sprint 8: Per-finding token validation. The path ``secret``
    segment is compared against the finding's stored ``oob_token`` (not
    the global secret). This closes the spoofing vulnerability where a
    malicious target that observed one OOB URL could forge callbacks
    for unrelated findings.

    V5 Sprint 8: All DatabaseManager calls are offloaded to a worker
    thread via ``asyncio.to_thread`` so the FastAPI event loop is never
    blocked by synchronous SQLite I/O. This is critical because the OOB
    endpoint may receive many concurrent callbacks during a scan, and
    blocking the event loop would stall every other request (including
    the validator's status polls).

    TEAM-1 Phase 1 (OOB database parity): when the callback URL carries
    the engagement ``thread_id`` (3-segment form), the API resolves the
    SAME engagement workspace the worker used, activates it, and performs
    the lookup + confirmation against the workspace database. Previously
    this handler resolved ``get_db_manager()`` to the API process's
    default database while the worker had persisted the finding inside
    the per-workspace database — the callback 404'd and every OOB
    confirmation was silently lost. The ContextVar-based workspace
    activation propagates through ``asyncio.to_thread`` copies, so the
    sync helpers keep resolving ``get_db_manager()`` correctly.
    """
    settings = get_settings()
    # The global secret is now an on/off switch, not a credential.
    if not settings.oob_callback_secret:
        logger.warning(
            "OOB callback rejected: oob_callback_secret is empty — "
            "OOB feature disabled. Set WEBPENT_OOB_CALLBACK_SECRET "
            "to enable."
        )
        raise HTTPException(
            status_code=503,
            detail="OOB confirmation is disabled (no secret configured).",
        )

    # The path "secret" segment is the per-finding oob_token.
    path_token = request.path_params.get("secret", "")

    # TEAM-1 Phase 1 (OOB database parity): resolve the engagement workspace
    # the worker used, so lookup + confirmation run against the SAME
    # workspace database where the finding was persisted. The legacy
    # 2-segment URL form (no thread_id) keeps the historical default-database
    # behavior for deployments that never activate workspaces.
    workspace_objects: tuple[Any, Any] | None = None
    if thread_id:
        try:
            thread_uuid = UUID(str(thread_id))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Malformed engagement id.") from exc

        def _resolve_workspace():
            from webpent.api.scan_registry import get_scan_record

            record = get_scan_record(str(thread_uuid))
            if record is None:
                return None
            return _workspace_for_record(record)

        try:
            workspace = await asyncio.to_thread(_resolve_workspace)
        except Exception as exc:
            logger.exception(
                "OOB callback workspace resolution failed for thread %s: %s",
                thread_id,
                exc,
            )
            workspace = None
        if workspace is not None:
            workspace_objects = (workspace, _settings_for_workspace(workspace))
            logger.info(
                "OOB callback: resolved engagement workspace %s for finding %s",
                workspace.workspace_id,
                finding_id,
            )
        else:
            # IMPL P0-A (OOB parity, fail-closed): a 3-segment callback URL
            # (the only form the validator issues) whose thread has no scan
            # registry record used to fall back to the DEFAULT database —
            # the exact split-brain the workspace resolution was added to
            # prevent. The worker persisted the finding in the workspace DB;
            # confirming against the default DB would silently target the
            # wrong persistence authority (or 404 later). Fail closed.
            logger.warning(
                "OOB callback: no scan registry record for thread %s — "
                "refusing default-database fallback (split-brain protection).",
                thread_id,
            )
            raise HTTPException(
                status_code=404,
                detail=(
                    "OOB callback rejected: engagement workspace could not "
                    "be resolved for this thread id."
                ),
            )

    def _workspace_stack():
        """Enter a FRESH workspace activation for one DB step.

        Each step gets its own ExitStack because activation is not
        re-entrant across ``with`` blocks (the stack unwinds on exit).
        """
        if workspace_objects is None:
            return None
        workspace, workspace_settings = workspace_objects
        stack = contextlib.ExitStack()
        stack.enter_context(activate_target_workspace(workspace))
        stack.enter_context(activate_settings(workspace_settings))
        return stack

    # V5 Sprint 8: offload the DB lookup to a thread so we don't block
    # the event loop on SQLite I/O.
    lookup_stack = _workspace_stack()
    try:
        if lookup_stack is not None:
            with lookup_stack:
                finding = await asyncio.to_thread(_oob_db_lookup, finding_id)
        else:
            finding = await asyncio.to_thread(_oob_db_lookup, finding_id)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("OOB callback DB lookup failed for %s: %s", finding_id, exc)
        raise HTTPException(status_code=500, detail="Failed to look up finding.") from exc

    if finding is None:
        logger.warning(
            "OOB callback: finding %s not found in DB (possible replay or stale callback URL).",
            finding_id,
        )
        raise HTTPException(status_code=404, detail="Finding not found.")

    # V5 Sprint 8: validate the path token against the finding's stored
    # per-finding oob_token. This is the spoofing fix — every finding
    # has its own unguessable 32-char hex token.
    _validate_oob_secret(path_token, finding.oob_token)

    # V9 FIX-3: Read the body with a hard ceiling so a malicious target
    # cannot exhaust server memory by streaming a 10 GB POST body.
    # Previous code used ``await request.body()`` which loads the entire
    # body into RAM unbounded. Now we stream with a 64KB hard cap.
    oob_max_body = 64 * 1024  # 64 KB — more than enough for an OOB callback
    body = b""
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > oob_max_body:
                body += chunk[: oob_max_body - len(body)]
                logger.warning(
                    "OOB callback: body truncated at %d bytes (limit=%d)",
                    len(body),
                    oob_max_body,
                )
                break
            body += chunk
    except Exception as exc:
        logger.warning("OOB callback: could not read body: %s", exc)
    body_digest = _digest_oob_body(body)

    client_host = request.client.host if request.client else "unknown"
    callback_ts = datetime.now(timezone.utc).isoformat()
    reasoning_appendix = (
        f"OOB Callback Received from {client_host} at {callback_ts} "
        f"(method={request.method}, body_digest={body_digest!r})."
    )

    # V5 Sprint 8: offload the DB write to a thread as well. The workspace
    # context (Phase 1) is re-entered so the confirm targets the same
    # workspace database the lookup just read.
    confirm_stack = _workspace_stack()
    callback_context = {
        "method": request.method,
        "client_host": client_host,
        "body_digest": body_digest,
        "callback_ts": callback_ts,
        "thread_id": thread_id,
    }
    try:
        if confirm_stack is not None:
            with confirm_stack:
                updated = await asyncio.to_thread(
                    _oob_db_lookup_and_record_advisory,
                    finding_id,
                    reasoning_appendix,
                    callback_context,
                )
        else:
            updated = await asyncio.to_thread(
                _oob_db_lookup_and_record_advisory,
                finding_id,
                reasoning_appendix,
                callback_context,
            )
    except HTTPException:
        raise
    except (TypeError, ValueError) as exc:
        # R3 E-1 / RF-04 contract: malformed callback input is rejected by
        # the persistence layer BEFORE any write opens. Surface it as a
        # HANDLED 400 (never an unhandled 500) with the finding untouched.
        logger.warning(
            "OOB callback for finding %s rejected (malformed advisory "
            "payload; no partial state written): %s",
            finding_id,
            exc,
        )
        raise HTTPException(
            status_code=400,
            detail="OOB callback payload malformed; nothing was recorded.",
        ) from exc
    except Exception as exc:
        logger.exception("OOB callback DB update failed for %s: %s", finding_id, exc)
        raise HTTPException(status_code=500, detail="Failed to record OOB callback.") from exc

    if updated is None:
        # Finding vanished between lookup and confirm (race) — treat as 404.
        logger.warning(
            "OOB callback: finding %s disappeared during confirm.",
            finding_id,
        )
        raise HTTPException(status_code=404, detail="Finding not found.")

    # R3 E-1 (Ruling R3-002 §3.2(ii) — RF-03 MANDATORY HUNK): the handler-
    # side parity check now validates the ADVISORY state, not the
    # Tool-Confirmed flip. The demoted path must return 204 exactly when a
    # correlated advisory record exists (appended now, or already present
    # from a replayed callback) — and the finding's confidence semantics
    # must be untouched. RED-1 proved every valid callback 500s without
    # this hunk post-demotion.
    advisory_records = list(updated.advisory_evidence or [])
    if not advisory_records:
        logger.error(
            "OOB callback for finding %s was NOT recorded: advisory state "
            "missing after the advisory write (invariant violation).",
            finding_id,
        )
        raise HTTPException(
            status_code=500,
            detail="OOB advisory record was not persisted by the persistence authority.",
        )
    if str(getattr(updated, "confidence_level", "") or "") == "Tool-Confirmed":
        # The demoted path can never see a Tool-Confirmed row here: the
        # advisory write structurally cannot flip confidence. If one
        # appears, something outside the audited path mutated authority —
        # fail loudly. (getattr preserved from the pre-R3 parity check at
        # this same site: the g02 dynamic-resolution identity position is
        # unchanged, so the inventory regen stays a pure line drift.)
        logger.error(
            "OOB callback for finding %s: confidence_level is Tool-Confirmed "
            "on the advisory path — unauthorized confidence mutation detected "
            "(observed level: %r).",
            finding_id,
            getattr(updated, "confidence_level", None),
        )
        raise HTTPException(
            status_code=500,
            detail="OOB advisory path observed unauthorized confirmation state.",
        )

    logger.info(
        "OOB callback recorded as ADVISORY evidence for finding %s (url=%s) — "
        "confidence unchanged; authority untouched (R3 E-1).",
        finding_id,
        updated.url,
    )


@app.api_route(
    "/api/oob/{finding_id}/{secret}",
    methods=["GET", "POST"],
    status_code=204,
)
async def receive_oob_callback(finding_id: str, request: Request) -> Response:
    """OOB callback receiver — records ADVISORY evidence (R3 E-1).

    Accepts both GET (typical for SSRF — target fetches a URL) and
    POST (useful for RCE scenarios where the payload exfiltrates via
    HTTP POST). The handler is identical for both methods; only the
    body digest recorded into the advisory evidence record differs.

    R3 E-1 (Ruling R3-002 §3.2): a valid, correlated callback appends an
    authority-neutral ADVISORY evidence record to the finding. It NEVER
    seals a ProofBundle and NEVER changes confidence/confidence_level —
    the response is 204 on a recorded (or replay-idempotent duplicate)
    advisory record, and the finding's authority state is untouched.

    Path parameters:
      * ``finding_id``: UUID of the finding to record advisory evidence
        against. Must be a canonical UUID string; anything else is
        rejected with 400.
      * ``secret``: Must match ``Settings.oob_callback_secret``.
        Compared in constant time. Empty server-side secret → 503.

    Returns:
        204 No Content on success — advisory record appended, or an
        idempotent replay collapsed to the existing record (RF-04) —
        with an empty body so no framework internals leak to the target.
        400 (malformed payload / bad UUID — nothing recorded), 403
        (token mismatch), 404 (unknown finding), 500 (invariant
        violation) on the various failure modes documented above.
    """
    _reject_if_oob_confirm_route_disabled()
    finding_uuid = _validate_oob_finding_id(finding_id)
    # POST-P0 Phase 9: OOB callbacks are operator-relevant security
    # events — record them in the audit trail (digest-level metadata
    # only; never payload contents or secrets).
    from webpent.memory.decision_log import log_operator_event

    log_operator_event(
        action="oob_callback",
        thread_id=None,
        actor="target",
        outcome="received",
        metadata={"finding_id": str(finding_uuid)},
    )
    await _process_oob_callback(finding_uuid, request)
    return Response(status_code=204)


@app.api_route(
    "/api/oob/{thread_id}/{finding_id}/{secret}",
    methods=["GET", "POST"],
    status_code=204,
)
async def receive_oob_callback_scoped(
    thread_id: str,
    finding_id: str,
    request: Request,
) -> Response:
    """Workspace-scoped OOB callback receiver (TEAM-1 Phase 1 parity fix).

    The validator now embeds the engagement ``thread_id`` in every OOB URL
    it issues. This route resolves the scan registry record for that
    engagement, rebuilds the SAME target workspace the worker used, and
    performs the finding lookup + confirmation against the workspace
    database — closing the API/worker database split that previously made
    every OOB callback 404 (the finding lived in the workspace database,
    the handler looked in the default database).

    Authentication is unchanged: the per-finding ``oob_token`` path segment
    is still compared in constant time against the row's stored token. The
    thread_id only routes the lookup to the right database; it grants no
    privilege by itself.

    Path parameters:
      * ``thread_id``: engagement identifier (UUID) from the OOB URL.
      * ``finding_id``: UUID of the finding to confirm.
      * ``secret``: per-finding token (constant-time compared).

    Returns:
        204 on success; 400/404/500 on the documented failure modes.
        (IMPL P0-A: an unknown thread_id NO LONGER falls back to the
        default database — that fallback was the split-brain this route
        exists to prevent. Unresolvable threads fail closed with 404.)
    """
    _reject_if_oob_confirm_route_disabled()
    finding_uuid = _validate_oob_finding_id(finding_id)
    await _process_oob_callback(finding_uuid, request, thread_id=thread_id)
    return Response(status_code=204)
