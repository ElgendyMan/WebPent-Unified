"""POST-P0 Phase 3 — session liveness + bounded re-auth service.

Authenticated hunting must not silently degrade mid-run. This service
is the single shared liveness seam:

  * ``probe`` re-verifies the current session with ONE safe request
    (reusing the auth agent's battle-tested
    ``_validate_session_cookies`` heuristic),
  * ``ensure_live`` is the pre-phase hook: probe → if dead, bounded
    re-login (at most 2 attempts per run, reusing the shared
    ``_perform_login`` routine and the reauth vault) → if still dead,
    request an explicit downgrade so findings land in
    ``Needs Human Review`` instead of being validated with a dead
    session (false "not injectable" results),
  * the liveness record stored in state is REDACTED BY CONSTRUCTION:
    it carries statuses, timestamps, attempt counters, and reason
    strings — never cookie values or credentials.

Scope rules (unchanged from the authentication agent):
  * credentials resolve state password first, then the reauth vault,
  * operator cookies live in ``session_cookies`` (merge_dicts) and the
    vault, stale keys are neutralized to "" following the existing
    merge-dicts invalidation convention,
  * the browser proof path remains deliberately cookie-free (the
    account-action policy blocks cookie injection in the sandbox —
    this service does NOT weaken that control).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "SESSION_LIVENESS_SCHEMA_VERSION",
    "MAX_REAUTH_ATTEMPTS_PER_RUN",
    "build_empty_record",
    "probe_session",
    "ensure_live_session",
    "phase_liveness_update",
]

SESSION_LIVENESS_SCHEMA_VERSION = "session-liveness-v1"
MAX_REAUTH_ATTEMPTS_PER_RUN = 2

_STATUS_UNKNOWN = "unknown"
_STATUS_HEALTHY = "healthy"
_STATUS_STALE = "stale"
_STATUS_INVALID = "invalid"


def build_empty_record() -> dict[str, Any]:
    """Initial (unknown) liveness record — no probe has run yet."""
    return {
        "schema_version": SESSION_LIVENESS_SCHEMA_VERSION,
        "status": _STATUS_UNKNOWN,
        "last_verified_at": None,
        "last_probe_reason": "",
        "reauth_attempts": 0,
        "max_reauth_attempts": MAX_REAUTH_ATTEMPTS_PER_RUN,
        "downgrade_requested": False,
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def probe_session(target_url: str, cookies: dict[str, str]) -> tuple[bool, str]:
    """One safe liveness probe. Returns (alive, reason).

    Delegates to the authentication agent's ``_validate_session_cookies``
    (redirect-to-login / 401/403 / login-indicator heuristics, SSRF-pinned
    client). Never raises — a probe error is reported as
    ``probe_error`` (treated as not-alive so callers fail closed).
    """
    if not cookies:
        return False, "no_cookies"
    try:
        from webpent.agents.authentication.agent import _validate_session_cookies

        alive, reason = _validate_session_cookies(target_url, dict(cookies))
        return bool(alive), str(reason or "unknown")
    except Exception as exc:
        logger.warning("Session liveness probe failed closed: %s", type(exc).__name__)
        return False, "probe_error"


def _resolve_reauth_password(state: dict[str, Any], thread_id: str | None) -> str | None:
    """Credentials resolve exactly like the validator: state then vault."""
    credentials = state.get("credentials") or {}
    password = str(credentials.get("password") or "").strip()
    if password:
        return password
    if thread_id:
        try:
            from webpent.auth.reauth_vault import unseal_reauth_secret

            vaulted = unseal_reauth_secret(thread_id)
            if vaulted:
                return str(vaulted)
        except Exception:
            logger.warning(
                "unseal_reauth_secret failed for thread %s; no vaulted credential available",
                thread_id,
                exc_info=True,
            )
            return None
    return None


def _record(
    current: dict[str, Any] | None,
) -> dict[str, Any]:
    """Normalize a possibly-missing/partial record onto the schema."""
    record = build_empty_record()
    if isinstance(current, dict):
        for key in record:
            if key in current and current[key] is not None:
                record[key] = current[key]
    try:
        attempts = max(0, int(record.get("reauth_attempts") or 0))
    except (TypeError, ValueError):
        attempts = 0
    record["reauth_attempts"] = attempts
    return record


def ensure_live_session(
    state: dict[str, Any],
    *,
    target_url: str | None = None,
    thread_id: str | None = None,
) -> dict[str, Any]:
    """Pre-phase liveness gate. Returns a PARTIAL STATE UPDATE (never raises).

    Behaviour:
      * no session cookies in state → status stays ``unknown``, no-op
        (unauthenticated engagements are not this service's concern),
      * alive → status ``healthy`` + ``last_verified_at`` stamped,
      * dead → bounded re-login (≤ ``MAX_REAUTH_ATTEMPTS_PER_RUN`` per
        run). Success refreshes ``session_cookies`` (stale keys
        neutralized to "" per the merge-dicts convention) and stamps
        ``healthy``. Final failure sets ``invalid`` +
        ``downgrade_requested`` so downstream validation honestly parks
        affected findings in ``Needs Human Review``.

    The returned record never contains cookie or credential values.
    """
    from webpent.state.reducers import model_get

    target = state.get("target")
    resolved_target = str(target_url or model_get(target, "url") or "").strip()
    cookies = dict(state.get("session_cookies") or {})
    record = _record(state.get("session_liveness"))

    if not cookies:
        # No session to watch — leave the record untouched (unknown).
        return {"session_liveness": record}
    if not resolved_target:
        record["status"] = _STATUS_UNKNOWN
        record["last_probe_reason"] = "missing_target"
        return {"session_liveness": record}

    alive, reason = probe_session(resolved_target, cookies)
    if alive:
        record["status"] = _STATUS_HEALTHY
        record["last_verified_at"] = _now_iso()
        record["last_probe_reason"] = reason
        return {"session_liveness": record}

    # Session is dead (or probe failed). Bounded re-auth.
    attempts = int(record.get("reauth_attempts") or 0)
    if attempts >= MAX_REAUTH_ATTEMPTS_PER_RUN:
        record["status"] = _STATUS_INVALID
        record["last_probe_reason"] = reason
        record["downgrade_requested"] = True
        logger.error(
            "Session liveness: re-auth budget exhausted (%d/%d) — "
            "downgrade requested (no cookie values logged).",
            attempts,
            MAX_REAUTH_ATTEMPTS_PER_RUN,
        )
        return {"session_liveness": record}

    password = _resolve_reauth_password(state, thread_id)
    username = str((state.get("credentials") or {}).get("username") or "").strip()
    if not password or not username:
        # No usable credentials: cannot re-auth → fail closed to invalid
        # when the validator already had a live session expectation.
        record["status"] = _STATUS_INVALID
        record["last_probe_reason"] = f"{reason}+no_credentials"
        record["downgrade_requested"] = True
        return {"session_liveness": record}

    try:
        from webpent.agents.authentication.agent import _perform_login

        fresh = _perform_login(resolved_target, username, password)
    except Exception as exc:
        logger.warning("Session re-login attempt failed: %s", type(exc).__name__)
        fresh = {}
    attempts += 1
    record["reauth_attempts"] = attempts

    if fresh:
        alive2, reason2 = probe_session(resolved_target, dict(fresh))
        if alive2:
            stale_keys = {k: "" for k in cookies if k not in fresh}
            record["status"] = _STATUS_HEALTHY
            record["last_verified_at"] = _now_iso()
            record["last_probe_reason"] = f"reauth:{reason2}"
            record["downgrade_requested"] = False
            update: dict[str, Any] = {
                "session_liveness": record,
                # merge_dicts: fresh values overwrite, stale keys -> "".
                "session_cookies": {**stale_keys, **dict(fresh)},
            }
            logger.info(
                "Session liveness: re-auth succeeded (attempt %d/%d).",
                attempts,
                MAX_REAUTH_ATTEMPTS_PER_RUN,
            )
            return update

    record["status"] = _STATUS_INVALID if attempts >= MAX_REAUTH_ATTEMPTS_PER_RUN else _STATUS_STALE
    record["last_probe_reason"] = reason
    if attempts >= MAX_REAUTH_ATTEMPTS_PER_RUN:
        record["downgrade_requested"] = True
    logger.error(
        "Session liveness: re-auth attempt %d/%d failed — session %s "
        "(no cookie values logged).",
        attempts,
        MAX_REAUTH_ATTEMPTS_PER_RUN,
        record["status"],
    )
    return {"session_liveness": record}


def phase_liveness_update(state: dict[str, Any], *, phase: str) -> dict[str, Any]:
    """Pre-phase liveness gate for heavy session-consuming nodes.

    SCENARIO CONTRACT (step 9: probe before heavy phases): heavy phases
    (crawler, access-control mapping, business-logic fuzzing) must not run
    on a silently dead session. This wraps :func:`ensure_live_session` and
    additionally appends a DECLARED limitation when a downgrade was
    requested, so the report states the constraint openly.

    Returns a partial state update (never raises):
      * ``session_liveness`` record (redacted by construction),
      * refreshed ``session_cookies`` when a bounded re-login succeeded
        (stale keys neutralized per the merge-dicts convention),
      * ``engagement_limitations`` append-only records on downgrade.

    Unauthenticated engagements (no cookies in state) get a no-op record.
    """
    update = ensure_live_session(state)
    limitations: list[dict[str, str]] = []
    record = update.get("session_liveness") or {}
    try:
        downgrade = bool(record.get("downgrade_requested"))
    except Exception:  # noqa: BLE001 — the gate must never crash a phase
        downgrade = False
    if downgrade:
        limitations.append(
            {
                "code": "session_downgraded",
                "detail": (
                    f"the session went stale before the {phase} phase and the "
                    "bounded re-auth budget was exhausted; session-dependent "
                    f"coverage in {phase} is degraded or absent"
                ),
                "source": f"session_liveness:{phase}",
            }
        )
        logger.error(
            "Session liveness gate (%s): downgrade requested — no cookie "
            "values logged.",
            phase,
        )
    if limitations:
        update["engagement_limitations"] = limitations
    return update
