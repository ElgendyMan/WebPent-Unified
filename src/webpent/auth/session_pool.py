# src/webpent/auth/session_pool.py
"""Multi-principal session pool (2026-10-25 Proposal 5).

One pool per engagement holds one session per principal role, with a
health layer that never lets a dead session produce results:

  * ``acquire(role)`` returns a HEALTHY session or None. A stale
    session is health-checked first; a dead one is re-authenticated
    through the registered ``reauth`` callback; a session that cannot
    be recovered fails CLOSED — the caller gets None, never a dead
    session (zero results from dead sessions is the contract).
  * ``register_reauth(role, callback)`` attaches a bounded re-auth
    callable per role (one attempt per acquire, counted on the record).
  * ``snapshot()`` is a READ-ONLY status view (role, healthy, age,
    re-auth count) — it never exposes session material (cookies or
    headers are not secrets to be logged).

The pool is deliberately NOT thread-shared state across engagements:
module-level registries (``set_pool`` / ``pop_pool`` / ``snapshot_all``)
key pools by engagement id and are bounded (``_MAX_REGISTERED_POOLS``),
sweeping dropped engagements on read. The clock is injected so tests
can advance time without sleeping.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

__all__ = [
    "SessionRecord",
    "SessionPool",
    "set_pool",
    "pop_pool",
    "snapshot_all",
    "DEFAULT_HEALTH_INTERVAL_SECONDS",
    "MAX_SESSIONS_PER_POOL",
    "MAX_REGISTERED_POOLS",
]

DEFAULT_HEALTH_INTERVAL_SECONDS = 300.0
MAX_SESSIONS_PER_POOL = 8
MAX_REGISTERED_POOLS = 64

HealthProbe = Callable[[str, Any], bool]
ReauthCallback = Callable[[str], Any | None]


@dataclass
class SessionRecord:
    role: str
    session: Any = None
    created_at: float = 0.0
    last_checked_at: float = 0.0
    healthy: bool = True
    reauth_count: int = 0

    def age_seconds(self, now: float) -> float:
        return max(0.0, now - self.created_at) if self.created_at else 0.0


class SessionPool:
    """One role -> one live-or-failed session, health-checked lazily."""

    def __init__(
        self,
        *,
        health_probe: HealthProbe | None = None,
        reauth: ReauthCallback | None = None,
        health_interval: float = DEFAULT_HEALTH_INTERVAL_SECONDS,
        max_sessions: int = MAX_SESSIONS_PER_POOL,
        now: Callable[[], float] | None = None,
    ) -> None:
        self._health_probe = health_probe
        self._reauth = reauth
        self._health_interval = max(0.0, float(health_interval))
        self._max_sessions = max(1, int(max_sessions))
        self._now = now or time.time
        self._sessions: dict[str, SessionRecord] = {}
        self._reauth_callbacks: dict[str, ReauthCallback] = {}

    def register(self, role: str, session: Any) -> bool:
        """Seed a role's session. Bounded; re-registration replaces."""
        if len(self._sessions) >= self._max_sessions and role not in self._sessions:
            return False
        self._sessions[role] = SessionRecord(
            role=role, session=session, created_at=self._now(), last_checked_at=self._now()
        )
        return True

    def register_reauth(self, role: str, callback: ReauthCallback) -> bool:
        """Attach a bounded re-auth callable for a role."""
        if callback is None:
            return False
        self._reauth_callbacks[role] = callback
        return True

    def _probe_healthy(self, role: str, record: SessionRecord) -> bool:
        if self._health_probe is None:
            return record.healthy
        try:
            return bool(self._health_probe(role, record.session))
        except Exception:  # noqa: BLE001 — probe failure = unhealthy, fail-closed
            return False

    def _try_reauth(self, role: str) -> Any | None:
        callback: ReauthCallback | None = None
        if self._reauth is not None:
            callback = self._reauth_callbacks.get(role, self._reauth)
        else:
            callback = self._reauth_callbacks.get(role)
        if callback is None:
            return None
        try:
            return callback(role)
        except Exception:  # noqa: BLE001 — re-auth failure = None, fail-closed
            return None

    def acquire(self, role: str) -> Any | None:
        """Return a healthy session for the role, or None.

        Fail-closed order: healthy + fresh -> as-is; stale -> probe;
        probe-dead -> one bounded re-auth attempt; still dead -> None.
        A role with NO registered session and a working re-auth
        callback can still be acquired (the callback is the source of
        truth for that role's liveness).
        """
        record = self._sessions.get(role)
        if record is None:
            session = self._try_reauth(role)
            if session is None:
                return None
            self.register(role, session)
            self._sessions[role].reauth_count = 1
            return session

        now = self._now()
        fresh = (now - record.last_checked_at) < self._health_interval
        if fresh and record.healthy:
            return record.session
        if fresh and not record.healthy:
            # Already known dead and re-auth already failed once.
            return None

        record.last_checked_at = now
        if self._probe_healthy(role, record):
            record.healthy = True
            return record.session
        record.healthy = False
        session = self._try_reauth(role)
        if session is None:
            return None
        record.session = session
        record.healthy = True
        record.created_at = self._now()
        record.last_checked_at = self._now()
        record.reauth_count += 1
        return session

    def invalidate(self, role: str) -> None:
        record = self._sessions.get(role)
        if record is not None:
            record.healthy = False
            record.last_checked_at = self._now()

    def health_check(self, role: str | None = None) -> dict[str, bool]:
        """Force a health probe (all roles, or one). Read-only outside."""
        roles = [role] if role is not None else list(self._sessions)
        out: dict[str, bool] = {}
        for name in roles:
            record = self._sessions.get(name)
            if record is None:
                out[name] = False
                continue
            healthy = self._probe_healthy(name, record)
            record.healthy = healthy
            record.last_checked_at = self._now()
            out[name] = healthy
        return out

    def snapshot(self) -> list[dict[str, Any]]:
        """READ-ONLY status view — no session material leaves the pool."""
        now = self._now()
        return [
            {
                "role": record.role,
                "healthy": record.healthy,
                "age_seconds": round(record.age_seconds(now), 1),
                "last_checked_seconds_ago": (
                    round(max(0.0, now - record.last_checked_at), 1)
                    if record.last_checked_at
                    else None
                ),
                "reauth_count": record.reauth_count,
            }
            for record in self._sessions.values()
        ]


_POOLS: dict[str, SessionPool] = {}


def set_pool(engagement_id: str, pool: SessionPool) -> None:
    """Register a pool under an engagement id. Bounded; oldest dropped."""
    if len(_POOLS) >= MAX_REGISTERED_POOLS and engagement_id not in _POOLS:
        oldest = next(iter(_POOLS))
        _POOLS.pop(oldest, None)
    _POOLS[engagement_id] = pool


def pop_pool(engagement_id: str) -> SessionPool | None:
    return _POOLS.pop(engagement_id, None)


def snapshot_all() -> list[dict[str, Any]]:
    """Read-only fleet view across registered pools, bounded."""
    out: list[dict[str, Any]] = []
    for engagement_id, pool in list(_POOLS.items()):
        for record in pool.snapshot():
            out.append({"engagement_id": engagement_id, **record})
    return out[:MAX_REGISTERED_POOLS * MAX_SESSIONS_PER_POOL]
