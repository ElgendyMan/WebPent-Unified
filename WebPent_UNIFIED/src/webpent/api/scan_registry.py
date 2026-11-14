# src/webpent/api/scan_registry.py
"""webpent.api.scan_registry

V10 P0-0 fix: thread_id ↔ task_id mapping store.

Problem
-------
POST /api/v1/scans generates a ``thread_id`` (uuid4) for the LangGraph
configurable, dispatches ``run_pentest_task.delay(...)`` which returns a
Celery ``task_id``, and returns BOTH to the client. But the mapping is
never persisted anywhere — not in DB, not in Redis, not in memory.

GET /api/v1/scans/{thread_id}/status only has ``thread_id``. To consult
``AsyncResult(task_id).state`` (the authoritative Celery signal —
PENDING / STARTED / SUCCESS / FAILURE / RETRY), the API must be able to
look up the corresponding ``task_id``.

This module provides a minimal, dependency-free mapping store backed by
SQLite (the same DB the findings table lives in). It is intentionally
NOT Redis-backed to avoid adding a new failure mode; SQLite is already
a hard dependency.

Schema
------
A single table ``scan_engagements``:

    thread_id    TEXT PRIMARY KEY
    task_id      TEXT NOT NULL
    target_url   TEXT
    created_at   TEXT NOT NULL
    status       TEXT  -- 'running' | 'completed' | 'failed' | 'terminated'

The table is created idempotently on first use (CREATE TABLE IF NOT
EXISTS). No alembic migration is needed — this is a self-contained
registry, not part of the findings schema.

Thread-safety
-------------
All public functions acquire the DatabaseManager's ``_write_lock``
(mutual exclusion with findings writes) for writes, and use the shared
``_connect()`` context for reads. SQLite handles concurrent reads
natively; writes are serialised by the lock.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

_REGISTRY_HEALTH_LOCK = threading.Lock()
_REGISTRY_HEALTH: dict[str, Any] = {
    "ready": False,
    "last_error": None,
    "last_checked_at": None,
}


def _set_registry_health(*, ready: bool, error: str | None = None) -> None:
    with _REGISTRY_HEALTH_LOCK:
        _REGISTRY_HEALTH.update(
            {
                "ready": ready,
                "last_error": error,
                "last_checked_at": datetime.now(timezone.utc).isoformat(),
            }
        )


def scan_registry_health() -> dict[str, Any]:
    """Return non-secret registry readiness evidence for health endpoints."""
    with _REGISTRY_HEALTH_LOCK:
        return dict(_REGISTRY_HEALTH)


SCAN_ENGAGEMENTS_DDL = """
CREATE TABLE IF NOT EXISTS scan_engagements (
    thread_id   TEXT PRIMARY KEY,
    task_id     TEXT NOT NULL,
    target_url      TEXT,
    owner_username  TEXT,
    client_id       TEXT,
    engagement_id   TEXT,
    created_at      TEXT NOT NULL,
    status              TEXT DEFAULT 'running',
    resume_token_hash   TEXT,
    resume_claimed_at   TEXT,
    resume_lease_until  TEXT,
    resume_consumed_at  TEXT,
    resume_consumer_id   TEXT,
    cost_estimate_json   TEXT
);
"""

_SCAN_ENGAGEMENTS_INSERT = """
INSERT OR REPLACE INTO scan_engagements
    (thread_id, task_id, target_url, owner_username, client_id,
     engagement_id, created_at, status, cost_estimate_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

_SCAN_ENGAGEMENTS_SELECT_TASK = """
SELECT task_id FROM scan_engagements WHERE thread_id = ?;
"""

_SCAN_ENGAGEMENTS_SELECT_RECORD = """
SELECT thread_id, task_id, target_url, owner_username, client_id,
       engagement_id, created_at, status, cost_estimate_json
FROM scan_engagements WHERE thread_id = ?;
"""

_SCAN_ENGAGEMENTS_UPDATE_STATUS = """
UPDATE scan_engagements SET status = ? WHERE thread_id = ?;
"""

_SCAN_ENGAGEMENTS_SELECT_STATUS = """
SELECT status FROM scan_engagements WHERE thread_id = ?;
"""

_SCAN_ENGAGEMENTS_SELECT_THREADS_BY_ENGAGEMENT = """
SELECT thread_id
FROM scan_engagements
WHERE engagement_id = ?
  AND owner_username = ?
  AND client_id = ?
ORDER BY created_at ASC
LIMIT 256;
"""

_SCAN_ENGAGEMENTS_SELECT_THREADS_BY_SCOPE = """
SELECT thread_id
FROM scan_engagements
WHERE engagement_id = ?
  AND client_id = ?
ORDER BY created_at ASC
LIMIT 256;
"""

_SCAN_ENGAGEMENTS_SELECT_THREADS_BY_ID = """
SELECT thread_id
FROM scan_engagements
WHERE engagement_id = ?
ORDER BY created_at ASC
LIMIT 256;
"""


def _get_db():
    """Lazy import to avoid circular dependencies at module load time."""
    from webpent.memory.db import get_db_manager

    return get_db_manager()


def _get_registry_db():
    """Resolve the GLOBAL scan-registry database, never a workspace copy.

    IMPL P0-A (split-brain fix): ``scan_engagements`` is written by the API
    process at dispatch time into the process default database. Callers that
    run inside a target-workspace activation (API findings/risk-summary
    aggregation, the in-graph reporter) used to resolve ``get_db_manager()``
    to the workspace copy of the table — an auto-created EMPTY registry — so
    sibling-thread aggregation silently degraded to the current thread only.
    The registry is by definition the default database, so resolution
    bypasses the workspace settings contextvar explicitly via the base
    settings singleton.
    """
    from webpent.config.settings import _base_settings
    from webpent.memory.db import get_db_manager

    return get_db_manager(_base_settings().database_url)


def init_scan_registry(db=None) -> bool:
    """Create or migrate the scan registry table idempotently.

    A failed initialization is recorded and returned to callers so status and
    authorization paths can fail closed instead of silently operating without
    their ownership registry.

    ``db`` optionally targets an explicit database manager (IMPL P0-A):
    the registry lives in the process default database, so callers running
    inside a workspace activation pass ``_get_registry_db()`` to avoid
    creating a misleading empty copy of the table in the workspace DB.
    """
    try:
        db = db or _get_db()
        with db._connect() as conn:
            conn.execute(SCAN_ENGAGEMENTS_DDL)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(scan_engagements)")}
            for name, definition in (
                ("owner_username", "TEXT"),
                ("client_id", "TEXT"),
                ("engagement_id", "TEXT"),
                ("resume_token_hash", "TEXT"),
                ("resume_claimed_at", "TEXT"),
                ("resume_lease_until", "TEXT"),
                ("resume_consumed_at", "TEXT"),
                ("resume_consumer_id", "TEXT"),
                ("cost_estimate_json", "TEXT"),
            ):
                if name not in columns:
                    conn.execute(f"ALTER TABLE scan_engagements ADD COLUMN {name} {definition}")
            conn.commit()
        _set_registry_health(ready=True)
        return True
    except Exception as exc:
        _set_registry_health(ready=False, error=type(exc).__name__)
        logger.error("scan_registry init failed: %s", exc)
        return False


def register_scan(
    thread_id: str,
    task_id: str,
    target_url: str = "",
    *,
    owner_username: str = "",
    client_id: str = "",
    engagement_id: str = "",
    cost_estimate: dict[str, Any] | None = None,
) -> bool:
    """Record the thread_id ↔ task_id mapping at scan dispatch time.

    Called by POST /api/v1/scans immediately after ``run_pentest_task.delay``
    returns. Best-effort: if the DB write fails, the status endpoint will
    fall back to the (now-fixed) graph-checkpoint + inspect.active() path —
    so a registry failure does not break the scan, only weakens the
    status check's Celery cross-check.
    """
    if not thread_id or not task_id:
        return False
    try:
        db = _get_db()
        if not init_scan_registry():
            return False
        with db._write_lock, db._connect() as conn:
            conn.execute(
                _SCAN_ENGAGEMENTS_INSERT,
                (
                    thread_id,
                    task_id,
                    target_url or "",
                    owner_username or "",
                    client_id or "",
                    engagement_id or thread_id,
                    datetime.now(timezone.utc).isoformat(),
                    "running",
                    json.dumps(cost_estimate or {}, sort_keys=True),
                ),
            )
            conn.commit()
        logger.debug(
            "scan_registry: registered thread_id=%s -> task_id=%s owner=%s client=%s engagement=%s",
            thread_id,
            task_id,
            owner_username,
            client_id,
            engagement_id or thread_id,
        )
        return True
    except Exception as exc:
        logger.warning(
            "scan_registry: failed to register thread_id=%s task_id=%s: %s "
            "(status authorization will fail closed for non-admin users)",
            thread_id,
            task_id,
            exc,
        )
        return False


def get_scan_record(thread_id: str) -> dict[str, Any] | None:
    """Return the persisted scan ownership/scope record, if present."""
    if not thread_id:
        return None
    try:
        db = _get_db()
        if not init_scan_registry():
            return None
        with db._connect() as conn:
            row = conn.execute(_SCAN_ENGAGEMENTS_SELECT_RECORD, (thread_id,)).fetchone()
        if row is None:
            return None
        return {
            "thread_id": row[0],
            "task_id": row[1],
            "target_url": row[2] or "",
            "owner_username": row[3] or "",
            "client_id": row[4] or "",
            "engagement_id": row[5] or row[0],
            "created_at": row[6],
            "status": row[7] or "running",
            "cost_estimate": json.loads(row[8] or "{}"),
        }
    except Exception as exc:
        logger.warning("scan_registry: record lookup failed for %s: %s", thread_id, exc)
        return None


def get_thread_ids_by_engagement_id(
    engagement_id: str,
    *,
    owner_username: str = "",
    client_id: str = "",
) -> list[str]:
    """Return bounded sibling scan threads in one authorized engagement scope.

    Owner and client are part of the predicate so a reused engagement label
    cannot cause cross-user or cross-tenant finding bleed.
    """
    if not engagement_id:
        return []
    try:
        # IMPL P0-A: always read the registry from the GLOBAL default
        # database (see _get_registry_db) — inside a workspace activation
        # the previous ``_get_db()`` resolution returned the workspace's
        # empty scan_engagements copy and dropped sibling threads.
        db = _get_registry_db()
        if not init_scan_registry(db=db):
            return []
        if owner_username:
            query = _SCAN_ENGAGEMENTS_SELECT_THREADS_BY_ENGAGEMENT
            params = (engagement_id, owner_username, client_id or "")
        elif client_id:
            query = _SCAN_ENGAGEMENTS_SELECT_THREADS_BY_SCOPE
            params = (engagement_id, client_id)
        else:
            query = _SCAN_ENGAGEMENTS_SELECT_THREADS_BY_ID
            params = (engagement_id,)
        with db._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [str(row[0]) for row in rows if row[0]]
    except Exception as exc:
        logger.warning(
            "scan_registry: engagement thread lookup failed for %s: %s",
            engagement_id,
            exc,
        )
        return []


def lookup_task_id(thread_id: str) -> str | None:
    """Return the Celery task_id for the given thread_id, or None."""
    if not thread_id:
        return None
    try:
        db = _get_db()
        with db._connect() as conn:
            cursor = conn.execute(_SCAN_ENGAGEMENTS_SELECT_TASK, (thread_id,))
            row = cursor.fetchone()
        return row[0] if row else None
    except Exception as exc:
        logger.debug(
            "scan_registry: lookup failed for thread_id=%s: %s",
            thread_id,
            exc,
        )
        return None


def _resume_token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def claim_resume_capability(
    thread_id: str,
    token: str,
    *,
    lease_seconds: int = 300,
) -> bool:
    """Atomically reserve one resume capability for worker delivery.

    Only a new capability may replace a consumed one. An active unconsumed
    lease rejects concurrent approval/retry attempts. The raw capability is
    never persisted; only a SHA-256 digest is stored.
    """
    if not thread_id or not token or lease_seconds <= 0:
        return False
    now = datetime.now(timezone.utc)
    now_text = now.isoformat()
    lease_text = (now + timedelta(seconds=lease_seconds)).isoformat()
    digest = _resume_token_digest(token)
    try:
        db = _get_db()
        if not init_scan_registry():
            return False
        with db._write_lock, db._connect() as conn:
            # P2-05 (0.33.0): single conditional UPDATE — the old
            # SELECT-then-UPDATE pair was serialized only by the
            # in-process threading.Lock, so two API workers could both
            # pass the lease check and overwrite each other's claim.
            # Claim is now allowed exactly when:
            #   (a) a consumed capability exists but the digest differs
            #       (token rotation), OR
            #   (b) unconsumed with a free/expired lease.
            # ISO timestamps share one format (datetime.isoformat on
            # tz-aware UTC values), so lexicographic comparison is sound.
            cursor = conn.execute(
                """
                UPDATE scan_engagements
                SET resume_token_hash = ?, resume_claimed_at = ?,
                    resume_lease_until = ?, resume_consumed_at = NULL
                WHERE thread_id = ?
                  AND (
                        (resume_consumed_at IS NOT NULL
                         AND resume_token_hash != ?)
                        OR
                        (resume_consumed_at IS NULL
                         AND (resume_lease_until IS NULL
                              OR resume_lease_until = ''
                              OR resume_lease_until <= ?))
                      )
                """,
                (digest, now_text, lease_text, thread_id, digest, now_text),
            )
            conn.commit()
            if cursor.rowcount != 1:
                # Row missing, digest already consumed, or lease active —
                # same outcomes the old SELECT pre-check returned False for.
                return False
        return True
    except Exception as exc:
        logger.warning("scan_registry: resume claim failed for %s: %s", thread_id, exc)
        return False


def consume_resume_capability(
    thread_id: str,
    token: str,
    *,
    consumer_id: str = "",
) -> bool:
    """Consume a claimed capability exactly once before graph side effects.

    A retry with the same Celery task id is idempotent; a different task id
    cannot replay the capability.
    """
    if not thread_id or not token:
        return False
    now = datetime.now(timezone.utc)
    digest = _resume_token_digest(token)
    try:
        db = _get_db()
        with db._write_lock, db._connect() as conn:
            existing = conn.execute(
                """
                SELECT resume_consumed_at, resume_consumer_id
                FROM scan_engagements
                WHERE thread_id = ? AND resume_token_hash = ?
                """,
                (thread_id, digest),
            ).fetchone()
            if existing and existing[0] is not None:
                return bool(consumer_id and existing[1] == consumer_id)
            cursor = conn.execute(
                """
                UPDATE scan_engagements
                SET resume_consumed_at = ?, resume_consumer_id = ?
                WHERE thread_id = ? AND resume_token_hash = ?
                  AND resume_consumed_at IS NULL
                  AND resume_lease_until IS NOT NULL
                  AND resume_lease_until >= ?
                """,
                (now.isoformat(), consumer_id or None, thread_id, digest, now.isoformat()),
            )
            conn.commit()
            return cursor.rowcount == 1
    except Exception as exc:
        logger.warning("scan_registry: resume consume failed for %s: %s", thread_id, exc)
        return False


def release_resume_claim(thread_id: str, token: str) -> bool:
    """Release a reservation when Celery dispatch fails before worker start."""
    if not thread_id or not token:
        return False
    digest = _resume_token_digest(token)
    try:
        db = _get_db()
        with db._write_lock, db._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_engagements
                SET resume_token_hash = NULL, resume_claimed_at = NULL,
                    resume_lease_until = NULL, resume_consumed_at = NULL,
                    resume_consumer_id = NULL
                WHERE thread_id = ? AND resume_token_hash = ?
                  AND resume_consumed_at IS NULL
                """,
                (thread_id, digest),
            )
            conn.commit()
            return cursor.rowcount == 1
    except Exception as exc:
        logger.warning("scan_registry: resume release failed for %s: %s", thread_id, exc)
        return False


def update_scan_status(thread_id: str, status: str) -> None:
    """Update the engagement status (running/completed/failed/terminated).

    Called by the API status endpoint after it computes the authoritative
    status, so subsequent polls can short-circuit without re-querying
    Celery. Best-effort.
    """
    if not thread_id or not status:
        return
    try:
        db = _get_db()
        with db._write_lock, db._connect() as conn:
            conn.execute(_SCAN_ENGAGEMENTS_UPDATE_STATUS, (status, thread_id))
            conn.commit()
    except Exception as exc:
        logger.debug(
            "scan_registry: status update failed for thread_id=%s: %s",
            thread_id,
            exc,
        )


def lookup_scan_status(thread_id: str) -> str | None:
    """Return the cached engagement status, or None if unknown."""
    if not thread_id:
        return None
    try:
        db = _get_db()
        with db._connect() as conn:
            cursor = conn.execute(_SCAN_ENGAGEMENTS_SELECT_STATUS, (thread_id,))
            row = cursor.fetchone()
        return row[0] if row else None
    except Exception as exc:
        logger.debug(
            "scan_registry: status lookup failed for thread_id=%s: %s",
            thread_id,
            exc,
        )
        return None
