"""UM-DR-41 §6.3 — durable, shared scope-policy store.

The pre-UMDR41 ``ScopeRegistry`` kept policies in an in-process Python
dict guarded by a thread lock. That lock coordinates nothing beyond one
interpreter: separate Uvicorn workers, separate API containers, Celery
workers and restarted processes each held an INDEPENDENT registry, so a
policy loaded through ``POST /api/v1/scope/load`` in the API process was
invisible to every other process and vanished on restart.

This module adds the missing durability layer WITHOUT a new dependency
(the project already ships SQLite everywhere — 26 direct ``sqlite3``
call sites — and the directive explicitly allows "the existing
database"):

* ``SqliteScopeStore`` — versioned, append-only policy records keyed by
  ``(engagement_id, policy_version)``. Every load appends a new version;
  reads resolve the CURRENT (highest-version) row atomically. Updates
  never mutate history, so an audit trail of what policy was in effect
  at any time survives.
* Fail-closed read semantics: a store that cannot be opened or read
  raises ``ScopeStoreUnavailable`` — callers must treat that as
  "authoritative scope unknown", never silently continue with an empty
  permissive view.
* ``ScopeRegistry`` grows an OPTIONAL durable backend. Constructed with
  ``SqliteScopeStore(path)`` it mirrors every load/clear into SQLite and
  every read falls through to the store when the in-memory view misses
  (another process may have loaded the policy). Constructed without a
  store it keeps the exact legacy single-process behavior, so existing
  imports and tests are untouched.

Serialization is the policy's OWN ``as_dict()`` projection; loading uses
``policy_from_dict`` (same module) so the round-trip is the canonical
model, not a second parser.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from .models import ScopeLimits, ScopePolicy, ScopeRule

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scope_policies (
    engagement_id  TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    policy_json    TEXT NOT NULL,
    fingerprint    TEXT NOT NULL,
    source         TEXT NOT NULL,
    loaded_at_utc  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    cleared_at_utc TEXT,
    PRIMARY KEY (engagement_id, policy_version)
);
CREATE INDEX IF NOT EXISTS idx_scope_current
    ON scope_policies (engagement_id, policy_version) WHERE cleared_at_utc IS NULL;
"""


class ScopeStoreUnavailable(RuntimeError):
    """The authoritative scope store could not be opened/read.

    Security semantics: callers MUST fail closed on this error — an
    unavailable authority means scope cannot be established, not that an
    empty permissive policy applies.
    """


def policy_from_dict(data: dict[str, Any]) -> ScopePolicy:
    """Rebuild a ``ScopePolicy`` from its ``as_dict()`` projection.

    Raises ``ValueError`` on any structural mismatch — never returns a
    half-populated policy.
    """
    try:
        rules = tuple(
            ScopeRule(
                value=str(item["value"]),
                kind=str(item.get("kind") or "url"),
                allow=bool(item.get("allow", True)),
                protocol=item.get("protocol"),
                port=tuple(item["port"]) if isinstance(item.get("port"), list)
                else item.get("port"),
                path=item.get("path"),
                source=str(item.get("source") or "operator"),
                instruction=str(item.get("instruction") or ""),
                max_severity=item.get("max_severity"),
                allowed_methods=frozenset(
                    str(m).upper() for m in (item.get("allowed_methods") or ())),
            )
            for item in data["rules"]
        )
        limits_raw = data.get("limits") or {}
        limits = ScopeLimits(
            max_requests_per_second=float(
                limits_raw.get("max_requests_per_second", 1.0)),
            max_concurrent_requests=int(
                limits_raw.get("max_concurrent_requests", 1)),
            max_violations=int(limits_raw.get("max_violations", 5)),
            no_destructive=bool(limits_raw.get("no_destructive", True)),
        )
        blacklisted = tuple(
            str(x)[:200] for x in (data.get("blacklisted_payloads") or ()))
        instructions = tuple(
            str(x)[:500] for x in (data.get("instructions") or ()))
        return ScopePolicy(
            rules=rules,
            limits=limits,
            blacklisted_payloads=blacklisted,
            source=str(data.get("source") or "operator"),
            instructions=instructions,
            fingerprint=str(data.get("fingerprint") or ""),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"corrupt scope policy record: {exc}") from exc


class SqliteScopeStore:
    """Versioned, process-shared scope-policy authority (SQLite).

    One row per (engagement, version); the current policy is the highest
    version whose ``cleared_at_utc`` is NULL. Connections are opened per
    operation (SQLite file locking coordinates processes); WAL mode and
    a busy timeout keep concurrent API+worker access from failing
    spuriously.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path).expanduser()
        parent = self._path.parent
        if str(parent) and not parent.exists():
            try:
                parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise ScopeStoreUnavailable(
                    f"scope store directory unusable: {exc}") from exc
        try:
            self._init_db()
        except sqlite3.Error as exc:
            raise ScopeStoreUnavailable(
                f"scope store cannot be initialised: {exc}") from exc

    def _connect(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(
                str(self._path),
                timeout=10.0,
                isolation_level=None,  # autocommit; explicit BEGIN where needed
            )
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA foreign_keys=ON")
            return conn
        except sqlite3.Error as exc:
            raise ScopeStoreUnavailable(
                f"scope store connection failed: {exc}") from exc

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
        finally:
            conn.close()

    # -- writes ----------------------------------------------------------

    def append(self, policy: ScopePolicy, *, engagement_id: str) -> int:
        """Persist a NEW version of the engagement's policy.

        Returns the assigned version number (monotonic per engagement).
        The in-record fingerprint makes tampering detectable: the stored
        JSON's recomputed fingerprint must equal the stored column.
        """
        key = str(engagement_id).strip()
        if not key or len(key) > 128:
            raise ValueError("engagement_id is required")
        payload = policy.as_dict()
        fingerprint = str(payload.get("fingerprint") or policy.fingerprint or "")
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT COALESCE(MAX(policy_version), 0) FROM scope_policies "
                "WHERE engagement_id = ?", (key,)).fetchone()
            next_version = int(row[0]) + 1
            conn.execute(
                "INSERT INTO scope_policies "
                "(engagement_id, policy_version, policy_json, fingerprint, source) "
                "VALUES (?, ?, ?, ?, ?)",
                (key, next_version, json.dumps(payload, sort_keys=True),
                 fingerprint, str(policy.source)[:200]))
            conn.execute("COMMIT")
            return next_version
        except sqlite3.Error as exc:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise ScopeStoreUnavailable(
                f"scope store append failed: {exc}") from exc
        finally:
            conn.close()

    def clear(self, engagement_id: str) -> bool:
        """Tombstone EVERY active version (history preserved, never deleted).

        UMDR42 P1-SCOPE-REVIVE: the previous implementation tombstoned
        only the latest ACTIVE row. Because current()/current_version()
        filtered tombstones BEFORE choosing the latest version, a
        revoked v2 resurrected the older v1 policy — a revocation
        downgrade. clear() now tombstones all active rows for the
        engagement, so nothing survives to be resurrected.
        """
        key = str(engagement_id).strip()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                "UPDATE scope_policies SET cleared_at_utc = "
                "strftime('%Y-%m-%dT%H:%M:%fZ','now') "
                "WHERE engagement_id = ? AND cleared_at_utc IS NULL",
                (key,))
            cleared = cursor.rowcount > 0
            conn.execute("COMMIT")
            return cleared
        except sqlite3.Error as exc:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise ScopeStoreUnavailable(
                f"scope store clear failed: {exc}") from exc
        finally:
            conn.close()

    # -- reads -----------------------------------------------------------

    @staticmethod
    def _recompute_fingerprint(policy: ScopePolicy,
                               blacklisted: tuple[str, ...]) -> str:
        """Recompute the parser's canonical fingerprint for a policy.

        Mirrors ``parse_scope_text``'s formula exactly (rules/limits/
        blacklisted, sorted JSON) so a record whose stored JSON was
        edited after load is detectable by comparison against the
        fingerprint column recorded at load time.
        """
        import hashlib
        payload = {
            "rules": [r.as_dict() for r in policy.rules],
            "limits": policy.limits.as_dict(),
            "blacklisted": list(blacklisted),
        }
        return "sha256:" + hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def current(self, engagement_id: str) -> ScopePolicy | None:
        """Resolve the engagement's CURRENT policy (or None when absent).

        Raises ``ScopeStoreUnavailable`` on storage failure — fail
        closed, never an empty-permissive fallback.
        """
        key = str(engagement_id).strip()
        conn = self._connect()
        try:
            # UMDR42 P1-SCOPE-REVIVE: pick the LATEST version first,
            # THEN honour its tombstone. The previous order (filter
            # tombstones, then latest) let a revoked v2 resurrect v1.
            row = conn.execute(
                "SELECT policy_json, fingerprint, cleared_at_utc "
                "FROM scope_policies "
                "WHERE engagement_id = ? "
                "ORDER BY policy_version DESC LIMIT 1", (key,)).fetchone()
        except sqlite3.Error as exc:
            raise ScopeStoreUnavailable(
                f"scope store read failed: {exc}") from exc
        finally:
            conn.close()
        if row is None or row[2] is not None:
            return None
        try:
            payload = json.loads(row[0])
        except (json.JSONDecodeError, TypeError) as exc:
            raise ScopeStoreUnavailable(
                f"scope store record corrupt for {key!r}: {exc}") from exc
        policy = policy_from_dict(payload)
        recorded = str(row[1] or "")
        if recorded:
            # Tamper detection: recompute the canonical fingerprint from
            # the DESERIALIZED policy and compare with the fingerprint
            # recorded at load time. Comparing the JSON's embedded
            # fingerprint string against the column would compare
            # stored-vs-stored and miss in-place edits of rule values.
            recomputed = self._recompute_fingerprint(
                policy, tuple(str(x) for x in payload.get("blacklisted_payloads") or ()))
            if recomputed != recorded:
                raise ScopeStoreUnavailable(
                    f"scope store fingerprint mismatch for {key!r} — "
                    "record edited after load (possible tampering)")
        return policy

    def current_version(self, engagement_id: str) -> int | None:
        key = str(engagement_id).strip()
        conn = self._connect()
        try:
            # UMDR42 P1-SCOPE-REVIVE: latest-then-tombstone ordering
            # (see current() for the rationale).
            row = conn.execute(
                "SELECT policy_version, cleared_at_utc "
                "FROM scope_policies "
                "WHERE engagement_id = ? "
                "ORDER BY policy_version DESC LIMIT 1", (key,)).fetchone()
        except sqlite3.Error as exc:
            raise ScopeStoreUnavailable(
                f"scope store read failed: {exc}") from exc
        finally:
            conn.close()
        if row is None or row[1] is not None:
            return None
        return int(row[0])

    def redacted(self) -> dict[str, dict[str, Any]]:
        """All CURRENT policies, redacted (engagement -> projection).

        UMDR42 P1-SCOPE-REVIVE: latest-then-tombstone ordering — for
        each engagement pick the highest version first, then drop it
        when that latest row is tombstoned. The previous GROUP BY over
        active rows only could resurface an older policy after a
        revocation.
        """
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT engagement_id, policy_json, cleared_at_utc "
                "FROM scope_policies "
                "WHERE policy_version = ("
                "  SELECT MAX(p2.policy_version) FROM scope_policies p2 "
                "  WHERE p2.engagement_id = scope_policies.engagement_id)"
            ).fetchall()
        except sqlite3.Error as exc:
            raise ScopeStoreUnavailable(
                f"scope store listing failed: {exc}") from exc
        finally:
            conn.close()
        out: dict[str, dict[str, Any]] = {}
        for engagement_id, blob, cleared_at in rows:
            if cleared_at is not None:
                continue  # latest version revoked -> not current
            try:
                out[str(engagement_id)] = json.loads(blob)
            except (json.JSONDecodeError, TypeError):
                # one corrupt record must not blank the whole listing,
                # but it MUST be visible, not silently skipped.
                out[str(engagement_id)] = {"error": "corrupt_record"}
        return out


def default_scope_store_path() -> Path:
    """Durable store location, overridable for tests/deployment.

    Honours ``WEBPENT_SCOPE_STORE_PATH``; otherwise ``<cwd>/.webpent``
    next to the existing local databases the project already writes
    (``webpent.db`` et al). Absolute path wins; relative paths are
    resolved against the current working directory like the other
    local-file settings.
    """
    override = os.environ.get("WEBPENT_SCOPE_STORE_PATH", "").strip()
    if override:
        return Path(override).expanduser()
    return Path(".webpent") / "scope_store.sqlite3"


__all__ = [
    "SqliteScopeStore",
    "ScopeStoreUnavailable",
    "policy_from_dict",
    "default_scope_store_path",
]
