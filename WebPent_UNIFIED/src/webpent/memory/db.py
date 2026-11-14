# src/webpent/memory/db.py
"""webpent.memory.db

Lightweight SQLite persistence layer for the WebPent Framework V1/V2/V3.

V3 audit fix (Part 2 W-1): enables WAL mode and busy_timeout on every
file-backed connection to prevent ``database is locked`` errors under
concurrent multi-worker Celery writes.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from webpent.config.settings import get_settings
from webpent.models.findings import Confidence, Finding, Severity
from webpent.validators.causal_validator import validate_causal_observation
from webpent.validators.proof_validator import validate_bundle_structure

logger = logging.getLogger(__name__)

# Alembic's runtime environment uses process-global proxy state. Separate
# target databases still need serialized upgrade invocations within one
# process, while the per-database flock below protects cross-process calls.
_ALEMBIC_UPGRADE_LOCK = threading.RLock()


@contextmanager
def _suppress_sqlite_errors() -> Iterator[None]:
    """Swallow sqlite3.OperationalError exceptions.

    V5 Sprint 9: Used inside ``mark_oob_confirmed``'s exception handler
    to ensure ROLLBACK failures (e.g. when the connection is already in
    a broken state) do not mask the original exception that triggered
    the rollback.
    """
    with suppress(sqlite3.Error):
        yield


def _resolve_db_path(database_url: str) -> Path:
    """Resolve a database URL to an absolute :class:`Path`.

    V6.1 P0: Relative paths are anchored to the project root
    (``Path(__file__).resolve().parents[3]``) rather than ``os.getcwd()``
    which changes depending on where the process is launched from.
    """
    prefix = "sqlite:///"
    if database_url == "sqlite://":
        return Path(":memory:")
    if not database_url.startswith(prefix):
        raise ValueError(
            f"Unsupported database URL scheme: {database_url!r}. "
            "Only 'sqlite:///' URLs are supported."
        )
    raw_path = database_url[len(prefix) :]
    p = Path(raw_path)
    # V6.1 P0: If the path is relative, anchor it to the project root.
    # This prevents the DB from being created in whatever CWD the
    # process happens to be in (e.g., /app vs /app/src vs /).
    if not p.is_absolute():
        # db.py is at src/webpent/memory/db.py → parents[3] = project root.
        project_root = Path(__file__).resolve().parents[3]
        p = project_root / p
    return p


FINDINGS_DDL = """
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    description TEXT NOT NULL,
    tool_name   TEXT NOT NULL,
    payload     TEXT,
    request_method TEXT NOT NULL DEFAULT 'GET',
    request_data TEXT,
    target_param TEXT,
    url         TEXT NOT NULL,
    confidence  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    evidence    TEXT,
    "references" TEXT NOT NULL DEFAULT '[]',
    cvss_score      TEXT,
    business_impact TEXT,
    confidence_level TEXT,
    reasoning TEXT,
    oob_token TEXT,
    canary_token TEXT,
    evidence_bundle TEXT,
    compliance_tags TEXT NOT NULL DEFAULT '[]',
    evidence_hash TEXT,
    post_exploitation_data TEXT,
    vuln_class TEXT DEFAULT 'unknown',
    strategic_confidence_score REAL,
    hypothesis_id TEXT,
    thread_id TEXT,
    advisory_evidence TEXT NOT NULL DEFAULT '[]'
);
"""

# V10 P0-C: index on thread_id so get_findings_by_thread doesn't
# full-scan on every status poll. Created alongside FINDINGS_DDL.
FINDINGS_INDEX_DDL = """
CREATE INDEX IF NOT EXISTS ix_findings_thread_id ON findings(thread_id);
"""

AUTH_TOKEN_VERSIONS_DDL = """
CREATE TABLE IF NOT EXISTS auth_token_versions (
    username TEXT PRIMARY KEY,
    token_version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);
"""

REAUTH_VAULT_DDL = """
CREATE TABLE IF NOT EXISTS reauth_vault_records (
    thread_id TEXT NOT NULL,
    record_type TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    expires_at REAL NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (thread_id, record_type)
);
"""

REAUTH_VAULT_INDEX_DDL = """
CREATE INDEX IF NOT EXISTS ix_reauth_vault_expires_at
ON reauth_vault_records(expires_at);
"""

# TEAM-1 Phase 3: legacy databases created before the status-history table
# exist without it; the migration below runs during init_db() before Alembic
# hands over, so every process (API + worker) converges on the same schema.
# The Alembic head remains authoritative for the findings table itself.

# TEAM-1 Phase 3 (P0 refutation correctness): append-only status history for
# every finding-status transition. The findings table itself only stores the
# LATEST status; this table preserves the full monotonic transition trail
# (UNCONFIRMED -> CONFIRMED -> REFUTED) so history survives reloads and
# reports cannot silently resurrect an older confirmation.
FINDING_STATUS_HISTORY_DDL = """
CREATE TABLE IF NOT EXISTS finding_status_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    TEXT NOT NULL,
    thread_id     TEXT,
    status        TEXT NOT NULL,
    evidence_hash TEXT,
    evidence      TEXT,
    actor         TEXT NOT NULL DEFAULT 'system',
    reason        TEXT,
    created_at    TEXT NOT NULL
);
"""

FINDING_STATUS_HISTORY_INDEX_DDL = """
CREATE INDEX IF NOT EXISTS ix_finding_status_history_finding
ON finding_status_history(finding_id, id);
"""

# RED-TEAM WINDOW (2026-11-06, UM-DR-25): the OOB collaboration tables.
# shared/oob.py::DatabaseOOBStore (merged with its full DB contract) calls
# five DatabaseManager methods that were never implemented here — every
# DB-backed OOB interaction raised AttributeError on arrival (30 test
# failures in tests/test_oob_collaboration.py). Tables follow the same
# always-bootstrap pattern as finding_status_history (CREATE TABLE IF NOT
# EXISTS on every process start, outside Alembic) so existing deployments
# converge without a new migration head.
OOB_BINDINGS_DDL = """
CREATE TABLE IF NOT EXISTS oob_bindings (
    token         TEXT PRIMARY KEY,
    host          TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    vuln_class    TEXT NOT NULL,
    probe_label   TEXT NOT NULL DEFAULT '',
    registered_at REAL NOT NULL
);
"""

OOB_CALLBACKS_DDL = """
CREATE TABLE IF NOT EXISTS oob_callbacks (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    token               TEXT NOT NULL,
    protocol            TEXT NOT NULL DEFAULT '',
    seen_at             REAL NOT NULL,
    source_fingerprint  TEXT NOT NULL DEFAULT '',
    details             TEXT NOT NULL DEFAULT ''
);
"""

OOB_CALLBACKS_INDEX_DDL = """
CREATE INDEX IF NOT EXISTS ix_oob_callbacks_token
ON oob_callbacks(token, seen_at);
"""

# Deterministic status vocabulary for the finding state machine.
#   UNCONFIRMED — candidate only (AI-Assessed / Pending / heuristic)
#   CONFIRMED   — deterministic evidence passed (Tool-Confirmed / OOB marker)
#   REFUTED     — verified contradictory deterministic evidence persisted
STATUS_UNCONFIRMED = "UNCONFIRMED"
STATUS_CONFIRMED = "CONFIRMED"
STATUS_REFUTED = "REFUTED"

# Display status -> state-machine status mapping. Anything unmapped falls
# back to UNCONFIRMED (fail-closed: an unknown level never counts as
# confirmed evidence).
_STATUS_LEVEL_MAP = {
    "Tool-Confirmed": STATUS_CONFIRMED,
    "Refuted": STATUS_REFUTED,
}

# Append one history row. Executed on the caller's connection so the
# transition row commits atomically with the status change that produced it.
_FINDING_HISTORY_INSERT = """
INSERT INTO finding_status_history
    (finding_id, thread_id, status, evidence_hash, evidence, actor, reason, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
"""

# Latest history row for one finding (max id = most recent append).
_FINDING_HISTORY_LATEST = """
SELECT finding_id, thread_id, status, evidence_hash, evidence, actor, reason, created_at
FROM finding_status_history
WHERE finding_id = ?
ORDER BY id DESC
LIMIT 1;
"""

_FINDING_HISTORY_ALL = """
SELECT finding_id, thread_id, status, evidence_hash, evidence, actor, reason, created_at
FROM finding_status_history
WHERE finding_id = ?
ORDER BY id ASC;
"""

_FINDINGS_INSERT = """
INSERT OR REPLACE INTO findings (
    id, title, severity, description, tool_name,
    payload, request_method, request_data, target_param, url,
    confidence, created_at, evidence, "references",
    cvss_score, business_impact, confidence_level, reasoning, oob_token,
    canary_token, evidence_bundle, compliance_tags, evidence_hash,
    post_exploitation_data, vuln_class,
    strategic_confidence_score, hypothesis_id, thread_id,
    advisory_evidence
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

_FINDINGS_SELECT = """
SELECT
    id, title, severity, description, tool_name,
    payload, request_method, request_data, target_param, url,
    confidence, created_at, evidence, "references",
    cvss_score, business_impact, confidence_level, reasoning, oob_token,
    canary_token, evidence_bundle, compliance_tags, evidence_hash,
    post_exploitation_data, vuln_class,
    strategic_confidence_score, hypothesis_id, thread_id,
    advisory_evidence
FROM findings
ORDER BY created_at ASC;
"""

# V9 P0 Fix 3: per-thread findings query — no cross-thread bleed.
_FINDINGS_SELECT_BY_THREAD = """
SELECT
    id, title, severity, description, tool_name,
    payload, request_method, request_data, target_param, url,
    confidence, created_at, evidence, "references",
    cvss_score, business_impact, confidence_level, reasoning, oob_token,
    canary_token, evidence_bundle, compliance_tags, evidence_hash,
    post_exploitation_data, vuln_class,
    strategic_confidence_score, hypothesis_id, thread_id,
    advisory_evidence
FROM findings
WHERE thread_id = ?
ORDER BY created_at ASC;
"""

# V5 Sprint 5: Single-row lookup used by the OOB endpoint and by the
# validator's poll loop. Indexing by primary key keeps this O(log n).
_FINDINGS_SELECT_BY_ID = """
SELECT
    id, title, severity, description, tool_name,
    payload, request_method, request_data, target_param, url,
    confidence, created_at, evidence, "references",
    cvss_score, business_impact, confidence_level, reasoning, oob_token,
    canary_token, evidence_bundle, compliance_tags, evidence_hash,
    post_exploitation_data, vuln_class,
    strategic_confidence_score, hypothesis_id, thread_id,
    advisory_evidence
FROM findings
WHERE id = ?;
"""

# V5 Sprint 5: Targeted UPDATE used by the OOB callback endpoint to
# flip a finding to "Tool-Confirmed" and append a justification note
# to its reasoning trail. Only mutates the three columns that change;
# all other columns are preserved.
# R3 E-1 (Ruling R3-002): this UPDATE is now DEAD for the OOB callback
# path — the handler records ADVISORY evidence via append_oob_advisory_
# evidence() instead. The constant is retained only because the M1-audited
# promotion component may still reference the sibling write path.
_FINDINGS_UPDATE_OOB = """
UPDATE findings
SET confidence_level = ?,
    confidence = ?,
    reasoning = ?,
    payload = COALESCE(?, payload),
    evidence = ?
WHERE id = ?;
"""

# R3 E-1 (Ruling R3-002 §3.2(v)): the advisory sibling write. Mutates
# EXACTLY one column (advisory_evidence) and nothing else — confidence,
# confidence_level, reasoning, and payload are structurally unreachable
# from this statement (fail-closed by construction, per C5).
_FINDINGS_UPDATE_ADVISORY = """
UPDATE findings
SET advisory_evidence = ?
WHERE id = ?;
"""


class DatabaseManager:
    """Thread-safe SQLite manager for ``Finding`` persistence.

    V3 improvements:
      * WAL mode enabled on every file-backed connection (Part 2 W-1).
      * ``busy_timeout=30000`` to wait for locks instead of failing.
      * Schema migration for ``cvss_score`` and ``business_impact``.
    """

    def __init__(self, database_url: str | None = None) -> None:
        self._database_url = database_url
        self._write_lock = threading.Lock()
        self._initialised = False
        self._memory_conn: sqlite3.Connection | None = None

    def _db_path(self) -> Path:
        url = self._database_url or get_settings().database_url
        return _resolve_db_path(url)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        path = self._db_path()

        if str(path) == ":memory:":
            if self._memory_conn is None:
                self._memory_conn = sqlite3.connect(
                    ":memory:",
                    isolation_level="",
                    check_same_thread=False,
                    timeout=30.0,
                )
                self._memory_conn.row_factory = sqlite3.Row
            try:
                yield self._memory_conn
            finally:
                pass
            return

        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(path),
            isolation_level="",
            check_same_thread=False,
            timeout=30.0,
        )
        conn.row_factory = sqlite3.Row

        # V3 Part 2 W-1: Enable WAL mode + busy_timeout for concurrent
        # multi-worker safety. WAL allows readers to coexist with a
        # single writer without blocking.
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
        except sqlite3.OperationalError as exc:
            logger.warning("Could not set WAL mode / busy_timeout: %s", exc)

        try:
            yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        """Initialize the database schema.

        V6 Ultimate: Uses Alembic migrations (``alembic upgrade head``)
        instead of raw CREATE TABLE / ALTER TABLE statements. Falls back
        to the legacy DDL + ALTER TABLE approach if Alembic is not
        installed (e.g., in minimal dev environments).

        Migration errors are fail-closed. Legacy DDL is used only when
        Alembic itself is unavailable or ``alembic.ini`` is missing; a
        real migration failure must propagate instead of being stamped
        as successful.
        """
        if self._initialised:
            return
        with self._write_lock:
            if self._initialised:
                return

            # TEAM-1 Phase 3: the status-history table is created outside
            # Alembic (CREATE TABLE IF NOT EXISTS on every process start) so
            # existing deployments converge without a new migration head.
            # This runs BEFORE the Alembic attempt so the table exists even
            # when the migration path fails closed below.
            try:
                with self._connect() as conn:
                    conn.execute(FINDING_STATUS_HISTORY_DDL)
                    conn.execute(FINDING_STATUS_HISTORY_INDEX_DDL)
                    conn.commit()
            except sqlite3.Error as exc:
                logger.warning("finding_status_history bootstrap failed: %s", exc)

            # UM-DR-25: OOB collaboration tables bootstrap (same pattern).
            try:
                with self._connect() as conn:
                    conn.execute(OOB_BINDINGS_DDL)
                    conn.execute(OOB_CALLBACKS_DDL)
                    conn.execute(OOB_CALLBACKS_INDEX_DDL)
                    conn.commit()
            except sqlite3.Error as exc:
                logger.warning("oob tables bootstrap failed: %s", exc)

            # V6 Ultimate: Try Alembic first.
            try:
                self._run_alembic_upgrade()
                self._initialised = True
                logger.info("Database initialized via Alembic migration")
                return
            except (ImportError, FileNotFoundError) as exc:
                logger.warning(
                    "Alembic unavailable (%s) — falling back to legacy DDL + ALTER TABLE approach.",
                    exc,
                )
                # Legacy fallback is intentionally limited to an unavailable
                # migration tool/configuration. Upgrade failures propagate.
                self._init_db_legacy()

    def get_token_version(self, username: str) -> int:
        """Return the shared token version for ``username``.

        Missing rows intentionally resolve to version 1 for compatibility
        with tokens issued before the shared table existed.  Database errors
        propagate so authentication can fail closed instead of silently
        trusting a stale in-process counter.
        """
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT token_version FROM auth_token_versions WHERE username = ?",
                (username,),
            ).fetchone()
        return int(row[0]) if row is not None else 1

    def save_reauth_vault_record(
        self,
        thread_id: str,
        record_type: str,
        encrypted_value: str,
        expires_at: float,
    ) -> None:
        """Persist one encrypted runtime secret when shared vault is enabled."""
        self.init_db()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._write_lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO reauth_vault_records "
                "(thread_id, record_type, encrypted_value, expires_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(thread_id, record_type) DO UPDATE SET "
                "encrypted_value=excluded.encrypted_value, expires_at=excluded.expires_at, "
                "updated_at=excluded.updated_at",
                (thread_id, record_type, encrypted_value, float(expires_at), now),
            )
            conn.commit()

    def get_reauth_vault_record(
        self,
        thread_id: str,
        record_type: str,
    ) -> tuple[str, float] | None:
        """Return one encrypted vault record without exposing plaintext."""
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT encrypted_value, expires_at FROM reauth_vault_records "
                "WHERE thread_id = ? AND record_type = ?",
                (thread_id, record_type),
            ).fetchone()
        if row is None:
            return None
        return str(row[0]), float(row[1])

    def delete_reauth_vault_record(self, thread_id: str, record_type: str) -> int:
        """Delete one typed vault record without affecting sibling records."""
        self.init_db()
        with self._write_lock, self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM reauth_vault_records WHERE thread_id = ? AND record_type = ?",
                (thread_id, record_type),
            )
            conn.commit()
            return int(cursor.rowcount)

    def delete_reauth_vault_records(self, thread_id: str) -> int:
        """Delete all vault records for one engagement and return rows removed."""
        self.init_db()
        with self._write_lock, self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM reauth_vault_records WHERE thread_id = ?",
                (thread_id,),
            )
            conn.commit()
            return int(cursor.rowcount)

    def sweep_reauth_vault_records(self, max_items: int = 256) -> int:
        """Delete at most ``max_items`` expired shared-vault rows."""
        if max_items <= 0:
            return 0
        self.init_db()
        with self._write_lock, self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM reauth_vault_records WHERE rowid IN ("
                "SELECT rowid FROM reauth_vault_records WHERE expires_at <= ? "
                "ORDER BY expires_at LIMIT ?)",
                (time.time(), max_items),
            )
            conn.commit()
            return int(cursor.rowcount)

    def reauth_vault_stats(self) -> dict[str, int]:
        """Return non-secret counts for shared-vault operational health."""
        self.init_db()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT record_type, COUNT(*) FROM reauth_vault_records "
                "GROUP BY record_type"
            ).fetchall()
        return {str(row[0]): int(row[1]) for row in rows}

    # ------------------------------------------------------------------
    # OOB collaboration persistence (RED-TEAM WINDOW 2026-11-06, UM-DR-25).
    # Contract owner: shared/oob.py::DatabaseOOBStore (token in, row-dict
    # out; callbacks ordered oldest-first; prune returns removed count).
    # ------------------------------------------------------------------
    def register_oob_binding(
        self,
        token: str,
        host: str,
        engagement_id: str,
        vuln_class: str,
        probe_label: str,
        registered_at: float,
    ) -> None:
        """Upsert one OOB probe binding (token is the primary key)."""
        self.init_db()
        with self._write_lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO oob_bindings "
                "(token, host, engagement_id, vuln_class, probe_label, registered_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(token) DO UPDATE SET "
                "host=excluded.host, engagement_id=excluded.engagement_id, "
                "vuln_class=excluded.vuln_class, probe_label=excluded.probe_label, "
                "registered_at=excluded.registered_at",
                (
                    str(token),
                    str(host),
                    str(engagement_id),
                    str(vuln_class),
                    str(probe_label or ""),
                    float(registered_at),
                ),
            )
            conn.commit()

    def get_oob_binding(self, token: str) -> dict[str, Any] | None:
        """Return one binding row-dict (or None when the token is unknown)."""
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT token, host, engagement_id, vuln_class, probe_label, "
                "registered_at FROM oob_bindings WHERE token = ?",
                (str(token),),
            ).fetchone()
        if row is None:
            return None
        return {
            "token": str(row["token"]),
            "host": str(row["host"]),
            "engagement_id": str(row["engagement_id"]),
            "vuln_class": str(row["vuln_class"]),
            "probe_label": str(row["probe_label"] or ""),
            "registered_at": float(row["registered_at"]),
        }

    def record_oob_callback(
        self,
        token: str,
        protocol: str,
        seen_at: float,
        source_fingerprint: str,
        details: str,
    ) -> None:
        """Append one observed callback (append-only; duplicates allowed)."""
        self.init_db()
        with self._write_lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO oob_callbacks "
                "(token, protocol, seen_at, source_fingerprint, details) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    str(token),
                    str(protocol or ""),
                    float(seen_at),
                    str(source_fingerprint or ""),
                    str(details or ""),
                ),
            )
            conn.commit()

    def get_oob_callbacks_for_token(self, token: str) -> list[dict[str, Any]]:
        """All callbacks for one token, oldest first (arrival order)."""
        self.init_db()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT token, protocol, seen_at, source_fingerprint, details "
                "FROM oob_callbacks WHERE token = ? ORDER BY seen_at ASC, id ASC",
                (str(token),),
            ).fetchall()
        return [
            {
                "token": str(row["token"]),
                "protocol": str(row["protocol"] or ""),
                "seen_at": float(row["seen_at"]),
                "source_fingerprint": str(row["source_fingerprint"] or ""),
                "details": str(row["details"] or ""),
            }
            for row in rows
        ]

    def prune_oob_callbacks(self, *, max_age_seconds: float, now: float) -> int:
        """Delete callbacks older than the cutoff; return the removed count."""
        self.init_db()
        cutoff = float(now) - float(max_age_seconds)
        with self._write_lock, self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM oob_callbacks WHERE seen_at < ?",
                (cutoff,),
            )
            conn.commit()
            return int(cursor.rowcount or 0)

    def bump_token_version(self, username: str) -> int:
        """Atomically revoke all existing tokens for ``username``.

        The write lock protects callers in one process; ``BEGIN IMMEDIATE``
        serializes concurrent SQLite writers across API/worker processes.
        """
        self.init_db()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._write_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT token_version FROM auth_token_versions WHERE username = ?",
                    (username,),
                ).fetchone()
                next_version = (int(row[0]) if row is not None else 1) + 1
                conn.execute(
                    "INSERT INTO auth_token_versions (username, token_version, updated_at) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT(username) DO UPDATE SET token_version=excluded.token_version, "
                    "updated_at=excluded.updated_at",
                    (username, next_version, now),
                )
                conn.commit()
                return next_version
            except Exception:
                with _suppress_sqlite_errors():
                    conn.execute("ROLLBACK")
                raise

    def _get_alembic_version(self, conn: sqlite3.Connection) -> str | None:
        """Return the current alembic version stamp, or ``None`` if unset.

        V6 DX-Final P1: Used by the cross-process migration guard to
        short-circuit ``alembic upgrade head`` when another container
        has already migrated the database. Reading the
        ``alembic_version`` table is O(1) and does not require an
        exclusive lock, making it a cheap pre-flight check.
        """
        try:
            cursor = conn.execute("SELECT version_num FROM alembic_version LIMIT 1")
            row = cursor.fetchone()
            return row[0] if row else None
        except sqlite3.OperationalError:
            # Table doesn't exist yet — first run.
            return None

    def _run_alembic_upgrade(self) -> None:
        """Run ``alembic upgrade head`` programmatically.

        V6 Ultimate: Replaces the raw SQL migration logic with Alembic.
        The alembic.ini and env.py are configured to read the database
        URL from settings.py, ensuring path consistency.

        V6 DX-Final P0: On Alembic failure, falls back to legacy DDL
        and stamps the ``alembic_version`` table to ``head`` so future
        runs don't re-attempt the failed migration. Without the stamp,
        every container start would re-run the failed migration and
        re-trigger the fallback path, causing a startup loop.

        V6 DX-Final P1: Cross-process race guard. When the API and
        Worker containers start simultaneously, both used to call
        ``alembic upgrade head`` on the same SQLite database, racing
        for the SQLite write lock and occasionally producing
        ``database is locked`` errors or partially-applied migrations.
        We now (a) check the ``alembic_version`` table first and skip
        the upgrade entirely if already at head, and (b) acquire a
        file-level advisory lock (``fcntl.flock`` on a sibling
        ``<db>.migration.lock`` sentinel) so only one process at a
        time can attempt a migration. The DB-level check is the fast
        path; the file lock is the correctness guarantee.
        """
        import sys as _sys
        from pathlib import Path as _Path

        project_root = _Path(__file__).resolve().parents[3]
        alembic_ini = project_root / "alembic.ini"
        if not alembic_ini.is_file():
            raise FileNotFoundError(f"alembic.ini not found at {alembic_ini}")

        # Ensure project root is on sys.path for alembic env.py imports.
        if str(project_root) not in _sys.path:
            _sys.path.insert(0, str(project_root))
        src_dir = str(project_root / "src")
        if src_dir not in _sys.path:
            _sys.path.insert(0, src_dir)

        from alembic.config import Config as AlembicConfig

        # V6 DX-Final P1 FIX (CISO audit): Import ScriptDirectory to
        # resolve the *actual* head revision ID from the migration
        # scripts. The previous comparison `current == "head"` always
        # failed because `current` (read from the alembic_version
        # table) is a real revision ID like ``0001_initial``, not the
        # literal string ``"head"``. This forced every container
        # startup to re-enter the slow migration path (acquiring the
        # file lock, re-running ``alembic upgrade head``) even when
        # the database was already fully migrated.
        from alembic.script import ScriptDirectory

        from alembic import command as alembic_command

        cfg = AlembicConfig(str(alembic_ini))
        # Resolve migrations from the project root instead of the process
        # cwd. API and worker processes may start from arbitrary directories.
        cfg.set_main_option("script_location", str(project_root / "alembic"))
        # Alembic's env.py normally loads alembic.ini logging handlers. A
        # runtime API/worker must not replace its active handlers (including
        # pytest capture handlers), so keep logging ownership with the caller.
        cfg.attributes["configure_logger"] = False
        # Pass this manager's URL into Alembic.  Without this override,
        # alembic/env.py falls back to the process-wide settings URL and a
        # DatabaseManager created for an isolated path is marked initialized
        # even though its own database was never migrated.
        migration_url = self._database_url or get_settings().database_url
        cfg.set_main_option("sqlalchemy.url", migration_url)
        actual_head = ScriptDirectory.from_config(cfg).get_current_head()

        # ------------------------------------------------------------------
        # V6 DX-Final P1: Cross-process race guard.
        # ------------------------------------------------------------------
        # Step 1 — Fast path: check alembic_version table. If another
        # process has already migrated to head, we can return immediately
        # without acquiring any lock. This makes the steady-state cost
        # of init_db() a single indexed SELECT.
        db_path = self._db_path()
        if str(db_path) != ":memory:":
            try:
                with self._connect() as conn:
                    current = self._get_alembic_version(conn)
                if current == actual_head:
                    logger.info(
                        "Alembic already at head (version_num=%s, head=%s) — skipping migration.",
                        current,
                        actual_head,
                    )
                    return
            except Exception as preflight_exc:
                logger.debug(
                    "Alembic pre-flight version check failed (non-fatal, "
                    "will proceed to upgrade): %s",
                    preflight_exc,
                )

            # Step 2 — File-level advisory lock. fcntl.flock blocks
            # other processes trying to acquire the same lock, so only
            # one container can run migrations at a time. SQLite's own
            # busy_timeout handles intra-process writer contention; this
            # file lock prevents two processes from running
            # ``alembic upgrade head`` concurrently (which would cause
            # ``database is locked`` errors on the DDL statements).
            import fcntl

            lock_path = _Path(str(db_path) + ".migration.lock")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            lock_fd = os.open(
                str(lock_path),
                os.O_CREAT | os.O_RDWR,
                0o644,
            )
            try:
                # Blocking exclusive lock — waits for any other process
                # currently holding it. Combined with the busy_timeout
                # on the SQLite connection, this makes the migration
                # fully serialized across the API + Worker containers.
                fcntl.flock(lock_fd, fcntl.LOCK_EX)

                # Step 3 — Re-check inside the lock (double-checked
                # locking). The process that held the lock before us
                # may have completed the migration.
                try:
                    with self._connect() as conn:
                        current = self._get_alembic_version(conn)
                    if current == actual_head:
                        logger.info(
                            "Alembic already at head (version_num=%s, "
                            "head=%s) after acquiring migration lock "
                            "— skipping migration.",
                            current,
                            actual_head,
                        )
                        return
                except Exception as recheck_exc:
                    logger.debug(
                        "Alembic re-check failed (non-fatal): %s",
                        recheck_exc,
                    )

                # Step 4 — Run the actual migration while holding the
                # file lock. alembic uses its own SQLAlchemy connection
                # with its own transaction management; the file lock
                # only prevents concurrent invocations of the
                # ``alembic upgrade`` command itself.
                # Any migration failure is propagated. Silently falling back
                # and stamping ``head`` would falsely claim schema integrity.
                with _ALEMBIC_UPGRADE_LOCK:
                    # Older releases created the schema with legacy DDL but
                    # left an empty alembic_version table. Treat that state as
                    # a migration boundary: converge missing columns through
                    # the idempotent legacy upgrader, then stamp the actual
                    # head instead of replaying CREATE TABLE statements.
                    if current is None:
                        with self._connect() as conn:
                            existing_tables = {
                                row[0]
                                for row in conn.execute(
                                    "SELECT name FROM sqlite_master WHERE type='table'"
                                )
                            }
                        if "findings" in existing_tables:
                            self._init_db_legacy()
                            alembic_command.stamp(cfg, actual_head)
                            return
                    alembic_command.upgrade(cfg, "head")
            finally:
                # Release the file lock and close the lock fd. We do
                # NOT delete the lock file — leaving it on disk is
                # harmless and avoids a TOCTOU race between unlink and
                # the next process's O_CREAT.
                with suppress(OSError):
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            return

        # ------------------------------------------------------------------
        # In-memory DB path — no file lock needed (single-process only).
        # ------------------------------------------------------------------
        # Any migration failure is propagated. Silently stamping ``head``
        # would falsely claim schema integrity even for an in-memory DB.
        with _ALEMBIC_UPGRADE_LOCK:
            alembic_command.upgrade(cfg, "head")

    def _init_db_legacy(self) -> None:
        """Legacy DDL + ALTER TABLE migration (fallback when Alembic unavailable)."""
        with self._connect() as conn:
            conn.execute(FINDINGS_DDL)

            cursor = conn.execute("PRAGMA table_info(findings)")
            existing_columns = {row[1] for row in cursor.fetchall()}
            if "cvss_score" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN cvss_score TEXT")
                logger.info("Migration: added cvss_score column")
            if "business_impact" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN business_impact TEXT")
                logger.info("Migration: added business_impact column")
            if "confidence_level" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN confidence_level TEXT")
                logger.info("Migration: added confidence_level column")
            if "reasoning" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN reasoning TEXT")
                logger.info("Migration: added reasoning column")
            if "oob_token" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN oob_token TEXT")
                logger.info("Migration: added oob_token column")
            if "canary_token" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN canary_token TEXT")
                logger.info("Migration: added canary_token column")
            if "evidence_bundle" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN evidence_bundle TEXT")
                logger.info("Migration: added evidence_bundle column")
            if "compliance_tags" not in existing_columns:
                conn.execute(
                    "ALTER TABLE findings ADD COLUMN compliance_tags TEXT NOT NULL DEFAULT '[]'"
                )
                logger.info("Migration: added compliance_tags column")
            if "evidence_hash" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN evidence_hash TEXT")
                logger.info("Migration: added evidence_hash column")
            if "post_exploitation_data" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN post_exploitation_data TEXT")
                logger.info("Migration: added post_exploitation_data column")
            if "vuln_class" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN vuln_class TEXT DEFAULT 'unknown'")
                logger.info("Migration: added vuln_class column")
            # V7 Cognitive Upgrade — Phase 4: persist the new Finding
            # fields so the audit-trail back-reference (hypothesis_id)
            # and the informational confidence score survive DB
            # round-trips. Follows the exact same ALTER TABLE ADD COLUMN
            # guarded-by-PRAGMA pattern as every other column above.
            if "strategic_confidence_score" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN strategic_confidence_score REAL")
                logger.info("Migration: added strategic_confidence_score column")
            if "hypothesis_id" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN hypothesis_id TEXT")
                logger.info("Migration: added hypothesis_id column")
            # V9 P0 Fix 3: thread_id column for per-engagement isolation.
            if "thread_id" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN thread_id TEXT")
                logger.info("Migration: added thread_id column (V9 P0 Fix 3)")
            # R3 E-1 (Ruling R3-002, amendment B): advisory_evidence column —
            # authority-neutral OOB advisory records (JSON list), appended
            # ONLY by append_oob_advisory_evidence(). Follows the exact
            # PRAGMA-guarded ALTER TABLE pattern as every column above.
            if "advisory_evidence" not in existing_columns:
                conn.execute(
                    "ALTER TABLE findings ADD COLUMN advisory_evidence TEXT NOT NULL DEFAULT '[]'"
                )
                logger.info("Migration: added advisory_evidence column (R3 E-1)")
            if "request_method" not in existing_columns:
                conn.execute(
                    "ALTER TABLE findings ADD COLUMN request_method TEXT NOT NULL DEFAULT 'GET'"
                )
                logger.info("Migration: added request_method column (V72)")
            if "request_data" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN request_data TEXT")
                logger.info("Migration: added request_data column (V72)")
            if "target_param" not in existing_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN target_param TEXT")
                logger.info("Migration: added target_param column (V72)")

            # V10 P0-C: index on thread_id so get_findings_by_thread
            # doesn't full-scan on every status poll. CREATE INDEX IF
            # NOT EXISTS is idempotent.
            conn.execute(FINDINGS_INDEX_DDL)

            # Keep the compatibility fallback schema aligned with the
            # Alembic head so shared JWT revocation remains fail-closed even
            # in minimal environments where Alembic is unavailable.
            conn.execute(AUTH_TOKEN_VERSIONS_DDL)
            conn.execute(REAUTH_VAULT_DDL)
            conn.execute(REAUTH_VAULT_INDEX_DDL)

            # TEAM-1 Phase 3: append-only finding status history.
            conn.execute(FINDING_STATUS_HISTORY_DDL)
            conn.execute(FINDING_STATUS_HISTORY_INDEX_DDL)

            conn.commit()
        self._initialised = True

    @staticmethod
    def _enum_value(v: Any) -> str:
        """Normalize a (str, Enum) field to its parseable `.value` form.

        V7 Ready-For-Kali P0 FIX (found via empirical round-trip
        testing, not code review): the previous code did
        ``str(finding.confidence)`` etc. directly. For a
        ``class X(str, Enum)`` member, Python's bare ``str()`` returns
        the QUALIFIED repr form (``"Confidence.TENTATIVE"``), not the
        parseable value (``"tentative"``) -- confirmed empirically on
        this Python version. ``Confidence(row["confidence"])`` on read
        then raises ``ValueError`` immediately, for every single row.

        This "accidentally worked" in the real production pipeline
        ONLY because LangGraph's checkpointer msgpack round-trip
        happens to coerce these (str, Enum) fields down to plain
        strings before ``save_finding()`` is ever reached from
        ``pentest_worker.py`` -- so ``str()`` on the ALREADY-plain
        string was a harmless no-op there. It crashes immediately and
        reproducibly for any finding saved via a more direct path
        (any unit test; any future code that constructs and saves a
        Finding without first passing through a checkpoint round-trip
        -- e.g. exploit_chainer's freshly-created candidates, if they
        were ever persisted directly rather than via the graph). Not
        robust, not intentional -- accidental correctness in one
        specific call path, latent breakage everywhere else. Fixed by
        explicitly reading ``.value`` when present (true enum member)
        and falling back to the value itself when it's already a
        plain string (post-checkpoint case) — safe for both.
        """
        return v.value if hasattr(v, "value") else str(v)

    def save_finding(self, finding: Finding) -> None:
        """Persist a single :class:`Finding` to the database.

        V10 P1-10 FIX (save_finding vs mark_oob_confirmed clobber):
            ``_FINDINGS_INSERT`` uses ``INSERT OR REPLACE``, which
            overwrites ALL columns. The OOB callback endpoint calls
            :meth:`mark_oob_confirmed`, which performs a TARGETED
            ``UPDATE`` of just four columns (``confidence_level`` →
            "Tool-Confirmed", ``confidence`` → CONFIRMED, ``reasoning``
            → existing+appendix, ``payload`` → marker). If the graph
            subsequently calls ``save_finding`` again for the same
            finding (e.g. CVSS engine updates the score, devils_advocate
            appends reasoning), the in-memory finding's SNAPSHOT of
            those four columns pre-dates the OOB confirmation — so the
            ``INSERT OR REPLACE`` silently clobbers the OOB-confirmed
            state back to the older in-memory values. The DB row
            appeared "Tool-Confirmed" briefly and then reverted, with
            no log and no audit trail.

            Fix: BEFORE the INSERT OR REPLACE, read the existing row.
            If the DB row's ``confidence_level`` is "Tool-Confirmed"
            AND the in-memory finding is at a LOWER confidence (i.e.
            its ``confidence_level`` is NOT also "Tool-Confirmed"),
            preserve the DB's four OOB-confirmed columns by overriding
            the in-memory values used in the INSERT. This makes
            ``save_finding`` idempotent w.r.t. OOB confirmations: a
            Tool-Confirmed row cannot be silently downgraded by a
            later graph-state save. When the in-memory finding is
            ALSO Tool-Confirmed (e.g. the validator re-confirmed via
            a different path), the in-memory values win — that is the
            intended behaviour, since the in-memory state is fresher.
        """
        self.init_db()
        with self._write_lock, self._connect() as conn:
            # V10 P1-10: read existing row (if any) under the same
            # write lock so the check-then-replace is atomic w.r.t.
            # concurrent mark_oob_confirmed callers.
            # P1-04 (0.33.0): the threading.Lock protects callers in ONE
            # process only — mark_oob_confirmed's own docstring says so,
            # which is why IT uses BEGIN IMMEDIATE. save_finding's
            # SELECT-then-INSERT-OR-REPLACE now opens the same file-level
            # transaction, so a worker's stale snapshot can no longer
            # clobber another process's OOB confirmation between the
            # read and the replace (the V10 P1-10 bug, cross-process).
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(_FINDINGS_SELECT_BY_ID, (str(finding.id),))
            existing_row = cursor.fetchone()

            # Local mutable copies of the four OOB-confirmed fields;
            # overridden below if the DB has a Tool-Confirmed row that
            # the in-memory finding would otherwise clobber.
            save_confidence_level = finding.confidence_level
            save_confidence = self._enum_value(finding.confidence)
            save_reasoning = finding.reasoning
            save_payload = finding.payload
            # R-C-3 fix: the confirmation-era evidence and sealed bundle
            # are part of the same sealed artifact as the label.  If the
            # DB keeps the Tool-Confirmed label while a later stale
            # in-memory snapshot overwrites ``evidence`` with an
            # unconfirmed-era dict, the row becomes internally
            # contradictory (label says Tool-Confirmed, evidence says
            # unconfirmed).  Preserve them together.
            save_evidence = finding.evidence
            save_evidence_bundle = finding.evidence_bundle

            if (
                existing_row is not None
                and existing_row["confidence_level"] == "Tool-Confirmed"
                and finding.confidence_level != "Tool-Confirmed"
                and finding.confidence_level != "Refuted"
            ):
                # Preserve the DB's OOB-confirmed columns. The
                # in-memory finding is at a lower confidence (e.g.
                # "AI-Assessed" or "Needs Human Review") and would
                # otherwise clobber the Tool-Confirmed state.
                save_confidence_level = existing_row["confidence_level"]
                save_confidence = existing_row["confidence"]
                save_reasoning = existing_row["reasoning"]
                save_payload = existing_row["payload"]
                # R-C-3: keep the sealed evidence coherent with the label.
                try:
                    save_evidence = (
                        json.loads(existing_row["evidence"])
                        if existing_row["evidence"]
                        else None
                    )
                except (TypeError, ValueError):
                    save_evidence = None
                try:
                    save_evidence_bundle = (
                        json.loads(existing_row["evidence_bundle"])
                        if existing_row["evidence_bundle"]
                        else None
                    )
                except (TypeError, ValueError):
                    save_evidence_bundle = None
                logger.info(
                    "save_finding: preserving OOB-confirmed state for "
                    "finding %s — DB row is Tool-Confirmed but in-memory "
                    "finding is %s; keeping DB values for "
                    "confidence_level/confidence/reasoning/payload.",
                    finding.id,
                    finding.confidence_level,
                )

            # TEAM-1 Phase 3: REFUTED is a terminal state with the highest
            # precedence in the monotonic evidence law. Once deterministic
            # contradictory evidence has been persisted, NO later graph-state
            # save (INSERT OR REPLACE of a stale in-memory snapshot, a
            # reporter re-save, a checkpoint replay) may resurrect the old
            # confirmation. Only mark_refuted() itself may write Refuted
            # columns (its in-memory finding is also Refuted, so the branch
            # above is skipped and the fresh refuted snapshot wins).
            if (
                existing_row is not None
                and existing_row["confidence_level"] == "Refuted"
                and finding.confidence_level != "Refuted"
            ):
                save_confidence_level = existing_row["confidence_level"]
                save_confidence = existing_row["confidence"]
                save_reasoning = existing_row["reasoning"]
                save_payload = existing_row["payload"]
                logger.info(
                    "save_finding: REFUTED state preserved for finding %s — "
                    "in-memory snapshot is %s; a refuted finding cannot be "
                    "resurrected by a later save (refutation evidence: %s).",
                    finding.id,
                    finding.confidence_level,
                    existing_row["evidence_hash"] or "n/a",
                )

            conn.execute(
                _FINDINGS_INSERT,
                (
                    str(finding.id),
                    finding.title,
                    self._enum_value(finding.severity),
                    finding.description,
                    finding.tool_name,
                    save_payload,
                    finding.request_method,
                    json.dumps(finding.request_data) if finding.request_data else "{}",
                    finding.target_param,
                    finding.url,
                    save_confidence,
                    finding.created_at.isoformat(),
                    json.dumps(save_evidence) if save_evidence else None,
                    json.dumps(finding.references),
                    finding.cvss_score,
                    finding.business_impact,
                    save_confidence_level,
                    save_reasoning,
                    finding.oob_token,
                    finding.canary_token,
                    json.dumps(save_evidence_bundle) if save_evidence_bundle else None,
                    json.dumps(finding.compliance_tags) if finding.compliance_tags else "[]",
                    finding.evidence_hash,
                    json.dumps(finding.post_exploitation_data)
                    if finding.post_exploitation_data
                    else None,
                    self._enum_value(finding.vuln_class) if finding.vuln_class else "unknown",
                    # V7 Cognitive Upgrade — Phase 4: persist the new
                    # informational fields so the audit-trail back-reference
                    # (hypothesis_id) survives DB round-trips.
                    finding.strategic_confidence_score,
                    str(finding.hypothesis_id) if finding.hypothesis_id else None,
                    # V9 P0 Fix 3: persist thread_id for per-engagement isolation.
                    getattr(finding, "thread_id", None),
                    # R3 E-1 (amendment B): clobber-safe advisory round-trip.
                    # INSERT OR REPLACE rewrites every column, so a stale
                    # in-memory snapshot (read before an advisory append,
                    # saved after it) must not silently drop persisted
                    # advisory records — the same clobber class the
                    # OOB-confirmed columns received in V10 P1-10. The
                    # persisted list is authoritative; in-memory-only
                    # records are unioned in per correlation token.
                    json.dumps(self._merge_advisory_for_save(
                        existing_row, finding.advisory_evidence or [],
                    )),
                ),
            )

            # Capture the transition decision for the post-commit
            # notification hook (Track 11 item 8) — the variables inside
            # the try below are otherwise unreachable after commit.
            transition_new_status: str | None = None
            transition_old_status: str | None = None
            # TEAM-1 Phase 3: append a status-history row whenever the
            # state-machine status changed (or on first persist). Committed
            # atomically with the finding write on the same connection.
            try:
                new_status = _STATUS_LEVEL_MAP.get(str(save_confidence_level), STATUS_UNCONFIRMED)
                old_status = None
                if existing_row is not None:
                    old_status = _STATUS_LEVEL_MAP.get(
                        str(existing_row["confidence_level"]), STATUS_UNCONFIRMED
                    )
                if existing_row is None or new_status != old_status:
                    transition_new_status = str(new_status)
                    transition_old_status = str(old_status) if old_status is not None else None
                    conn.execute(
                        _FINDING_HISTORY_INSERT,
                        (
                            str(finding.id),
                            getattr(finding, "thread_id", None)
                            or (existing_row["thread_id"] if existing_row else None),
                            new_status,
                            finding.evidence_hash,
                            json.dumps(finding.evidence) if finding.evidence else None,
                            "save_finding",
                            f"status transition {old_status or 'NEW'} -> {new_status}",
                            datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        ),
                    )
            except sqlite3.Error as exc:
                # History is an audit trail: a history write failure must
                # never mask the finding write that just succeeded, but it
                # is loud so operators can repair the audit trail.
                logger.warning(
                    "save_finding: status-history append failed for %s: %s",
                    finding.id,
                    exc,
                )

            conn.commit()

        # Track 11 item 8 (2026-10-28): fire-and-forget confirmation
        # notification when a finding BECOMES CONFIRMED (not for the
        # first-persist UNCONFIRMED row, and never for a repeated
        # CONFIRMED save). Runs AFTER commit — and, since P1-04
        # (0.33.0), OUTSIDE the write lock/transaction: a notification
        # can never block, slow down, or hold the SQLite file hostage
        # (see webpent.vip.notifications for the channel/idempotency/
        # redaction contract).
        if (
            transition_new_status is not None
            and transition_new_status == STATUS_CONFIRMED
        ):
            try:
                from webpent.vip.notifications import notify_confirmation_transition

                notify_confirmation_transition(
                    new_status=transition_new_status,
                    old_status=transition_old_status,
                    finding=finding,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "save_finding: confirmation notification failed for %s: %s",
                    finding.id,
                    exc,
                )

    def get_all_findings(self) -> list[Finding]:
        """Return every persisted finding, ordered by creation time.

        V9 P1 RE-5: Corrupt finding row resilience — one bad row cannot
        crash the entire findings fetch.
        """
        self.init_db()
        with self._connect() as conn:
            cursor = conn.execute(_FINDINGS_SELECT)
            rows = cursor.fetchall()

        findings: list[Finding] = []
        for row in rows:
            try:
                findings.append(self._row_to_finding(row))
            except Exception as exc:
                row_id = "<unknown>"
                with suppress(Exception):
                    row_id = row["id"]
                logger.warning(
                    "Skipping corrupt finding row (id=%s): %s",
                    row_id,
                    exc,
                )
        return findings

    def get_findings_by_thread(self, thread_id: str) -> list[Finding]:
        """V9 P0 Fix 3: Return findings for a specific engagement thread only.

        V9 P1 RE-5: Corrupt finding row resilience — one bad row cannot
        crash the entire findings fetch.
        """
        self.init_db()
        with self._connect() as conn:
            cursor = conn.execute(_FINDINGS_SELECT_BY_THREAD, (thread_id,))
            rows = cursor.fetchall()

        findings: list[Finding] = []
        for row in rows:
            try:
                findings.append(self._row_to_finding(row))
            except Exception as exc:
                row_id = "<unknown>"
                with suppress(Exception):
                    row_id = row["id"]
                logger.warning(
                    "Skipping corrupt finding row (id=%s): %s",
                    row_id,
                    exc,
                )
        return findings

    def get_findings_by_threads(self, thread_ids: list[str] | tuple[str, ...]) -> list[Finding]:
        """Return findings for a bounded set of threads in creation order."""
        clean_ids = list(dict.fromkeys(str(item) for item in thread_ids if str(item)))[:256]
        if not clean_ids:
            return []
        self.init_db()
        placeholders = ", ".join("?" for _ in clean_ids)
        query = f"""
        SELECT
            id, title, severity, description, tool_name,
            payload, request_method, request_data, target_param, url,
    confidence, created_at, evidence, "references",
            cvss_score, business_impact, confidence_level, reasoning, oob_token,
            canary_token, evidence_bundle, compliance_tags, evidence_hash,
            post_exploitation_data, vuln_class,
            strategic_confidence_score, hypothesis_id, thread_id,
            advisory_evidence
        FROM findings
        WHERE thread_id IN ({placeholders})
        ORDER BY created_at ASC;
        """
        with self._connect() as conn:
            rows = conn.execute(query, clean_ids).fetchall()

        findings: list[Finding] = []
        for row in rows:
            try:
                findings.append(self._row_to_finding(row))
            except Exception as exc:
                row_id = "<unknown>"
                with suppress(Exception):
                    row_id = row["id"]
                logger.warning(
                    "Skipping corrupt finding row (id=%s): %s",
                    row_id,
                    exc,
                )
        return findings

    @staticmethod
    def _merge_advisory_for_save(existing_row: Any, in_memory: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Clobber-safe advisory_evidence merge for save_finding (R3 E-1).

        The persisted column is authoritative. In-memory-only records (not
        present in the persisted list by correlation token) are unioned in;
        persisted records are never dropped by a stale snapshot. Malformed
        persisted values degrade to the empty list via the same fail-closed
        parser the read path uses.
        """
        persisted: list[dict[str, Any]] = []
        if existing_row is not None:
            try:
                persisted = DatabaseManager._parse_advisory_evidence(
                    existing_row["advisory_evidence"]
                )
            except (IndexError, KeyError):
                persisted = []
        if not persisted:
            return list(in_memory or [])
        seen = {
            item.get("correlation_token")
            for item in persisted
            if isinstance(item, dict)
        }
        merged = list(persisted)
        for item in in_memory or []:
            tok = item.get("correlation_token") if isinstance(item, dict) else None
            if tok not in seen:
                merged.append(item)
                if tok is not None:
                    seen.add(tok)
        return merged

    @staticmethod
    def _parse_advisory_evidence(raw: Any) -> list[dict[str, Any]]:
        """Parse a persisted advisory_evidence JSON value (R3 E-1).

        Fail-closed read contract: anything that is not a JSON list of
        mappings (missing column, empty value, malformed JSON, wrong
        shape) degrades to the default-empty list. A malformed value can
        never be inflated into confirmation semantics by a reader.
        """
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            return []
        if not isinstance(parsed, list):
            return []
        return [item for item in parsed if isinstance(item, dict)]

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        """Convert a DB row into a validated :class:`Finding`.

        M1-B (E-1): rows whose confidence_level is "Tool-Confirmed" but
        whose evidence carries no confirmation provenance (possible only
        for rows written by pre-M1 code paths that predate the model-level
        proof requirement) are loaded FAIL-CLOSED: the returned Finding is
        downgraded to "Needs Human Review" with an explicit
        ``provenance_missing_on_load`` marker, never silently kept as
        confirmed.
        """

        # V5 Sprint 11: defensively read optional columns that may not
        # exist on pre-Sprint-11 databases (the ALTER TABLE migrations
        # add them, but in-memory test DBs may be created from old DDL).
        def _get_col(name: str, default: Any = None) -> Any:
            try:
                return row[name]
            except (IndexError, KeyError):
                return default

        def _build(confidence_level: str, evidence: Any) -> Finding:
            return Finding(
                id=UUID(row["id"]),
                title=row["title"],
                severity=Severity(row["severity"]),
                description=row["description"],
                tool_name=row["tool_name"],
                payload=row["payload"],
                request_method=_get_col("request_method", "GET") or "GET",
                request_data=(
                    json.loads(_get_col("request_data")) if _get_col("request_data") else {}
                ),
                target_param=_get_col("target_param"),
                url=row["url"],
                confidence=Confidence(row["confidence"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                evidence=evidence,
                references=json.loads(row["references"]) if row["references"] else [],
                cvss_score=row["cvss_score"],
                business_impact=row["business_impact"],
                confidence_level=confidence_level,
                reasoning=row["reasoning"] or "",
                oob_token=row["oob_token"] or "",
                canary_token=_get_col("canary_token"),
                evidence_bundle=(
                    json.loads(_get_col("evidence_bundle")) if _get_col("evidence_bundle") else None
                ),
                compliance_tags=(
                    json.loads(_get_col("compliance_tags", "[]"))
                    if _get_col("compliance_tags", "[]")
                    else []
                ),
                # R3 E-1 (amendment B): authority-neutral advisory records. A
                # malformed persisted value degrades to the default-empty list
                # (fail-closed read: bad JSON never becomes confirmation state).
                advisory_evidence=DatabaseManager._parse_advisory_evidence(
                    _get_col("advisory_evidence")
                ),
                evidence_hash=_get_col("evidence_hash"),
                post_exploitation_data=(
                    json.loads(_get_col("post_exploitation_data"))
                    if _get_col("post_exploitation_data")
                    else None
                ),
                vuln_class=_get_col("vuln_class", "unknown"),
                # V7 Cognitive Upgrade — Phase 4: read the new informational
                # fields. _get_col defensively handles pre-V7 DBs where the
                # columns don't exist yet (returns None — treated as 'not
                # scored' / 'no back-reference' by the model).
                strategic_confidence_score=_get_col("strategic_confidence_score"),
                hypothesis_id=(UUID(_get_col("hypothesis_id")) if _get_col("hypothesis_id") else None),
                # V9 P0 Fix 3: read thread_id for per-engagement isolation.
                thread_id=_get_col("thread_id"),
            )

        raw_level = str(row["confidence_level"] or "Pending")
        raw_evidence = json.loads(row["evidence"]) if row["evidence"] else None
        if raw_level != "Tool-Confirmed":
            return _build(raw_level, raw_evidence)
        # Tool-Confirmed rows: prove provenance or load fail-closed.
        try:
            return _build(raw_level, raw_evidence)
        except ValidationError as exc:
            if "Tool-Confirmed" not in str(exc):
                raise
            logger.warning(
                "_row_to_finding: persisted Tool-Confirmed row %s carries no "
                "confirmation provenance (pre-M1 writer) — loading FAIL-CLOSED "
                "as Needs Human Review with provenance_missing_on_load marker.",
                row["id"],
            )
            evidence = dict(raw_evidence) if isinstance(raw_evidence, dict) else {}
            evidence["provenance_missing_on_load"] = True
            return _build("Needs Human Review", evidence)

    # ------------------------------------------------------------------ #
    # V5 Sprint 5: OOB callback support                                  #
    # ------------------------------------------------------------------ #
    def get_finding(self, finding_id: UUID | str) -> Finding | None:
        """Return a single finding by its UUID, or ``None`` if not present.

        Used by the OOB callback endpoint to look up the row being
        confirmed, and by the validator's poll loop to inspect whether
        a callback has landed.
        """
        self.init_db()
        with self._connect() as conn:
            cursor = conn.execute(_FINDINGS_SELECT_BY_ID, (str(finding_id),))
            row = cursor.fetchone()
        return self._row_to_finding(row) if row is not None else None

    def mark_oob_confirmed(
        self,
        finding_id: UUID | str,
        *,
        reasoning_appendix: str,
        payload_marker: str | None = None,
        causal_observation: Mapping[str, Any] | None = None,
        proof_bundle: Any = None,
    ) -> Finding | None:
        """Flip a finding to Tool-Confirmed via an OOB callback.

        Updates exactly the columns that change on OOB confirmation:
          * ``confidence_level`` → ``"Tool-Confirmed"``
          * ``confidence``       → ``Confidence.CONFIRMED``
          * ``reasoning``        → existing reasoning + appendix
          * ``payload``          → marker (if provided)

        Returns the post-update Finding, or ``None`` if the ID was not
        found. The write is serialised under ``_write_lock`` so concurrent
        callbacks for the same finding cannot corrupt each other.

        V5 Sprint 9: Uses ``BEGIN IMMEDIATE`` to acquire a file-level
        SQLite write lock at transaction start. This prevents
        multi-worker race conditions that ``threading.Lock`` cannot
        protect against (each Celery worker is a separate process with
        its own lock instance). ``BEGIN IMMEDIATE`` blocks other writers
        until the transaction commits, ensuring the read-modify-write
        cycle is atomic across processes.

        Args:
            finding_id: UUID of the finding to confirm.
            reasoning_appendix: Text appended to the existing reasoning
                trail (e.g. ``"OOB Callback Received from <ip> at <ts>"``).
            payload_marker: Optional payload string to record (e.g.
                ``"confirmed-by:oob-callback"``).
        """
        self.init_db()
        if not (
            validate_causal_observation(causal_observation)
            and validate_bundle_structure(proof_bundle, require_negative_control=True)
        ):
            logger.warning(
                "OOB confirmation blocked for finding %s: causal signal and sealed "
                "negative-control proof are required.",
                finding_id,
            )
            return self.get_finding(finding_id)
        with self._write_lock, self._connect() as conn:
            # V5 Sprint 9: BEGIN IMMEDIATE acquires a RESERVED lock
            # immediately, preventing other connections (including
            # those in other worker processes) from writing until we
            # commit. This closes the multi-worker race that
            # threading.Lock cannot prevent (locks are per-process).
            try:
                conn.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                # Another writer holds the lock; the busy_timeout
                # (30s) should normally prevent this, but if it
                # fires we propagate so the caller can retry.
                logger.warning(
                    "mark_oob_confirmed: BEGIN IMMEDIATE failed for finding %s: %s",
                    finding_id,
                    exc,
                )
                raise

            try:
                # Read-modify-write inside the transaction so the
                # reasoning append is atomic and cannot lose a
                # concurrent writer's update.
                cursor = conn.execute(_FINDINGS_SELECT_BY_ID, (str(finding_id),))
                row = cursor.fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    return None

                existing_confidence_level = str(row["confidence_level"] or "")
                existing_confidence = str(row["confidence"] or "").lower()
                if (
                    existing_confidence_level == "Tool-Confirmed"
                    or existing_confidence == Confidence.CONFIRMED.value.lower()
                ):
                    # One-way/idempotent transition: a replayed callback must
                    # not append another forensic line or overwrite a later
                    # confirmation. The transaction is rolled back because
                    # this request made no state change.
                    conn.execute("ROLLBACK")
                    return self._row_to_finding(row)

                # TEAM-1 Phase 3: REFUTED is terminal. A late/replayed OOB
                # callback must NOT resurrect a finding whose confirmation
                # was already retracted by verified contradictory evidence.
                # The callback is recorded as a no-op and the Refuted row is
                # returned unchanged.
                if existing_confidence_level == "Refuted":
                    logger.warning(
                        "mark_oob_confirmed: refusing to re-confirm refuted "
                        "finding %s — deterministic refutation stands; the "
                        "callback is logged but changes no state.",
                        finding_id,
                    )
                    conn.execute("ROLLBACK")
                    return self._row_to_finding(row)

                existing_reasoning = row["reasoning"] or ""
                new_reasoning = (
                    f"{existing_reasoning}\n{reasoning_appendix}".strip()
                    if existing_reasoning
                    else reasoning_appendix
                )

                # M1-B (E-1): stamp the confirmation provenance into the
                # evidence JSON so the row remains loadable under the
                # model-level Tool-Confirmed proof requirement
                # (models/findings.py). The gate above already validated
                # the causal observation and the sealed negative-control
                # proof bundle BEFORE this write — this only records that
                # fact on the row itself.
                try:
                    existing_evidence = json.loads(row["evidence"]) if row["evidence"] else {}
                except (TypeError, ValueError):
                    existing_evidence = {}
                if not isinstance(existing_evidence, dict):
                    existing_evidence = {}
                existing_evidence["oob_confirmed"] = True
                existing_evidence["tool_confirmed_by"] = "oob.callback_token_gate"
                existing_evidence["oob_causal_validated"] = True

                conn.execute(
                    _FINDINGS_UPDATE_OOB,
                    (
                        "Tool-Confirmed",
                        Confidence.CONFIRMED.value,
                        new_reasoning,
                        payload_marker,
                        json.dumps(existing_evidence),
                        str(finding_id),
                    ),
                )

                # TEAM-1 Phase 3: record the UNCONFIRMED -> CONFIRMED
                # transition in the append-only history (atomic with the
                # status change).
                try:
                    conn.execute(
                        _FINDING_HISTORY_INSERT,
                        (
                            str(finding_id),
                            row["thread_id"],
                            STATUS_CONFIRMED,
                            row["evidence_hash"],
                            row["evidence"],
                            "mark_oob_confirmed",
                            "OOB callback with sealed negative-control proof",
                            datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        ),
                    )
                except sqlite3.Error as exc:
                    logger.warning(
                        "mark_oob_confirmed: history append failed for %s: %s",
                        finding_id,
                        exc,
                    )

                conn.commit()

                # Re-read so the returned object reflects the persisted state.
                cursor = conn.execute(_FINDINGS_SELECT_BY_ID, (str(finding_id),))
                row = cursor.fetchone()
                updated = self._row_to_finding(row) if row is not None else None
                # Track 11 item 8: OOB confirmation is a transition INTO
                # CONFIRMED too — same fire-and-forget, persistence-safe
                # notification contract as save_finding.
                if updated is not None:
                    try:
                        from webpent.vip.notifications import notify_confirmation_transition

                        notify_confirmation_transition(
                            new_status=STATUS_CONFIRMED,
                            old_status=None,
                            finding=updated,
                        )
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "mark_oob_confirmed: notification failed for %s: %s",
                            updated.id,
                            exc,
                        )
                return updated
            except Exception:
                # Any error during the transaction → roll back so we
                # don't leave a half-written state.
                with _suppress_sqlite_errors():
                    conn.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------------ #
    # R3 E-1 (Ruling R3-002 §3.2(v)) — advisory sibling write            #
    # ------------------------------------------------------------------ #
    def append_oob_advisory_evidence(
        self,
        finding_id: UUID | str,
        *,
        correlation_token: str,
        record: Mapping[str, Any],
    ) -> tuple[Finding | None, str]:
        """Append an AUTHORITY-NEUTRAL OOB advisory record to a finding.

        R3 E-1 (Ruling R3-002): the OOB callback path must NEVER construct
        or seal a ProofBundle and NEVER change confidence/confidence_level.
        This sibling of ``mark_oob_confirmed`` persists the correlated
        callback as advisory metadata instead, under the same multi-worker
        write discipline (``_write_lock`` + ``BEGIN IMMEDIATE``), with the
        same fail-closed shape:

          * Contract (validated BEFORE any write opens — malformed input
            can never leave a partial write):
              - ``record`` must be a JSON-serializable mapping;
              - ``correlation_token`` must be a non-empty string;
              - the finding must exist.
          * Replay idempotency (rider RF-04): deduplication by
            correlation token — a repeated callback collapses to the
            single existing record and reports status ``"duplicate"``
            with an idempotent success result.
          * Single-column mutation (fail-closed by construction): the
            only statement this method can execute is
            ``UPDATE findings SET advisory_evidence = ?``. Confidence,
            confidence_level, reasoning, payload, and the status history
            are structurally unreachable from here (C5: fail-closed only).

        Returns:
            ``(finding, status)`` where ``status`` is ``"appended"``,
            ``"duplicate"``, or ``"not_found"`` (unknown finding id).
            ``finding`` is the post-read row (unchanged authority state).

        Raises:
            TypeError: ``record`` is not a mapping or not JSON-serializable.
            ValueError: ``correlation_token`` empty/non-string.
        """
        # ---- contract validation BEFORE any write (no partial writes) ----
        if not isinstance(correlation_token, str) or not correlation_token.strip():
            raise ValueError(
                "append_oob_advisory_evidence: correlation_token must be a "
                "non-empty string."
            )
        if not isinstance(record, Mapping):
            raise TypeError(
                "append_oob_advisory_evidence: record must be a mapping."
            )
        try:
            # Validation-only serialization: a non-serializable record must
            # fail here, BEFORE the transaction opens (no partial writes).
            json.dumps(dict(record), sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise TypeError(
                "append_oob_advisory_evidence: record must be JSON-serializable."
            ) from exc

        self.init_db()
        with self._write_lock, self._connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                logger.warning(
                    "append_oob_advisory_evidence: BEGIN IMMEDIATE failed for "
                    "finding %s: %s",
                    finding_id,
                    exc,
                )
                raise

            try:
                cursor = conn.execute(_FINDINGS_SELECT_BY_ID, (str(finding_id),))
                row = cursor.fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    return None, "not_found"

                existing = self._parse_advisory_evidence(row["advisory_evidence"])
                for item in existing:
                    if item.get("correlation_token") == correlation_token:
                        # RF-04: replay-idempotent — no duplicate record, no
                        # state change, success semantics for the caller.
                        conn.execute("ROLLBACK")
                        return self._row_to_finding(row), "duplicate"

                updated = [
                    *existing,
                    {**dict(record), "correlation_token": correlation_token},
                ]
                conn.execute(
                    _FINDINGS_UPDATE_ADVISORY,
                    (json.dumps(updated, sort_keys=True), str(finding_id)),
                )
                conn.commit()

                cursor = conn.execute(_FINDINGS_SELECT_BY_ID, (str(finding_id),))
                row = cursor.fetchone()
                return (
                    self._row_to_finding(row) if row is not None else None
                ), "appended"
            except Exception:
                with _suppress_sqlite_errors():
                    conn.execute("ROLLBACK")
                raise

    # =====================================================================
    # TEAM-1 Phase 3 — deterministic refutation path.
    # =====================================================================
    def mark_refuted(
        self,
        finding_id: UUID | str,
        *,
        reasoning_appendix: str,
        causal_observation: Mapping[str, Any] | None = None,
        proof_bundle: Any = None,
        evidence_hash: str | None = None,
    ) -> Finding | None:
        """Retract a finding using VERIFIED CONTRADICTORY DETERMINISTIC EVIDENCE.

        Part of the monotonic evidence law:

            UNCONFIRMED -> CONFIRMED -> REFUTED

        A refutation is only legal when it carries deterministic evidence of
        the same rigor as a confirmation:

          * a causal observation that passes ``validate_causal_observation``
            (observed, structured HTTP behaviour — not an LLM conclusion),
          * AND a proof bundle that passes ``validate_bundle_structure`` with
            a sealed negative control.

        LLM text (Devil's Advocate arguments, model explanations, reasoning
        strings) can NEVER refute a finding on its own — a call without the
        deterministic evidence pair is refused fail-closed and the row is
        left untouched.

        REFUTED is terminal: ``save_finding`` and ``mark_oob_confirmed``
        preserve it against later resurrection. Every successful refutation
        appends a REFUTED row to ``finding_status_history`` atomically.

        Args:
            finding_id: UUID of the finding to refute.
            reasoning_appendix: Human-auditable reason appended to the
                reasoning trail (e.g. the differential-test verdict).
            causal_observation: Deterministic contradictory observation
                (baseline/candidate/negative-control digest structure).
            proof_bundle: Sealed proof bundle covering the observation.
            evidence_hash: Optional digest of the contradictory evidence to
                store on the row for correlation with the history entry.

        Returns:
            The post-update Finding, the unchanged Finding when the call was
            refused or was idempotent, or ``None`` if the ID was not found.
        """
        self.init_db()
        if not (
            validate_causal_observation(causal_observation)
            and validate_bundle_structure(proof_bundle, require_negative_control=True)
        ):
            logger.warning(
                "Refutation refused for finding %s: deterministic contradictory "
                "evidence (causal observation + sealed negative-control proof) "
                "is required — LLM text alone can never refute a finding.",
                finding_id,
            )
            return self.get_finding(finding_id)

        with self._write_lock, self._connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                logger.warning(
                    "mark_refuted: BEGIN IMMEDIATE failed for finding %s: %s",
                    finding_id,
                    exc,
                )
                raise

            try:
                cursor = conn.execute(_FINDINGS_SELECT_BY_ID, (str(finding_id),))
                row = cursor.fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    return None

                existing_level = str(row["confidence_level"] or "")
                if existing_level == "Refuted":
                    # Idempotent: already refuted (same or earlier evidence).
                    conn.execute("ROLLBACK")
                    return self._row_to_finding(row)

                existing_reasoning = row["reasoning"] or ""
                new_reasoning = (
                    f"{existing_reasoning}\n{reasoning_appendix}".strip()
                    if existing_reasoning
                    else reasoning_appendix
                )

                # Merge the refutation into the evidence envelope without
                # destroying the original confirmation evidence: history is
                # preserved, the LATEST status simply becomes REFUTED.
                try:
                    existing_evidence = json.loads(row["evidence"]) if row["evidence"] else {}
                    if not isinstance(existing_evidence, dict):
                        existing_evidence = {"legacy_evidence": existing_evidence}
                except (TypeError, ValueError):
                    existing_evidence = {}
                refutation_block = {
                    "refutation": {
                        "reason": reasoning_appendix[:500],
                        "evidence_hash": evidence_hash,
                        "causal_observation": dict(causal_observation or {}),
                        "refuted_at": datetime.now(timezone.utc).isoformat(
                            timespec="seconds"
                        ),
                    }
                }
                merged_evidence = {**existing_evidence, **refutation_block}

                conn.execute(
                    "UPDATE findings SET confidence_level = ?, confidence = ?, "
                    "reasoning = ?, evidence = ?, evidence_hash = COALESCE(?, evidence_hash) "
                    "WHERE id = ?;",
                    (
                        "Refuted",
                        Confidence.TENTATIVE.value,
                        new_reasoning,
                        json.dumps(merged_evidence),
                        evidence_hash,
                        str(finding_id),
                    ),
                )

                try:
                    conn.execute(
                        _FINDING_HISTORY_INSERT,
                        (
                            str(finding_id),
                            row["thread_id"],
                            STATUS_REFUTED,
                            evidence_hash or row["evidence_hash"],
                            json.dumps(refutation_block),
                            "mark_refuted",
                            reasoning_appendix[:500],
                            datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        ),
                    )
                except sqlite3.Error as exc:
                    logger.warning(
                        "mark_refuted: history append failed for %s: %s",
                        finding_id,
                        exc,
                    )

                conn.commit()

                cursor = conn.execute(_FINDINGS_SELECT_BY_ID, (str(finding_id),))
                row = cursor.fetchone()
                return self._row_to_finding(row) if row is not None else None
            except Exception:
                with _suppress_sqlite_errors():
                    conn.execute("ROLLBACK")
                raise

    def get_finding_status_history(self, finding_id: UUID | str) -> list[dict[str, Any]]:
        """Return the full append-only status history for one finding."""
        self.init_db()
        with self._connect() as conn:
            rows = conn.execute(
                _FINDING_HISTORY_ALL, (str(finding_id),)
            ).fetchall()
        return [dict(row) for row in rows]

    def get_latest_finding_status(self, finding_id: UUID | str) -> str | None:
        """Return the latest state-machine status for one finding.

        Resolution order: the newest history row when one exists; otherwise
        the current display level mapped through the state-machine vocabulary.
        Legacy rows (no history) resolve to CONFIRMED/UNCONFIRMED by their
        persisted confidence_level, never guessed.
        """
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                _FINDING_HISTORY_LATEST, (str(finding_id),)
            ).fetchone()
            if row is not None:
                return str(row["status"])
            finding_row = conn.execute(
                _FINDINGS_SELECT_BY_ID, (str(finding_id),)
            ).fetchone()
        if finding_row is None:
            return None
        return _STATUS_LEVEL_MAP.get(
            str(finding_row["confidence_level"] or ""), STATUS_UNCONFIRMED
        )


# ======================================================================
# V6 DX-Final P0 FIX (CISO audit): Module-level singleton accessor.
# ======================================================================
# Previously, every caller in the framework instantiated
# ``DatabaseManager()`` independently (in ``api/app.py``,
# ``workers/pentest_worker.py``, ``agents/validator/agent.py``,
# ``agents/post_exploit/agent.py``, ``agents/execution_sandbox/agent.py``).
# Each construction created a fresh ``_write_lock`` (threading.Lock) and
# a fresh ``_initialised = False`` flag, which had two consequences:
#
#   1. The in-process write lock was effectively useless — concurrent
#      callers each held their own lock, so they could all enter the
#      critical section simultaneously and race on the SQLite writer.
#   2. ``init_db()`` was re-run by every caller, re-entering the
#      Alembic migration path (file lock acquisition, version check,
#      potential upgrade) on every request even when the database was
#      already initialised — producing needless serialization
#      bottlenecks on the migration lock file.
#
# The singleton below ensures every caller shares the SAME
# ``DatabaseManager`` instance, the SAME ``_write_lock``, and the SAME
# ``_initialised`` flag. ``init_db()`` therefore runs at most once per
# process lifetime, and all subsequent writes are properly serialized
# through the single shared lock.
# ======================================================================
_db_manager_singleton: DatabaseManager | None = None
_db_manager_singletons: dict[str, DatabaseManager] = {}
_db_manager_singleton_lock = threading.Lock()


def get_db_manager(database_url: str | None = None) -> DatabaseManager:
    """Return a manager scoped to an explicit or active target database.

    Legacy callers outside a target workspace keep the original singleton
    semantics. During a target-scoped execution, an omitted URL resolves to
    that workspace's database and is cached by its normalized URL, preventing
    one target from reusing another target's SQLite connection state.
    """
    global _db_manager_singleton
    resolved_url = database_url
    if resolved_url is None:
        try:
            from webpent.shared.target_workspace_context import (
                get_active_target_workspace,
            )

            workspace = get_active_target_workspace()
        except ImportError:
            workspace = None
        if workspace is not None:
            resolved_url = workspace.database_url
    if resolved_url is None:
        if _db_manager_singleton is None:
            with _db_manager_singleton_lock:
                if _db_manager_singleton is None:
                    _db_manager_singleton = DatabaseManager()
        return _db_manager_singleton
    key = str(resolved_url)
    with _db_manager_singleton_lock:
        manager = _db_manager_singletons.get(key)
        if manager is None:
            manager = DatabaseManager(key)
            _db_manager_singletons[key] = manager
        return manager
