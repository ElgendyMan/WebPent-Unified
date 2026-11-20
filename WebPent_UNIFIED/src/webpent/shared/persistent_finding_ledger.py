"""Durable cumulative finding history with explicit tenant scoping.

This store is intentionally separate from the per-run findings table. A new
WebPent checkout or code revision must not erase the authoritative history for
the same authorized engagement. The ledger stores redacted Finding snapshots,
release provenance, and a deterministic logical fingerprint; it never stores
raw credentials, cookies, OOB tokens, or authorization headers.

Rows written by current entrypoints are scoped by ``engagement_id``,
``owner_username`` and ``client_id``. Legacy callers that omit both optional
scope arguments use an anonymous/legacy partition and cannot read scoped rows.
This preserves compatibility while preventing a reused engagement label from
becoming a cross-user or cross-client data channel.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.models.findings import Finding
from webpent.shared.finding_aggregation import aggregate_findings, finding_fingerprint

_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "oob_token",
    "canary_token",
}


DDL = """
CREATE TABLE IF NOT EXISTS cumulative_findings (
    fingerprint TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    owner_username TEXT NOT NULL DEFAULT '',
    client_id TEXT NOT NULL DEFAULT '',
    finding_json TEXT NOT NULL,
    release_id TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    source_threads TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (engagement_id, owner_username, client_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS ix_cumulative_findings_engagement
    ON cumulative_findings(engagement_id);
CREATE INDEX IF NOT EXISTS ix_cumulative_findings_scope
    ON cumulative_findings(engagement_id, owner_username, client_id);
"""


def _default_path() -> Path:
    configured = os.getenv("WEBPENT_FINDINGS_LEDGER_PATH", "~/.webpent/findings_ledger.sqlite3")
    return Path(configured).expanduser()


def current_release_id() -> str:
    """Return a stable operator-visible release identifier for this checkout."""
    explicit = os.getenv("WEBPENT_RELEASE_ID") or os.getenv("WEBPENT_BUILD_ID")
    if explicit:
        return explicit.strip()[:128] or "unknown-release"
    try:
        from importlib.metadata import version

        return f"webpent-{version('webpent')}"
    except Exception:
        return "webpent-dev"


def _redact(value: Any, key: str = "") -> Any:
    normalized_key = key.lower().replace("-", "_")
    if normalized_key in _SENSITIVE_KEYS or normalized_key.endswith("_token"):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item, key) for item in value]
    return value


def _safe_finding_json(finding: Finding) -> str:
    data = _redact(finding.model_dump(mode="json"))
    return json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _finding_from_json(raw: str) -> Finding | None:
    try:
        return Finding.model_validate(json.loads(raw))
    except Exception:
        return None


def _scope_values(
    owner_username: str | None,
    client_id: str | None,
) -> tuple[str, str, bool]:
    """Normalize scope and distinguish explicit scope from legacy calls."""
    scoped = owner_username is not None or client_id is not None
    return (
        str(owner_username or "").strip(),
        str(client_id or "").strip(),
        scoped,
    )


def _ensure_schema(connection: sqlite3.Connection) -> None:
    """Create or migrate the ledger schema without losing legacy findings."""
    columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(cumulative_findings)").fetchall()
    }
    if not columns:
        connection.executescript(DDL)
        return
    if {"owner_username", "client_id"}.issubset(columns):
        connection.executescript(DDL)
        return

    # The pre-scope schema used (engagement_id, fingerprint) as its primary
    # key. Move its rows into the anonymous legacy partition. Current callers
    # pass explicit owner/client values, so these rows remain available only
    # to explicit legacy/anonymous reads and cannot bleed into tenant scopes.
    connection.execute(
        "ALTER TABLE cumulative_findings RENAME TO cumulative_findings_legacy"
    )
    connection.execute("DROP INDEX IF EXISTS ix_cumulative_findings_engagement")
    connection.executescript(DDL)
    connection.execute(
        """
        INSERT INTO cumulative_findings
        (fingerprint, engagement_id, owner_username, client_id, finding_json,
         release_id, first_seen_at, last_seen_at, source_threads)
        SELECT fingerprint, engagement_id, '', '', finding_json, release_id,
               first_seen_at, last_seen_at, source_threads
        FROM cumulative_findings_legacy
        """
    )
    connection.execute("DROP TABLE cumulative_findings_legacy")


class PersistentFindingLedger:
    """Append/merge store that survives WebPent code revisions."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path).expanduser() if path else _default_path()
        self._lock = threading.Lock()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.path), timeout=30.0)
        connection.row_factory = sqlite3.Row
        try:
            # P1-17 (0.33.0): multiple Celery workers and CLI processes
            # write this ledger concurrently. The in-process threading.Lock
            # cannot see the other processes; without WAL + busy_timeout a
            # merge burst hit "database is locked" after the 30s timeout
            # and the _persist_findings safety net was lost mid-engagement.
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA busy_timeout=5000")
            _ensure_schema(connection)
            yield connection
            connection.commit()
        finally:
            connection.close()

    def merge(
        self,
        engagement_id: str,
        findings: list[Finding],
        *,
        release_id: str | None = None,
        thread_id: str | None = None,
        owner_username: str | None = None,
        client_id: str | None = None,
    ) -> list[Finding]:
        """Merge current findings into one explicit history partition."""
        scope = engagement_id.strip()
        if not scope:
            raise ValueError("engagement_id must not be empty")
        owner, client, scoped = _scope_values(owner_username, client_id)
        release = (release_id or current_release_id()).strip()[:128] or "unknown-release"
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as connection:
            for finding in findings:
                fingerprint = finding_fingerprint(finding)
                if scoped:
                    existing = connection.execute(
                        "SELECT finding_json, source_threads, first_seen_at "
                        "FROM cumulative_findings WHERE engagement_id = ? "
                        "AND owner_username = ? AND client_id = ? AND fingerprint = ?",
                        (scope, owner, client, fingerprint),
                    ).fetchone()
                else:
                    existing = connection.execute(
                        "SELECT finding_json, source_threads, first_seen_at "
                        "FROM cumulative_findings WHERE engagement_id = ? "
                        "AND owner_username = '' AND client_id = '' AND fingerprint = ?",
                        (scope, fingerprint),
                    ).fetchone()
                candidate = finding
                if existing:
                    previous = _finding_from_json(str(existing["finding_json"]))
                    if previous is not None:
                        candidate = aggregate_findings([previous, finding])[0]
                sources: list[str] = []
                if existing:
                    try:
                        sources = list(json.loads(existing["source_threads"]))
                    except Exception:
                        sources = []
                if thread_id and thread_id not in sources:
                    sources.append(thread_id)
                if not sources and candidate.thread_id:
                    sources.append(candidate.thread_id)
                first_seen_at = str(existing["first_seen_at"]) if existing else now
                connection.execute(
                    """
                    INSERT INTO cumulative_findings
                    (fingerprint, engagement_id, owner_username, client_id,
                     finding_json, release_id, first_seen_at, last_seen_at,
                     source_threads)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(engagement_id, owner_username, client_id, fingerprint)
                    DO UPDATE SET
                      finding_json = excluded.finding_json,
                      release_id = excluded.release_id,
                      last_seen_at = excluded.last_seen_at,
                      source_threads = excluded.source_threads
                    """,
                    (
                        fingerprint,
                        scope,
                        owner,
                        client,
                        _safe_finding_json(candidate),
                        release,
                        first_seen_at,
                        now,
                        json.dumps(sources, ensure_ascii=True),
                    ),
                )
            return self._read_locked(connection, scope, owner, client)

    def get(
        self,
        engagement_id: str,
        *,
        owner_username: str | None = None,
        client_id: str | None = None,
    ) -> list[Finding]:
        """Read only the requested owner/client history partition."""
        scope = engagement_id.strip()
        if not scope:
            return []
        owner, client, _ = _scope_values(owner_username, client_id)
        with self._lock, self._connect() as connection:
            return self._read_locked(connection, scope, owner, client)

    def _read_locked(
        self,
        connection: sqlite3.Connection,
        engagement_id: str,
        owner_username: str = "",
        client_id: str = "",
    ) -> list[Finding]:
        rows = connection.execute(
            "SELECT finding_json FROM cumulative_findings "
            "WHERE engagement_id = ? AND owner_username = ? AND client_id = ? "
            "ORDER BY first_seen_at ASC",
            (engagement_id, owner_username, client_id),
        ).fetchall()
        findings = [item for row in rows if (item := _finding_from_json(str(row[0]))) is not None]
        return aggregate_findings(findings)

    def export_digest(
        self,
        engagement_id: str,
        *,
        owner_username: str | None = None,
        client_id: str | None = None,
    ) -> str:
        """Return a deterministic digest for an audit/report scope."""
        findings = self.get(
            engagement_id,
            owner_username=owner_username,
            client_id=client_id,
        )
        payload = json.dumps(
            [_safe_finding_json(finding) for finding in findings],
            ensure_ascii=True,
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
