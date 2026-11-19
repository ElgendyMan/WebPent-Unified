# src/webpent/memory/postmortem.py
"""webpent.memory.postmortem

Project Zero-tier item 6 — Postmortem structure for every mistake.

Thread-safe SQLite manager for Postmortem records, following the
exact same pattern already established by:

  * :class:`webpent.memory.db.DatabaseManager` (findings), and
  * :class:`webpent.memory.decision_log.DecisionLogManager` (decisions).

Per-write connections for file-backed databases, a single shared
connection for in-memory databases, writes serialised by a
:class:`threading.Lock`. The DDL uses ``CREATE TABLE IF NOT EXISTS``
so the manager is safe to call multiple times.

Postmortem records are **append-only**, same audit-trail posture as
the Decision Log: once a root-cause analysis is recorded it is never
silently edited, only ever added to.

This module intentionally forces every record through the fixed
(category, root_cause, fix) shape described in item 6 of the
Project Zero-tier plan, rather than accepting arbitrary free text,
so that ``get_category_summary()`` below can answer "what kind of
mistake does webpent make most often?" without an LLM re-reading and
re-classifying a pile of prose every time someone asks.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import UUID

from webpent.models.postmortem import (
    PostmortemCategory,
    PostmortemKind,
    PostmortemRecord,
)

logger = logging.getLogger(__name__)

# Default location for the Postmortem database. Co-located with the
# other append-only memory stores (decision_log.db) so a single backup
# captures the full audit trail. Can be overridden by passing an
# explicit ``database_url`` to :class:`PostmortemManager`.
_DEFAULT_POSTMORTEM_DB_PATH = "./memory/global/postmortem.db"


# ---------------------------------------------------------------------------
# DDL — CREATE TABLE IF NOT EXISTS (safe to call multiple times).
# ---------------------------------------------------------------------------
_POSTMORTEM_DDL = """
CREATE TABLE IF NOT EXISTS postmortem (
    id                 TEXT PRIMARY KEY,
    timestamp          TEXT NOT NULL,
    kind               TEXT NOT NULL,
    category           TEXT NOT NULL,
    root_cause_detail  TEXT NOT NULL DEFAULT '',
    proposed_fix       TEXT NOT NULL DEFAULT '',
    finding_id         TEXT,
    vuln_class         TEXT,
    campaign_id        TEXT,
    thread_id          TEXT,
    detector_name      TEXT NOT NULL DEFAULT '',
    evidence_refs      TEXT NOT NULL DEFAULT '[]',
    metadata           TEXT NOT NULL DEFAULT '{}'
);
"""

_POSTMORTEM_INDEX_THREAD = (
    "CREATE INDEX IF NOT EXISTS idx_postmortem_thread "
    "ON postmortem(thread_id);"
)
_POSTMORTEM_INDEX_CATEGORY = (
    "CREATE INDEX IF NOT EXISTS idx_postmortem_category "
    "ON postmortem(category);"
)

_POSTMORTEM_INSERT = """
INSERT INTO postmortem (
    id, timestamp, kind, category, root_cause_detail, proposed_fix,
    finding_id, vuln_class, campaign_id, thread_id, detector_name,
    evidence_refs, metadata
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

_POSTMORTEM_SELECT_ALL = """
SELECT id, timestamp, kind, category, root_cause_detail, proposed_fix,
       finding_id, vuln_class, campaign_id, thread_id, detector_name,
       evidence_refs, metadata
FROM postmortem
ORDER BY timestamp ASC;
"""

_POSTMORTEM_SELECT_BY_THREAD = _POSTMORTEM_SELECT_ALL.replace(
    "ORDER BY", "WHERE thread_id = ?\nORDER BY"
)
_POSTMORTEM_SELECT_BY_KIND = _POSTMORTEM_SELECT_ALL.replace(
    "ORDER BY", "WHERE kind = ?\nORDER BY"
)
_POSTMORTEM_SELECT_BY_CATEGORY = _POSTMORTEM_SELECT_ALL.replace(
    "ORDER BY", "WHERE category = ?\nORDER BY"
)
_POSTMORTEM_SELECT_BY_FINDING = _POSTMORTEM_SELECT_ALL.replace(
    "ORDER BY", "WHERE finding_id = ?\nORDER BY"
)


def _resolve_db_path(database_url: str | None) -> Path:
    """Resolve a database URL or path to a :class:`Path`.

    Mirrors ``decision_log.py``'s ``_resolve_db_path``: anchor relative
    paths to the project root (the directory containing ``pyproject.toml``)
    so different worker CWDs don't write to different files.
    """
    if database_url is None:
        p = Path(_DEFAULT_POSTMORTEM_DB_PATH)
        if not p.is_absolute():
            root = Path(__file__).resolve()
            for parent in root.parents:
                if (parent / "pyproject.toml").exists():
                    return parent / p
        return p

    if database_url == "sqlite://":
        return Path(":memory:")

    prefix = "sqlite:///"
    if database_url.startswith(prefix):
        return Path(database_url[len(prefix):])

    return Path(database_url)


class PostmortemManager:
    """Thread-safe SQLite manager for Postmortem records.

    Follows the exact same pattern as :class:`DecisionLogManager`:
    per-operation connections for file-backed databases, a single
    shared connection for in-memory databases, writes serialised by a
    :class:`threading.Lock`.

    Postmortem records are **append-only** — there is no UPDATE or
    DELETE method on this manager.
    """

    def __init__(self, database_url: str | None = None) -> None:
        self._database_url = database_url
        self._write_lock = threading.Lock()
        self._initialised = False
        self._memory_conn: sqlite3.Connection | None = None

    # -- Connection management ----------------------------------------------
    def _db_path(self) -> Path:
        url = self._database_url or _DEFAULT_POSTMORTEM_DB_PATH
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
                # Intentionally do NOT close — connection is reused.
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
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
        except sqlite3.OperationalError:
            pass
        try:
            yield conn
        finally:
            conn.close()

    # -- Schema -------------------------------------------------------------
    def init_db(self) -> None:
        """Create the ``postmortem`` table (and indices) if absent.

        Safe to call multiple times.
        """
        if self._initialised:
            return
        with self._write_lock:
            if self._initialised:
                return
            with self._connect() as conn:
                conn.execute(_POSTMORTEM_DDL)
                conn.execute(_POSTMORTEM_INDEX_THREAD)
                conn.execute(_POSTMORTEM_INDEX_CATEGORY)
                conn.commit()
            self._initialised = True

    # -- Append-only writes ---------------------------------------------------
    def record(self, entry: PostmortemRecord) -> UUID:
        """Append a single Postmortem record.

        Args:
            entry: A populated :class:`PostmortemRecord` instance.

        Returns:
            The entry's UUID.
        """
        self.init_db()
        kind_value = (
            entry.kind.value if hasattr(entry.kind, "value") else str(entry.kind)
        )
        category_value = (
            entry.category.value
            if hasattr(entry.category, "value")
            else str(entry.category)
        )
        with self._write_lock, self._connect() as conn:
            conn.execute(
                _POSTMORTEM_INSERT,
                (
                    str(entry.id),
                    entry.timestamp.isoformat()
                    if hasattr(entry.timestamp, "isoformat")
                    else str(entry.timestamp),
                    kind_value,
                    category_value,
                    entry.root_cause_detail or "",
                    entry.proposed_fix or "",
                    str(entry.finding_id) if entry.finding_id else None,
                    entry.vuln_class,
                    entry.campaign_id,
                    entry.thread_id,
                    entry.detector_name or "",
                    json.dumps(list(entry.evidence_refs or [])),
                    json.dumps(entry.metadata or {}),
                ),
            )
            conn.commit()
        return entry.id

    def record_false_positive(
        self,
        *,
        category: PostmortemCategory | str,
        root_cause_detail: str,
        proposed_fix: str = "",
        finding_id: UUID | str | None = None,
        vuln_class: str | None = None,
        campaign_id: str | None = None,
        thread_id: str | None = None,
        detector_name: str = "",
        evidence_refs: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> UUID:
        """Convenience helper: record a false-positive postmortem from
        raw fields, without constructing :class:`PostmortemRecord` by
        hand.
        """
        entry = PostmortemRecord(
            kind=PostmortemKind.FALSE_POSITIVE,
            category=category,
            root_cause_detail=root_cause_detail,
            proposed_fix=proposed_fix,
            finding_id=UUID(str(finding_id)) if finding_id else None,
            vuln_class=vuln_class,
            campaign_id=campaign_id,
            thread_id=thread_id,
            detector_name=detector_name,
            evidence_refs=list(evidence_refs or []),
            metadata=dict(metadata or {}),
        )
        return self.record(entry)

    def record_missed_finding(
        self,
        *,
        category: PostmortemCategory | str,
        root_cause_detail: str,
        proposed_fix: str = "",
        vuln_class: str | None = None,
        campaign_id: str | None = None,
        thread_id: str | None = None,
        detector_name: str = "",
        evidence_refs: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> UUID:
        """Convenience helper: record a missed-finding postmortem.

        Missed findings by definition never became a :class:`Finding`,
        so there is no ``finding_id`` parameter here.
        """
        entry = PostmortemRecord(
            kind=PostmortemKind.MISSED_FINDING,
            category=category,
            root_cause_detail=root_cause_detail,
            proposed_fix=proposed_fix,
            finding_id=None,
            vuln_class=vuln_class,
            campaign_id=campaign_id,
            thread_id=thread_id,
            detector_name=detector_name,
            evidence_refs=list(evidence_refs or []),
            metadata=dict(metadata or {}),
        )
        return self.record(entry)

    def record_missed_findings(
        self,
        missed_items: list[dict[str, Any]] | list[str],
        *,
        category: PostmortemCategory | str = PostmortemCategory.COVERAGE_GAP,
        thread_id: str | None = None,
        campaign_id: str | None = None,
    ) -> list[UUID]:
        """Batch-record missed findings from a benchmark's ``missed_items``.

        Accepts either a list of plain vuln-class strings or a list of
        dicts with at least a ``vuln_class`` key (and optionally
        ``root_cause_detail``, ``proposed_fix``, ``category``,
        ``detector_name``, ``evidence_refs``). This is the natural
        entry point for a ``BenchmarkReport``-driven caller: each
        missed ground-truth item becomes one append-only record.

        Returns:
            The list of UUIDs created, in input order.
        """
        ids: list[UUID] = []
        for item in missed_items:
            if isinstance(item, str):
                ids.append(
                    self.record_missed_finding(
                        category=category,
                        root_cause_detail=(
                            f"Ground-truth vulnerability class '{item}' was "
                            "not surfaced as a finding."
                        ),
                        vuln_class=item,
                        campaign_id=campaign_id,
                        thread_id=thread_id,
                    )
                )
                continue
            if not isinstance(item, dict):
                continue
            ids.append(
                self.record_missed_finding(
                    category=item.get("category", category),
                    root_cause_detail=item.get(
                        "root_cause_detail",
                        (
                            "Ground-truth vulnerability class "
                            f"'{item.get('vuln_class', 'unknown')}' was not "
                            "surfaced as a finding."
                        ),
                    ),
                    proposed_fix=item.get("proposed_fix", ""),
                    vuln_class=item.get("vuln_class"),
                    campaign_id=item.get("campaign_id", campaign_id),
                    thread_id=item.get("thread_id", thread_id),
                    detector_name=item.get("detector_name", ""),
                    evidence_refs=item.get("evidence_refs"),
                    metadata=item.get("metadata"),
                )
            )
        return ids

    # -- Reads ----------------------------------------------------------------
    def get_all_records(self) -> list[dict]:
        """Return every Postmortem record, ordered by timestamp."""
        self.init_db()
        with self._connect() as conn:
            rows = conn.execute(_POSTMORTEM_SELECT_ALL).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_records_by_thread(self, thread_id: str) -> list[dict]:
        self.init_db()
        with self._connect() as conn:
            rows = conn.execute(
                _POSTMORTEM_SELECT_BY_THREAD, (thread_id,)
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_records_by_kind(self, kind: PostmortemKind | str) -> list[dict]:
        self.init_db()
        kind_value = kind.value if hasattr(kind, "value") else str(kind)
        with self._connect() as conn:
            rows = conn.execute(
                _POSTMORTEM_SELECT_BY_KIND, (kind_value,)
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_records_by_category(
        self, category: PostmortemCategory | str
    ) -> list[dict]:
        self.init_db()
        category_value = (
            category.value if hasattr(category, "value") else str(category)
        )
        with self._connect() as conn:
            rows = conn.execute(
                _POSTMORTEM_SELECT_BY_CATEGORY, (category_value,)
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_records_by_finding(self, finding_id: UUID | str) -> list[dict]:
        self.init_db()
        with self._connect() as conn:
            rows = conn.execute(
                _POSTMORTEM_SELECT_BY_FINDING, (str(finding_id),)
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_category_summary(
        self, *, thread_id: str | None = None
    ) -> dict[str, dict[str, int]]:
        """Aggregate record counts by ``kind`` then ``category``.

        Returns a dict shaped like::

            {
                "false_positive": {"tool_miscalibration": 3, "context_misread": 1},
                "missed_finding": {"coverage_gap": 2},
            }

        This is the whole point of forcing records into a closed
        vocabulary: a caller (dashboard, report appendix, or the
        red-vs-blue loop in item 5) can answer "what do we get wrong
        most often?" with a single aggregation query instead of an
        LLM re-reading free text every time.
        """
        records = (
            self.get_records_by_thread(thread_id)
            if thread_id
            else self.get_all_records()
        )
        summary: dict[str, Counter[str]] = {
            PostmortemKind.FALSE_POSITIVE.value: Counter(),
            PostmortemKind.MISSED_FINDING.value: Counter(),
        }
        for record in records:
            kind = record.get("kind", "")
            category = record.get("category", "")
            if kind not in summary:
                summary[kind] = Counter()
            summary[kind][category] += 1
        return {kind: dict(counter) for kind, counter in summary.items()}

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        raw_refs = d.get("evidence_refs") or "[]"
        try:
            d["evidence_refs"] = json.loads(raw_refs)
        except (ValueError, TypeError):
            d["evidence_refs"] = []
        raw_meta = d.get("metadata") or "{}"
        try:
            d["metadata"] = json.loads(raw_meta)
        except (ValueError, TypeError):
            d["metadata"] = {}
        return d


# ---------------------------------------------------------------------------
# Process-wide singleton — mirrors the DecisionLogManager pattern.
# ---------------------------------------------------------------------------
_singleton: PostmortemManager | None = None
_scoped_singletons: dict[str, PostmortemManager] = {}
_singleton_lock = threading.Lock()


def _active_workspace_database_url() -> str | None:
    """Return a workspace-local postmortem URL when a scan is active.

    Defensive: the target-workspace module is optional context and may
    not exist/behave identically across webpent versions, so any
    failure here silently falls back to the process-wide singleton
    rather than raising during postmortem recording (a postmortem
    write must never itself become a source of engagement failure).
    """
    try:
        from webpent.shared.target_workspace_context import (
            get_active_target_workspace,
        )
    except ImportError:
        return None
    try:
        workspace = get_active_target_workspace()
    except Exception:  # noqa: BLE001 — never let context lookup break recording
        return None
    if workspace is None:
        return None
    db_path = getattr(workspace, "decision_log_database_path", None)
    if db_path is None:
        return None
    # Co-locate postmortem.db alongside decision_log.db in the same
    # workspace directory.
    postmortem_path = Path(db_path).parent / "postmortem.db"
    return f"sqlite:///{postmortem_path.as_posix()}"


def get_postmortem_manager(database_url: str | None = None) -> PostmortemManager:
    """Return a manager scoped to an explicit or active target database."""
    global _singleton
    resolved_url = database_url or _active_workspace_database_url()
    if resolved_url is None:
        if _singleton is None:
            with _singleton_lock:
                if _singleton is None:
                    _singleton = PostmortemManager()
        return _singleton
    key = str(resolved_url)
    with _singleton_lock:
        manager = _scoped_singletons.get(key)
        if manager is None:
            manager = PostmortemManager(database_url=key)
            _scoped_singletons[key] = manager
        return manager


__all__ = [
    "PostmortemManager",
    "get_postmortem_manager",
]
