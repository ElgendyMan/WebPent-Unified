# src/webpent/memory/taint_tracker.py
"""webpent.memory.taint_tracker

Project Zero-tier item 1 — Taint tracking across sessions.

Thread-safe SQLite manager for :class:`TaintFlowPoint` records,
following the same pattern as :class:`PostmortemManager` /
:class:`DecisionLogManager`: per-write connections for file-backed
databases, a single shared connection for in-memory databases, writes
serialised by a :class:`threading.Lock`.

The headline capability: :meth:`TaintTracker.find_cross_session_flows`
answers "has a value introduced at some SOURCE later reappeared at a
SINK in a DIFFERENT session?" — the second-order SQLi / stored-XSS
detection this item exists for. A same-session reappearance is
ordinary (expected) request/response round-tripping and is reported
separately, at lower significance, from a genuinely cross-session
flow.

Values are tracked EXCLUSIVELY by salted fingerprint
(:func:`fingerprint_taint_value`) — this manager never stores, logs,
or returns a raw tainted value. The salt is process-local and
reproducible only by the caller supplying the same salt, so two
different engagements' fingerprint tables are never comparable to
each other even if (improbably) the same literal payload were reused
across them — a deliberate choice that keeps a shared/long-lived
taint database safe to persist across engagements without leaking
cross-client details.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from webpent.models.taint import TaintFlowPoint, TaintPointKind, TaintSinkContext

logger = logging.getLogger(__name__)

_DEFAULT_TAINT_DB_PATH = "./memory/global/taint.db"

# Default process-local salt. A caller tracking something especially
# sensitive can supply its own salt per engagement for stronger
# isolation; this default is adequate for the common case (defense in
# depth against casual fingerprint-table inspection, not a
# cryptographic secrecy boundary — the fingerprinted values are
# attacker-supplied test payloads, not target secrets).
_DEFAULT_SALT = "webpent-taint-v1"


def fingerprint_taint_value(value: str, *, salt: str = _DEFAULT_SALT) -> str:
    """Salted SHA-256 fingerprint of a tainted value.

    Never reversible to the original value by this module, and
    deliberately never exposed as "the value" anywhere in
    :class:`TaintFlowPoint` or :class:`TaintTracker` — only the digest
    travels.
    """
    return hashlib.sha256(f"{salt}:{value}".encode("utf-8", "ignore")).hexdigest()


_TAINT_DDL = """
CREATE TABLE IF NOT EXISTS taint_flow_point (
    id                 TEXT PRIMARY KEY,
    timestamp          TEXT NOT NULL,
    kind               TEXT NOT NULL,
    value_fingerprint  TEXT NOT NULL,
    endpoint_label     TEXT NOT NULL DEFAULT '',
    parameter_name     TEXT,
    session_id         TEXT,
    sink_context       TEXT,
    thread_id          TEXT,
    evidence_refs      TEXT NOT NULL DEFAULT '[]'
);
"""

_TAINT_INDEX_FINGERPRINT = (
    "CREATE INDEX IF NOT EXISTS idx_taint_fingerprint "
    "ON taint_flow_point(value_fingerprint);"
)
_TAINT_INDEX_THREAD = (
    "CREATE INDEX IF NOT EXISTS idx_taint_thread ON taint_flow_point(thread_id);"
)

_TAINT_INSERT = """
INSERT INTO taint_flow_point (
    id, timestamp, kind, value_fingerprint, endpoint_label,
    parameter_name, session_id, sink_context, thread_id, evidence_refs
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

_TAINT_SELECT_BY_FINGERPRINT = """
SELECT id, timestamp, kind, value_fingerprint, endpoint_label,
       parameter_name, session_id, sink_context, thread_id, evidence_refs
FROM taint_flow_point
WHERE value_fingerprint = ?
ORDER BY timestamp ASC;
"""

_TAINT_SELECT_BY_THREAD = """
SELECT id, timestamp, kind, value_fingerprint, endpoint_label,
       parameter_name, session_id, sink_context, thread_id, evidence_refs
FROM taint_flow_point
WHERE thread_id = ?
ORDER BY timestamp ASC;
"""


def _resolve_db_path(database_url: str | None) -> Path:
    if database_url is None:
        p = Path(_DEFAULT_TAINT_DB_PATH)
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


class CrossSessionTaintFlow:
    """A detected taint flow where a SOURCE in one session reappeared
    as a SINK in a DIFFERENT session — the second-order
    SQLi/stored-XSS signal this item exists to surface.
    """

    __slots__ = ("source", "sink")

    def __init__(self, source: dict, sink: dict) -> None:
        self.source = source
        self.sink = sink

    def as_dict(self) -> dict[str, Any]:
        return {
            "value_fingerprint": self.source["value_fingerprint"],
            "source": {
                "endpoint_label": self.source["endpoint_label"],
                "parameter_name": self.source["parameter_name"],
                "session_id": self.source["session_id"],
                "timestamp": self.source["timestamp"],
            },
            "sink": {
                "endpoint_label": self.sink["endpoint_label"],
                "sink_context": self.sink["sink_context"],
                "session_id": self.sink["session_id"],
                "timestamp": self.sink["timestamp"],
            },
            "cross_session": True,
            "advisory_only": True,
            "does_not_confirm": True,
        }


class TaintTracker:
    """Thread-safe SQLite manager for cross-session taint flow tracking.

    Append-only, same posture as :class:`PostmortemManager`.
    """

    def __init__(self, database_url: str | None = None) -> None:
        self._database_url = database_url
        self._write_lock = threading.Lock()
        self._initialised = False
        self._memory_conn: sqlite3.Connection | None = None

    def _db_path(self) -> Path:
        return _resolve_db_path(self._database_url or _DEFAULT_TAINT_DB_PATH)

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
            str(path), isolation_level="", check_same_thread=False, timeout=30.0
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

    def init_db(self) -> None:
        if self._initialised:
            return
        with self._write_lock:
            if self._initialised:
                return
            with self._connect() as conn:
                conn.execute(_TAINT_DDL)
                conn.execute(_TAINT_INDEX_FINGERPRINT)
                conn.execute(_TAINT_INDEX_THREAD)
                conn.commit()
            self._initialised = True

    def record(self, point: TaintFlowPoint) -> None:
        """Append a single taint flow observation (SOURCE or SINK)."""
        self.init_db()
        kind_value = point.kind.value if hasattr(point.kind, "value") else str(point.kind)
        sink_context_value = (
            point.sink_context.value
            if hasattr(point.sink_context, "value")
            else (str(point.sink_context) if point.sink_context else None)
        )
        with self._write_lock, self._connect() as conn:
            conn.execute(
                _TAINT_INSERT,
                (
                    str(point.id),
                    point.timestamp.isoformat()
                    if hasattr(point.timestamp, "isoformat")
                    else str(point.timestamp),
                    kind_value,
                    point.value_fingerprint,
                    point.endpoint_label or "",
                    point.parameter_name,
                    point.session_id,
                    sink_context_value,
                    point.thread_id,
                    json.dumps(list(point.evidence_refs or [])),
                ),
            )
            conn.commit()

    def record_source(
        self,
        *,
        value: str,
        endpoint_label: str,
        parameter_name: str | None = None,
        session_id: str | None = None,
        thread_id: str | None = None,
        salt: str = _DEFAULT_SALT,
        evidence_refs: list[str] | None = None,
    ) -> str:
        """Convenience helper: record a SOURCE observation from a raw
        value. The raw value is fingerprinted immediately and never
        stored; this is the ONLY place in the tracker's public API
        that accepts a raw value as input.

        Returns:
            The value's fingerprint, so the caller can correlate later
            sink observations of the SAME value without re-supplying
            the raw value (useful when the value is re-derived from
            evidence rather than re-typed by the caller).
        """
        fingerprint = fingerprint_taint_value(value, salt=salt)
        self.record(
            TaintFlowPoint(
                kind=TaintPointKind.SOURCE,
                value_fingerprint=fingerprint,
                endpoint_label=endpoint_label,
                parameter_name=parameter_name,
                session_id=session_id,
                thread_id=thread_id,
                evidence_refs=list(evidence_refs or []),
            )
        )
        return fingerprint

    def record_sink(
        self,
        *,
        value: str,
        endpoint_label: str,
        sink_context: TaintSinkContext | str | None = None,
        session_id: str | None = None,
        thread_id: str | None = None,
        salt: str = _DEFAULT_SALT,
        evidence_refs: list[str] | None = None,
    ) -> str:
        """Convenience helper: record a SINK observation from a raw
        value (or a value derived from a tainted source — the caller
        is responsible for recognising the derivation; this module
        only tracks exact-fingerprint reappearance, see module
        docstring note on scope).

        Returns:
            The value's fingerprint.
        """
        fingerprint = fingerprint_taint_value(value, salt=salt)
        self.record(
            TaintFlowPoint(
                kind=TaintPointKind.SINK,
                value_fingerprint=fingerprint,
                endpoint_label=endpoint_label,
                sink_context=sink_context,
                session_id=session_id,
                thread_id=thread_id,
                evidence_refs=list(evidence_refs or []),
            )
        )
        return fingerprint

    def get_points_by_fingerprint(self, fingerprint: str) -> list[dict]:
        self.init_db()
        with self._connect() as conn:
            rows = conn.execute(
                _TAINT_SELECT_BY_FINGERPRINT, (fingerprint,)
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_points_by_thread(self, thread_id: str) -> list[dict]:
        self.init_db()
        with self._connect() as conn:
            rows = conn.execute(_TAINT_SELECT_BY_THREAD, (thread_id,)).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def find_cross_session_flows(
        self, *, thread_id: str | None = None
    ) -> list[CrossSessionTaintFlow]:
        """Find every (source, sink) pair sharing a value fingerprint
        where the sink's session differs from the source's session.

        This is the second-order SQLi / stored-XSS detection surface:
        a value introduced in session A (e.g. an attacker submits a
        comment containing a payload) that later reappears as a SINK
        in session B (e.g. an admin's session renders that comment)
        is exactly the "entry point and execution point split across
        sessions" pattern ordinary same-request/same-session taint
        tracking cannot see.

        A sink in the SAME session as its source is NOT returned here
        — that is ordinary request/response round-tripping (e.g. a
        form that echoes back what you just typed), not a
        cross-session flow, and reporting it here would drown the
        signal this method exists to surface. (A caller who also wants
        same-session reappearances can get them directly from
        :meth:`get_points_by_fingerprint`.)

        Returns:
            A list of :class:`CrossSessionTaintFlow`, one per
            (source, sink) pair found, in the order encountered.
            Advisory only — this never confirms exploitability (no
            payload is evaluated, no execution is observed); it
            surfaces a cross-session reappearance as a strong prior
            for a human/validator to investigate.
        """
        self.init_db()
        if thread_id is not None:
            points = self.get_points_by_thread(thread_id)
        else:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id, timestamp, kind, value_fingerprint, endpoint_label,
                           parameter_name, session_id, sink_context, thread_id,
                           evidence_refs
                    FROM taint_flow_point
                    ORDER BY timestamp ASC;
                    """
                ).fetchall()
            points = [self._row_to_dict(r) for r in rows]

        by_fingerprint: dict[str, list[dict]] = {}
        for point in points:
            by_fingerprint.setdefault(point["value_fingerprint"], []).append(point)

        flows: list[CrossSessionTaintFlow] = []
        for fingerprint_points in by_fingerprint.values():
            sources = [p for p in fingerprint_points if p["kind"] == "source"]
            sinks = [p for p in fingerprint_points if p["kind"] == "sink"]
            for source in sources:
                for sink in sinks:
                    if (
                        source["session_id"] is not None
                        and sink["session_id"] is not None
                        and source["session_id"] != sink["session_id"]
                    ):
                        flows.append(CrossSessionTaintFlow(source=source, sink=sink))
        return flows

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        raw_refs = d.get("evidence_refs") or "[]"
        try:
            d["evidence_refs"] = json.loads(raw_refs)
        except (ValueError, TypeError):
            d["evidence_refs"] = []
        return d


_singleton: TaintTracker | None = None
_singleton_lock = threading.Lock()


def get_taint_tracker(database_url: str | None = None) -> TaintTracker:
    """Process-wide singleton accessor, mirroring ``get_postmortem_manager``."""
    global _singleton
    if database_url is not None:
        return TaintTracker(database_url=database_url)
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = TaintTracker()
    return _singleton


__all__ = [
    "CrossSessionTaintFlow",
    "TaintTracker",
    "fingerprint_taint_value",
    "get_taint_tracker",
]
