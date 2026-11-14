# src/webpent/resume/campaign_checkpoints.py
"""Campaign resume machinery (2026-10-25 Proposal 8).

Three pieces, all deterministic and fail-closed:

  * ``CampaignCheckpointStore`` — interrupt markers keyed by engagement
    (thread) id. A marker records WHY the campaign was interrupted
    (soft time limit, worker crash) together with the last-known node
    and a state fingerprint. The LangGraph checkpointer remains the
    authority for the state blob itself; the marker is what tells a
    redelivered task to CONTINUE instead of merely report. Corrupt or
    stale markers are ignored and cleared: a damaged checkpoint means
    a clean start, never a garbage resume.
  * ``ProbeLedger`` — a bounded ledger of executed probe ids so a
    resume skips already-executed probes. A probe id is derived
    deterministically from (target, kind, path) via
    ``derive_probe_id``. Reads fail in the SAFE direction: on any
    ledger error ``was_executed`` returns False, so the worst case is
    a duplicate probe (safe: observations are idempotent), never a
    silently skipped probe.
  * Bounded requeue backoff: ``backoff_seconds`` grows exponentially
    (30s → 60s → 120s) capped at ``BACKOFF_CAP_S``, with at most
    ``MAX_CAMPAIGN_RETRIES`` automatic requeues. HITL pauses are never
    auto-resumed — they never write a marker.

All state lives in SQLite under the memory directory (same convention
as the session store); when SQLite is unavailable the store degrades
to an in-process memory backend so callers keep working.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from typing import Any, Iterable

__all__ = [
    "MAX_CAMPAIGN_RETRIES",
    "BACKOFF_BASE_S",
    "BACKOFF_CAP_S",
    "MARKER_TTL_S",
    "MAX_PROBE_ROWS",
    "derive_probe_id",
    "backoff_seconds",
    "state_fingerprint",
    "CampaignCheckpointStore",
    "ProbeLedger",
    "get_marker_store",
    "get_probe_ledger",
    "mark_interrupted",
    "clear_interrupt",
    "should_auto_resume",
    "resume_snapshot",
    "mark_probe_executed",
    "probe_was_executed",
    "filter_pending_probes",
]

# Bound the automatic resume loop: at most 3 requeues with exponential
# backoff (30s, 60s, 120s — capped). A campaign that cannot survive 3
# resumes needs a human, and pretending otherwise would loop forever.
MAX_CAMPAIGN_RETRIES = 3
BACKOFF_BASE_S = 30.0
BACKOFF_CAP_S = 600.0

# Stale markers (campaign interrupted more than a week ago with no
# resume attempt since) are ignored: resuming a week-old engagement
# state is more likely harmful than helpful.
MARKER_TTL_S = 7 * 24 * 3600.0

# Probe ledger bounds: 50k rows per engagement, pruned oldest-first.
MAX_PROBE_ROWS = 50_000

DEFAULT_DB_PATH = os.path.join("./memory/global", "campaign_resume.db")

_INTERRUPT_REASONS = frozenset({"soft_time_limit", "worker_crash"})


def derive_probe_id(target: str, kind: str, path: str) -> str:
    """Deterministic probe id: sha256 over (target, kind, path).

    Deliberately content-based and side-effect free so the SAME probe
    derived on a fresh worker process maps to the SAME ledger entry.
    """
    payload = "\x1f".join((str(target or ""), str(kind or ""), str(path or "")))
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


def backoff_seconds(retries: int, *, base: float = BACKOFF_BASE_S, cap: float = BACKOFF_CAP_S) -> float:
    """Exponential backoff, bounded: min(cap, base * 2**retries)."""
    if retries < 0:
        retries = 0
    return min(cap, base * (2 ** retries))


def state_fingerprint(state_values: Any) -> str:
    """Cheap, deterministic fingerprint of a graph state for audit.

    NOT a security hash: it records which findings and which phase the
    interrupted state carried, bounded to the first 100 finding ids, so
    an operator can see what a resume was built on. Never raises.
    """
    try:
        findings = (state_values or {}).get("findings") or []
        ids = []
        for finding in list(findings)[:100]:
            if isinstance(finding, dict):
                ids.append(str(finding.get("id") or finding.get("title") or ""))
            else:
                ids.append(str(getattr(finding, "id", "") or ""))
        crawl = (state_values or {}).get("crawled_data") or {}
        payload = json.dumps(
            {
                "current_phase": (state_values or {}).get("current_phase"),
                "finding_ids": ids,
                "crawled_keys": sorted(str(k) for k in crawl.keys())[:100],
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()
    except Exception:  # noqa: BLE001 — fingerprint is audit-only
        return "unavailable"


class CampaignCheckpointStore:
    """Interrupt markers keyed by engagement id, SQLite-backed."""

    def __init__(self, *, db_path: str | None = DEFAULT_DB_PATH) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._memory: dict[str, dict[str, Any]] = {}
        self._order: list[str] = []
        self._conn: sqlite3.Connection | None = None
        if db_path is not None:
            try:
                os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
                self._conn = sqlite3.connect(db_path, check_same_thread=False)
                self._conn.execute(
                    "CREATE TABLE IF NOT EXISTS campaign_checkpoints ("
                    "engagement_id TEXT PRIMARY KEY, reason TEXT NOT NULL, "
                    "node TEXT, state_hash TEXT, interrupted_at REAL NOT NULL, "
                    "resume_count INTEGER NOT NULL DEFAULT 0)"
                )
                self._conn.commit()
            except Exception:  # noqa: BLE001 — degrade to memory store
                self._conn = None

    def _prune_memory(self) -> None:
        while len(self._order) > 256:
            stale = self._order.pop(0)
            self._memory.pop(stale, None)

    def _prune_stale_sql(self) -> None:
        """DELETE stale markers from SQLite (MARKER_TTL_S expired).

        The v3.0 defect: ``get()`` and ``resumable()`` ignored stale
        rows but nothing ever deleted them, so the table kept every
        marker forever. Pruned opportunistically on write.
        """
        try:
            self._conn.execute(
                "DELETE FROM campaign_checkpoints WHERE interrupted_at < ?",
                (time.time() - MARKER_TTL_S,),
            )
        except Exception:  # noqa: BLE001 — pruning failure is non-fatal
            pass

    def mark(self, engagement_id: str, *, reason: str, node: str | None, state_hash: str) -> bool:
        """Record (or refresh) an interrupt marker. Never raises."""
        if not engagement_id:
            return False
        row = {
            "reason": str(reason or "unknown"),
            "node": node,
            "state_hash": state_hash,
            "interrupted_at": time.time(),
            "resume_count": 0,
        }
        with self._lock:
            if self._conn is None:
                if engagement_id in self._memory:
                    row["resume_count"] = self._memory[engagement_id].get("resume_count", 0)
                else:
                    self._order.append(engagement_id)
                self._memory[engagement_id] = row
                self._prune_memory()
                return True
            try:
                self._prune_stale_sql()
                self._conn.execute(
                    "INSERT INTO campaign_checkpoints (engagement_id, reason, node, "
                    "state_hash, interrupted_at, resume_count) VALUES (?, ?, ?, ?, ?, "
                    "COALESCE((SELECT resume_count FROM campaign_checkpoints "
                    "WHERE engagement_id = ?), 0))",
                    (engagement_id, row["reason"], row["node"], row["state_hash"],
                     row["interrupted_at"], engagement_id),
                )
                self._conn.commit()
                return True
            except Exception:  # noqa: BLE001 — marker failure must not kill the task
                return False

    def get(self, engagement_id: str) -> dict[str, Any] | None:
        """Return a FRESH marker for the engagement, or None.

        Corrupt rows (undecodable) are treated as absent and cleared:
        a damaged checkpoint means a clean start, never a resume.
        """
        if not engagement_id:
            return None
        with self._lock:
            if self._conn is None:
                row = self._memory.get(engagement_id)
                if row is None:
                    return None
                if (time.time() - row["interrupted_at"]) > MARKER_TTL_S:
                    return None
                return dict(row)
            try:
                cur = self._conn.execute(
                    "SELECT reason, node, state_hash, interrupted_at, resume_count "
                    "FROM campaign_checkpoints WHERE engagement_id = ?",
                    (engagement_id,),
                )
                fetched = cur.fetchone()
            except Exception:  # noqa: BLE001 — unreadable store = no resume
                return None
        if fetched is None:
            return None
        try:
            reason, node, state_hash, interrupted_at, resume_count = fetched
            if (time.time() - float(interrupted_at)) > MARKER_TTL_S:
                return None
            return {
                "reason": str(reason),
                "node": node,
                "state_hash": str(state_hash),
                "interrupted_at": float(interrupted_at),
                "resume_count": int(resume_count),
            }
        except Exception:  # noqa: BLE001 — corrupt row = clean start
            self.clear(engagement_id)
            return None

    def clear(self, engagement_id: str) -> None:
        with self._lock:
            if self._conn is None:
                self._memory.pop(engagement_id, None)
                if engagement_id in self._order:
                    self._order.remove(engagement_id)
                return
            try:
                self._conn.execute(
                    "DELETE FROM campaign_checkpoints WHERE engagement_id = ?",
                    (engagement_id,),
                )
                self._conn.commit()
            except Exception:  # noqa: BLE001 — clear failure is non-fatal
                pass

    def increment_resume(self, engagement_id: str) -> None:
        with self._lock:
            if self._conn is None:
                row = self._memory.get(engagement_id)
                if row is not None:
                    row["resume_count"] = int(row.get("resume_count", 0)) + 1
                return
            try:
                self._conn.execute(
                    "UPDATE campaign_checkpoints SET resume_count = resume_count + 1 "
                    "WHERE engagement_id = ?",
                    (engagement_id,),
                )
                self._conn.commit()
            except Exception:  # noqa: BLE001 — non-fatal
                pass

    def resumable(self) -> list[dict[str, Any]]:
        """Read-only snapshot of fresh, resumable markers (status view)."""
        now = time.time()
        with self._lock:
            if self._conn is None:
                rows = [dict(self._memory[k]) | {"engagement_id": k}
                        for k in self._order if k in self._memory]
            else:
                try:
                    cur = self._conn.execute(
                        "SELECT engagement_id, reason, node, state_hash, interrupted_at, "
                        "resume_count FROM campaign_checkpoints ORDER BY interrupted_at DESC LIMIT 64"
                    )
                    rows = [
                        {
                            "engagement_id": r[0], "reason": r[1], "node": r[2],
                            "state_hash": r[3], "interrupted_at": r[4], "resume_count": r[5],
                        }
                        for r in cur.fetchall()
                    ]
                except Exception:  # noqa: BLE001
                    rows = []
        out = []
        for row in rows:
            if (now - float(row.get("interrupted_at") or 0)) > MARKER_TTL_S:
                continue
            if row.get("reason") in _INTERRUPT_REASONS:
                out.append(row)
        return out[:64]


_STORE_LOCK = threading.Lock()
_STORE: CampaignCheckpointStore | None = None


def get_marker_store() -> CampaignCheckpointStore:
    global _STORE
    with _STORE_LOCK:
        if _STORE is None:
            _STORE = CampaignCheckpointStore()
        return _STORE


def mark_interrupted(
    engagement_id: str,
    *,
    reason: str,
    node: str | None = None,
    state_hash: str = "",
) -> bool:
    return get_marker_store().mark(engagement_id, reason=reason, node=node, state_hash=state_hash)


def clear_interrupt(engagement_id: str) -> None:
    get_marker_store().clear(engagement_id)


def should_auto_resume(engagement_id: str, retries: int) -> bool:
    """Decide whether a redelivered task should CONTINUE the graph.

    Fail-closed: True only when a FRESH crash/timeout marker exists for
    the engagement AND the retry budget remains. HITL pauses never
    write markers, so they are never auto-resumed. Any doubt = False.
    """
    if retries >= MAX_CAMPAIGN_RETRIES:
        return False
    marker = get_marker_store().get(engagement_id)
    if marker is None:
        return False
    if marker.get("reason") not in _INTERRUPT_REASONS:
        return False
    get_marker_store().increment_resume(engagement_id)
    return True


def resume_snapshot() -> list[dict[str, Any]]:
    """Status view for the worker dashboard: what is resumable right now."""
    return get_marker_store().resumable()


class ProbeLedger:
    """Bounded ledger of executed probe ids, per engagement.

    Bounded for real: ``MAX_PROBE_ROWS`` caps rows per engagement and is
    ENFORCED on every write (the v3.0 defect — the constant existed but
    nothing read it, so a long campaign's ledger grew without bound in
    both the SQLite table and the memory fallback). Eviction is
    oldest-executed-first: a probe id evicted from the ledger means a
    possible duplicate probe on resume, which is the SAFE direction
    (observations are idempotent); never the reverse.
    """

    def __init__(self, *, db_path: str | None = DEFAULT_DB_PATH) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        # engagement_id -> {probe_id: executed_at} (insertion order kept
        # as a secondary bound for memory eviction).
        self._memory: dict[str, dict[str, float]] = {}
        self._conn: sqlite3.Connection | None = None
        if db_path is not None:
            try:
                os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
                # Separate table in the same resume DB.
                self._conn = sqlite3.connect(db_path, check_same_thread=False)
                self._conn.execute(
                    "CREATE TABLE IF NOT EXISTS probe_ledger ("
                    "engagement_id TEXT NOT NULL, probe_id TEXT NOT NULL, "
                    "executed_at REAL NOT NULL, "
                    "PRIMARY KEY (engagement_id, probe_id))"
                )
                self._conn.commit()
            except Exception:  # noqa: BLE001 — degrade to memory ledger
                self._conn = None

    def _prune_memory(self, engagement_id: str) -> None:
        rows = self._memory.get(engagement_id)
        if not rows or len(rows) <= MAX_PROBE_ROWS:
            return
        keep = sorted(rows.items(), key=lambda kv: kv[1])[-MAX_PROBE_ROWS:]
        self._memory[engagement_id] = dict(keep)

    def _prune_sql(self, engagement_id: str) -> None:
        # Oldest-executed-first eviction beyond the per-engagement bound.
        self._conn.execute(
            "DELETE FROM probe_ledger WHERE engagement_id = ? AND probe_id NOT IN ("
            "SELECT probe_id FROM probe_ledger WHERE engagement_id = ? "
            "ORDER BY executed_at DESC, probe_id DESC LIMIT ?)",
            (engagement_id, engagement_id, MAX_PROBE_ROWS),
        )

    def mark(self, engagement_id: str, probe_id: str) -> bool:
        if not engagement_id or not probe_id:
            return False
        with self._lock:
            if self._conn is None:
                self._memory.setdefault(engagement_id, {})[probe_id] = time.time()
                self._prune_memory(engagement_id)
                return True
            try:
                self._conn.execute(
                    "INSERT OR IGNORE INTO probe_ledger (engagement_id, probe_id, executed_at) "
                    "VALUES (?, ?, ?)",
                    (engagement_id, probe_id, time.time()),
                )
                self._prune_sql(engagement_id)
                self._conn.commit()
                return True
            except Exception:  # noqa: BLE001
                return False

    def was_executed(self, engagement_id: str, probe_id: str) -> bool:
        """SAFE-DIRECTION read: ledger error -> False (duplicate, not skip).

        Never raises: any error on any path (SQL, memory store, lock)
        resolves to False, because a duplicate probe is safe while a
        skipped probe is not.
        """
        if not engagement_id or not probe_id:
            return False
        try:
            with self._lock:
                if self._conn is None:
                    memory: Any = self._memory
                    if memory is None:
                        return False
                    return probe_id in memory.get(engagement_id, set())
                cur = self._conn.execute(
                    "SELECT 1 FROM probe_ledger WHERE engagement_id = ? AND probe_id = ?",
                    (engagement_id, probe_id),
                )
                return cur.fetchone() is not None
        except Exception:  # noqa: BLE001 — duplicate is safe, a skip is not
            return False

    def pending(self, engagement_id: str, probe_ids: Iterable[str]) -> list[str]:
        ids = list(dict.fromkeys(str(p) for p in probe_ids))
        return [p for p in ids if not self.was_executed(engagement_id, p)]

    def row_count(self, engagement_id: str) -> int:
        with self._lock:
            if self._conn is None:
                return len(self._memory.get(engagement_id, set()))
            try:
                cur = self._conn.execute(
                    "SELECT COUNT(*) FROM probe_ledger WHERE engagement_id = ?",
                    (engagement_id,),
                )
                return int(cur.fetchone()[0])
            except Exception:  # noqa: BLE001
                return 0


_LEDGER_LOCK = threading.Lock()
_LEDGER: ProbeLedger | None = None


def get_probe_ledger() -> ProbeLedger:
    global _LEDGER
    with _LEDGER_LOCK:
        if _LEDGER is None:
            _LEDGER = ProbeLedger()
        return _LEDGER


def mark_probe_executed(engagement_id: str, target: str, kind: str, path: str) -> bool:
    return get_probe_ledger().mark(engagement_id, derive_probe_id(target, kind, path))


def probe_was_executed(engagement_id: str, target: str, kind: str, path: str) -> bool:
    return get_probe_ledger().was_executed(engagement_id, derive_probe_id(target, kind, path))


def filter_pending_probes(
    engagement_id: str,
    probes: Iterable[tuple[str, str, str]],
    *,
    ledger: ProbeLedger | None = None,
) -> list[tuple[str, str, str]]:
    """Return the subset of (target, kind, path) probes not yet executed."""
    ledger = ledger if ledger is not None else get_probe_ledger()
    probes = list(probes)
    ids = [derive_probe_id(t, k, p) for t, k, p in probes]
    pending_ids = set(ledger.pending(engagement_id, ids))
    return [item for pid, item in zip(ids, probes) if pid in pending_ids]
