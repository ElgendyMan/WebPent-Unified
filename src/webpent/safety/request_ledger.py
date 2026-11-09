# src/webpent/safety/request_ledger.py
"""Request ledger (2026-10-25 Proposal 10, control 1).

One layer every HTTP request from any agent passes through: a bounded
SQLite log of ``(ts, method, url, flags, engagement)`` rows, wired into
``make_safe_httpx_client`` as an httpx request hook.

Observability, not enforcement: a ledger failure NEVER blocks a
request. The hook and the record call are fail-soft (log + continue),
because an observability outage must not stop an engagement — that is
the opposite failure direction from the kill switch, which IS
enforcement.

Bounds: ``MAX_LEDGER_ROWS`` rows kept globally (oldest pruned on a
lazy sweep every ``PRUNE_EVERY`` writes), and rows older than
``REQUEST_TTL_S`` are pruned in the same sweep. ``stats()`` gives the
worker dashboard its view.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from typing import Any, Callable

from webpent.shared.target_workspace_context import get_active_target_workspace

__all__ = [
    "MAX_LEDGER_ROWS",
    "REQUEST_TTL_S",
    "PRUNE_EVERY",
    "RequestLedger",
    "get_ledger",
    "ledger_request_hook",
    "ledger_stats",
]

MAX_LEDGER_ROWS = 100_000
REQUEST_TTL_S = 7 * 24 * 3600.0
PRUNE_EVERY = 512

DEFAULT_DB_PATH = os.path.join("./memory/global", "request_ledger.db")

# Flag stamped on every row recorded through the safe-client hook: the
# client pins SSRF targets by construction, so its requests are all
# pinned.
_PINNED_FLAG = "ssrf_pinned"


class RequestLedger:
    """Bounded SQLite ledger of HTTP requests, fail-soft by contract."""

    def __init__(
        self,
        *,
        db_path: str | None = DEFAULT_DB_PATH,
        max_rows: int = MAX_LEDGER_ROWS,
        ttl_seconds: float = REQUEST_TTL_S,
        now: Callable[[], float] | None = None,
    ) -> None:
        self._db_path = db_path
        self._max_rows = max(1, int(max_rows))
        self._ttl = max(0.0, float(ttl_seconds))
        self._now = now or time.time
        self._lock = threading.Lock()
        self._writes = 0
        self._memory: list[dict[str, Any]] = []
        self._conn: sqlite3.Connection | None = None
        if db_path is not None:
            try:
                os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
                # WAL + a real busy timeout: the v3.0 defect connected
                # with journal defaults and timeout 0, so any concurrent
                # reader (dashboard stats() during a write burst) made
                # writes fail with SQLITE_BUSY — and this ledger is on
                # the request path of EVERY httpx client.
                self._conn = sqlite3.connect(
                    db_path, check_same_thread=False, timeout=5.0
                )
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=NORMAL")
                self._conn.execute(
                    "CREATE TABLE IF NOT EXISTS request_ledger ("
                    "ts REAL NOT NULL, method TEXT NOT NULL, url TEXT NOT NULL, "
                    "flags TEXT NOT NULL DEFAULT '', engagement_id TEXT NOT NULL DEFAULT '')"
                )
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_request_ledger_ts "
                    "ON request_ledger (ts)"
                )
                self._conn.commit()
            except Exception:  # noqa: BLE001 — degrade to memory ledger
                self._conn = None

    def record(self, method: str, url: str, *, engagement_id: str = "", flags: str = "") -> bool:
        """Append one row, bounded. Never raises; False on failure."""
        method = str(method or "").upper()[:16]
        url = str(url or "")[:2048]
        if not method or not url:
            return False
        row = (self._now(), method, url, str(flags or ""), str(engagement_id or ""))
        with self._lock:
            if self._conn is None:
                self._memory.append(row)
                if len(self._memory) > self._max_rows:
                    del self._memory[: len(self._memory) - self._max_rows]
                return True
            try:
                self._conn.execute(
                    "INSERT INTO request_ledger (ts, method, url, flags, engagement_id) "
                    "VALUES (?, ?, ?, ?, ?)",
                    row,
                )
                self._conn.commit()
                self._writes += 1
                # Amortized sweep, AFTER the row is durably committed and
                # in its own transaction: the v3.0 defect ran both DELETEs
                # inside the insert's transaction every 512th write, so
                # one request stalled behind a full-table rewrite. The
                # row-cap rewrite now runs only when the table actually
                # exceeds the cap (cheap indexed COUNT first); the TTL
                # delete is index-backed and stays on the schedule.
                if self._writes % PRUNE_EVERY == 0:
                    if self._ttl > 0:
                        self._conn.execute(
                            "DELETE FROM request_ledger WHERE ts < ?",
                            (self._now() - self._ttl,),
                        )
                    cur = self._conn.execute("SELECT COUNT(*) FROM request_ledger")
                    if int(cur.fetchone()[0]) > self._max_rows:
                        self._conn.execute(
                            "DELETE FROM request_ledger WHERE rowid NOT IN ("
                            "SELECT rowid FROM request_ledger ORDER BY ts DESC LIMIT ?)",
                            (self._max_rows,),
                        )
                    self._conn.commit()
                return True
            except Exception:  # noqa: BLE001 — observability must not block
                return False

    def prune(self) -> None:
        """Force the TTL + row-cap sweep (usually amortized over writes)."""
        with self._lock:
            if self._conn is None:
                now = self._now()
                self._memory = [
                    row for row in self._memory if not self._ttl or now - row[0] <= self._ttl
                ]
                if len(self._memory) > self._max_rows:
                    del self._memory[: len(self._memory) - self._max_rows]
                return
            try:
                if self._ttl > 0:
                    self._conn.execute(
                        "DELETE FROM request_ledger WHERE ts < ?",
                        (self._now() - self._ttl,),
                    )
                self._conn.execute(
                    "DELETE FROM request_ledger WHERE rowid NOT IN ("
                    "SELECT rowid FROM request_ledger ORDER BY ts DESC LIMIT ?)",
                    (self._max_rows,),
                )
                self._conn.commit()
            except Exception:  # noqa: BLE001 — observability must not block
                pass

    def stats(self) -> dict[str, Any]:
        """Read-only dashboard view: row count and ledger age."""
        with self._lock:
            if self._conn is None:
                rows = len(self._memory)
                oldest = self._memory[0][0] if self._memory else None
            else:
                try:
                    cur = self._conn.execute("SELECT COUNT(*) FROM request_ledger")
                    rows = int(cur.fetchone()[0])
                    cur = self._conn.execute("SELECT MIN(ts) FROM request_ledger")
                    oldest = cur.fetchone()[0]
                except Exception:  # noqa: BLE001
                    return {"rows": None, "oldest_age_seconds": None}
        if oldest is None:
            return {"rows": rows, "oldest_age_seconds": None}
        return {
            "rows": rows,
            "oldest_age_seconds": round(max(0.0, self._now() - float(oldest)), 1),
        }

    def entries(self, limit: int = 50) -> list[dict[str, Any]]:
        """Read-only tail of the most recent rows (audit/debug view).

        Newest-first in BOTH backends: the v3.0 defect returned the
        memory rows chronological (oldest first) while the SQL path
        ordered by ts DESC — the same call gave opposite orders
        depending on which backend the store had degraded to.
        """
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            if self._conn is None:
                rows = list(reversed(self._memory[-limit:]))
            else:
                try:
                    cur = self._conn.execute(
                        "SELECT ts, method, url, flags, engagement_id FROM request_ledger "
                        "ORDER BY ts DESC, rowid DESC LIMIT ?",
                        (limit,),
                    )
                    rows = cur.fetchall()
                except Exception:  # noqa: BLE001
                    return []
        return [
            {
                "ts": r[0], "method": r[1], "url": r[2], "flags": r[3],
                "engagement_id": r[4],
            }
            for r in rows
        ]


_LEDGER_LOCK = threading.Lock()
_LEDGER: RequestLedger | None = None


def get_ledger() -> RequestLedger:
    global _LEDGER
    with _LEDGER_LOCK:
        if _LEDGER is None:
            _LEDGER = RequestLedger()
        return _LEDGER


def _active_engagement_id() -> str:
    """The engagement bound to the active target workspace ('' when none).

    UM-DR-26 wiring fix: this alias previously imported a name
    (``active_engagement_id``) that ``target_workspace_context`` never
    exported, so every caller crashed with ImportError and the fail-soft
    wrappers masked the crash as an empty decision.  The engagement now
    derives from the M1b active-workspace identity axis, fail-soft to ''.
    """
    try:
        from webpent.shared.target_workspace_context import get_active_target_workspace

        workspace = get_active_target_workspace()
        engagement = getattr(workspace, "engagement_id", None) if workspace is not None else None
        return str(engagement or "")
    except Exception:  # noqa: BLE001 — fail soft to the unassigned bucket
        return ""


def ledger_request_hook(request: Any) -> None:
    """httpx request hook: log (ts, method, url, flags, engagement).

    Fail-soft by contract — any error is swallowed so the ledger can
    never break the request it observes.
    """
    try:
        get_ledger().record(
            getattr(request, "method", ""), str(getattr(request, "url", "")),
            engagement_id=_active_engagement_id(),
            flags=_PINNED_FLAG,
        )
    except Exception:  # noqa: BLE001 — observability must not block
        pass


def ledger_stats() -> dict[str, Any]:
    return get_ledger().stats()
