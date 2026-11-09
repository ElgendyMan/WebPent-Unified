# src/webpent/benchmark/metrics_store.py
"""SQLite snapshot store for self-test harness runs (2026-10-25
proposals, Proposal 6).

Every ``run_vulnbox_campaign`` report can be persisted as a dated
snapshot so detection quality is a TIMELINE, not an anecdote: the
benchmark gate (``scripts/benchmark_gate.py``) and the nightly
schedule both read this store to decide whether a capability change
regressed recall or raised false positives.

Bounded: snapshots keep per-mode class rows only; there is no finding
payload in the store, so it can never leak target data.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.benchmark.fixtures.runner import VulnboxBenchmarkReport

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vulnbox_runs (
    run_id TEXT PRIMARY KEY,
    recorded_at TEXT NOT NULL,
    modes TEXT NOT NULL,
    tp TEXT NOT NULL,
    fp TEXT NOT NULL,
    fn TEXT NOT NULL,
    total_server_requests INTEGER NOT NULL,
    elapsed_seconds REAL NOT NULL,
    report_json TEXT NOT NULL
);
"""


class VulnboxMetricsStore:
    """Append-only snapshot store for harness reports."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(path))
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def record_report(self, report: VulnboxBenchmarkReport) -> str:
        payload = json.dumps(report.as_dict())
        with self._conn:
            self._conn.execute(
                "INSERT INTO vulnbox_runs (run_id, recorded_at, modes, tp, fp, fn,"
                " total_server_requests, elapsed_seconds, report_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    report.run_id,
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    ",".join(r.mode for r in report.results),
                    ",".join(report.tp),
                    ",".join(report.fp),
                    ",".join(report.fn),
                    report.total_server_requests,
                    report.elapsed_seconds,
                    payload,
                ),
            )
        return report.run_id

    def history(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT run_id, recorded_at, modes, tp, fp, fn,"
            " total_server_requests, elapsed_seconds FROM vulnbox_runs"
            " ORDER BY rowid DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        return [
            {
                "run_id": r[0], "recorded_at": r[1], "modes": r[2],
                "tp": r[3].split(",") if r[3] else [], "fp": r[4].split(",") if r[4] else [],
                "fn": r[5].split(",") if r[5] else [],
                "total_server_requests": r[6], "elapsed_seconds": r[7],
            }
            for r in rows
        ]  # rowid DESC: insertion order — same-second runs keep their true sequence

    def latest(self) -> dict[str, Any] | None:
        rows = self.history(limit=1)
        return rows[0] if rows else None

    def close(self) -> None:
        self._conn.close()


__all__ = ["VulnboxMetricsStore"]
