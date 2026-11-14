"""Durable, target-free runtime markers used by the P9 qualification task.

This module is intentionally separate from target findings. It records only
bounded state for an internal qualification exercise: checkpoint creation,
worker ownership, one deterministic side effect, and terminal completion. It
never stores task arguments, credentials, cookies, HTTP data, or payloads.
"""
from __future__ import annotations

import hashlib
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class QualificationState:
    engagement_id: str
    idempotency_key: str
    status: str
    checkpoint_created: bool
    side_effect_count: int
    worker_id: str


class P9QualificationLedger:
    """SQLite-backed state machine for one harmless internal task."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS p9_qualification_runs (
                    engagement_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    checkpoint_created INTEGER NOT NULL DEFAULT 0,
                    side_effect_count INTEGER NOT NULL DEFAULT 0,
                    worker_id TEXT NOT NULL DEFAULT '',
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (engagement_id, idempotency_key)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS p9_qualification_dead_letters (
                    engagement_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    task_name TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    retries INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    recorded_at REAL NOT NULL,
                    PRIMARY KEY (engagement_id, idempotency_key)
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    @staticmethod
    def _clean(value: str, limit: int = 160) -> str:
        return str(value or "").strip()[:limit]

    def begin_or_resume(
        self,
        engagement_id: str,
        idempotency_key: str,
        worker_id: str,
    ) -> QualificationState:
        engagement = self._clean(engagement_id, 128)
        key = self._clean(idempotency_key, 240)
        worker = self._clean(worker_id, 128)
        if not engagement or not key or not worker:
            raise ValueError("qualification identity is required")
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT engagement_id, idempotency_key, status,
                       checkpoint_created, side_effect_count, worker_id
                FROM p9_qualification_runs
                WHERE engagement_id = ? AND idempotency_key = ?
                """,
                (engagement, key),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO p9_qualification_runs
                    (engagement_id, idempotency_key, status, checkpoint_created,
                     side_effect_count, worker_id, updated_at)
                    VALUES (?, ?, 'checkpointed', 1, 0, ?, ?)
                    """,
                    (engagement, key, worker, now),
                )
                status = "checkpointed"
                count = 0
            else:
                status = str(row["status"])
                count = int(row["side_effect_count"])
                connection.execute(
                    """
                    UPDATE p9_qualification_runs
                    SET worker_id = ?, updated_at = ?
                    WHERE engagement_id = ? AND idempotency_key = ?
                    """,
                    (worker, now, engagement, key),
                )
            connection.commit()
        return QualificationState(engagement, key, status, True, count, worker)

    def record_side_effect(
        self,
        engagement_id: str,
        idempotency_key: str,
        worker_id: str,
    ) -> bool:
        """Atomically record the one deterministic side effect."""
        now = time.time()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE p9_qualification_runs
                SET side_effect_count = 1, status = 'side_effect_done',
                    worker_id = ?, updated_at = ?
                WHERE engagement_id = ? AND idempotency_key = ?
                  AND checkpoint_created = 1 AND side_effect_count = 0
                """,
                (
                    self._clean(worker_id, 128),
                    now,
                    self._clean(engagement_id, 128),
                    self._clean(idempotency_key, 240),
                ),
            )
            return cursor.rowcount == 1

    def complete(self, engagement_id: str, idempotency_key: str) -> bool:
        now = time.time()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE p9_qualification_runs
                SET status = 'completed', updated_at = ?
                WHERE engagement_id = ? AND idempotency_key = ?
                  AND checkpoint_created = 1 AND side_effect_count = 1
                  AND status IN ('checkpointed', 'side_effect_done')
                """,
                (now, self._clean(engagement_id, 128), self._clean(idempotency_key, 240)),
            )
            return cursor.rowcount == 1

    def get(self, engagement_id: str, idempotency_key: str) -> QualificationState | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT engagement_id, idempotency_key, status,
                       checkpoint_created, side_effect_count, worker_id
                FROM p9_qualification_runs
                WHERE engagement_id = ? AND idempotency_key = ?
                """,
                (self._clean(engagement_id, 128), self._clean(idempotency_key, 240)),
            ).fetchone()
        if row is None:
            return None
        return QualificationState(
            engagement_id=str(row["engagement_id"]),
            idempotency_key=str(row["idempotency_key"]),
            status=str(row["status"]),
            checkpoint_created=bool(row["checkpoint_created"]),
            side_effect_count=int(row["side_effect_count"]),
            worker_id=str(row["worker_id"]),
        )

    def record_dead_letter(
        self,
        engagement_id: str,
        idempotency_key: str,
        *,
        task_name: str,
        task_id: str,
        retries: int,
        reason: str,
        payload: object = None,
    ) -> bool:
        """Persist one redacted dead-letter record idempotently."""
        material = repr(payload).encode("utf-8", errors="replace")
        payload_hash = hashlib.sha256(material).hexdigest()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO p9_qualification_dead_letters
                (engagement_id, idempotency_key, task_name, task_id, retries,
                 reason, payload_sha256, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self._clean(engagement_id, 128),
                    self._clean(idempotency_key, 240),
                    self._clean(task_name, 160),
                    self._clean(task_id, 160),
                    max(0, int(retries)),
                    self._clean(reason, 240),
                    payload_hash,
                    time.time(),
                ),
            )
            return cursor.rowcount == 1

    def get_dead_letter(self, engagement_id: str, idempotency_key: str) -> dict[str, object] | None:
        """Return only redacted DLQ metadata for one qualification run."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT task_name, task_id, retries, reason, payload_sha256
                FROM p9_qualification_dead_letters
                WHERE engagement_id = ? AND idempotency_key = ?
                """,
                (self._clean(engagement_id, 128), self._clean(idempotency_key, 240)),
            ).fetchone()
        if row is None:
            return None
        return {
            "task_name": str(row[0]),
            "task_id": str(row[1]),
            "retries": int(row[2]),
            "reason": str(row[3]),
            "payload_sha256": str(row[4]),
        }

    def output_digest(self, engagement_id: str, idempotency_key: str) -> str:
        value = f"{self._clean(engagement_id, 128)}:{self._clean(idempotency_key, 240)}"
        return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = ["P9QualificationLedger", "QualificationState"]
