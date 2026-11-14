"""Durable action reservations for bounded campaign execution.

The ledger is intentionally transport-agnostic.  It records only redacted action
metadata and reservation state; request bodies, cookies, and response content
must never be persisted here.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LedgerReservation:
    """Result of an atomic action reservation attempt."""

    allowed: bool
    reason: str = ""
    used_actions: int = 0
    used_budget: float = 0.0
    rejection_metadata: dict[str, Any] | None = None


def _rejection_metadata(
    reason: str,
    *,
    used_actions: int = 0,
    used_budget: float = 0.0,
) -> dict[str, Any] | None:
    """Return a stable, redaction-safe name for a denied reservation."""
    if not reason:
        return None
    names = {
        "budget:max_actions_exhausted": ("max_actions_cap", "cap"),
        "budget:action_budget_exhausted": ("budget_cap", "cap"),
        "budget:invalid_or_over_engagement_limit": ("budget_request_invalid", "budget"),
        "operator:halted": ("operator_halt", "control"),
        "loop:repeated_hypothesis": ("repeated_hypothesis", "safety"),
        "idempotency:duplicate_reservation": ("duplicate_reservation", "idempotency"),
        "idempotency:key_required": ("idempotency_key_required", "input"),
        "identity:engagement_required": ("engagement_required", "input"),
        "ledger:reservation_failure": ("ledger_unavailable", "availability"),
    }
    name, category = names.get(reason, ("reservation_rejected", "reservation"))
    return {
        "name": name,
        "category": category,
        "reason": reason,
        "used_actions": int(used_actions),
        "used_budget": float(used_budget),
    }


class SQLiteActionLedger:
    """SQLite-backed reservation ledger safe across worker restarts."""

    _TERMINAL_STATUSES = frozenset({"executed", "failed"})

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS action_ledger (
                    idempotency_key TEXT NOT NULL,
                    engagement_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    target_origin TEXT NOT NULL,
                    method TEXT NOT NULL,
                    action_family TEXT NOT NULL,
                    identity_ref TEXT NOT NULL,
                    tenant_context TEXT NOT NULL,
                    vulnerability_class TEXT NOT NULL,
                    validator_id TEXT NOT NULL,
                    action_signature TEXT NOT NULL DEFAULT '',
                    estimated_cost REAL NOT NULL,
                    status TEXT NOT NULL,
                    reserved_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    output_digest TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (engagement_id, idempotency_key)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_action_ledger_engagement
                ON action_ledger (engagement_id, status)
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS campaign_controls (
                    engagement_id TEXT PRIMARY KEY,
                    halt_requested INTEGER NOT NULL DEFAULT 0,
                    requested_by TEXT NOT NULL DEFAULT '',
                    requested_at TEXT,
                    resumed_at TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS reservation_rejections (
                    engagement_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    used_actions INTEGER NOT NULL DEFAULT 0,
                    used_budget REAL NOT NULL DEFAULT 0.0,
                    rejected_at TEXT NOT NULL
                )
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(action_ledger)")}
            if "action_signature" not in columns:
                connection.execute(
                    "ALTER TABLE action_ledger ADD COLUMN action_signature TEXT NOT NULL DEFAULT ''"
                )

    def _record_rejection(self, metadata: dict[str, Any] | None) -> None:
        """Persist only redacted denial metadata for operator status views."""
        if not metadata:
            return
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO reservation_rejections
                        (engagement_id, name, category, reason, used_actions, used_budget, rejected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(engagement_id) DO UPDATE SET
                        name=excluded.name, category=excluded.category, reason=excluded.reason,
                        used_actions=excluded.used_actions, used_budget=excluded.used_budget,
                        rejected_at=excluded.rejected_at
                    """,
                    (
                        str(metadata.get("engagement_id", ""))[:128],
                        str(metadata["name"])[:64],
                        str(metadata["category"])[:32],
                        str(metadata["reason"])[:128],
                        int(metadata.get("used_actions", 0)),
                        float(metadata.get("used_budget", 0.0)),
                        self._now(),
                    ),
                )
        except sqlite3.Error:
            # A status projection must never turn a deterministic reservation
            # denial into an execution failure.
            return

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    def reserve(
        self,
        *,
        idempotency_key: str,
        engagement_id: str,
        task_id: str,
        target_origin: str,
        method: str,
        action_family: str,
        identity_ref: str,
        tenant_context: str,
        vulnerability_class: str,
        validator_id: str,
        estimated_cost: float,
        max_actions: int,
        max_budget: float,
        action_signature: str = "",
        loop_threshold: int = 3,
    ) -> LedgerReservation:
        """Atomically reserve one action or return a deterministic denial."""
        key = str(idempotency_key or "").strip()
        if not key:
            return LedgerReservation(False, "idempotency:key_required")
        if not engagement_id.strip():
            return LedgerReservation(False, "identity:engagement_required")
        if estimated_cost <= 0 or estimated_cost > max_budget:
            return LedgerReservation(False, "budget:invalid_or_over_engagement_limit")

        now = self._now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            control = connection.execute(
                "SELECT halt_requested FROM campaign_controls WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchone()
            if control is not None and bool(control[0]):
                connection.rollback()
                return LedgerReservation(False, "operator:halted", 0, 0.0)
            signature = str(action_signature or key)[:256]
            repeated = connection.execute(
                """
                SELECT COUNT(*) FROM action_ledger
                WHERE engagement_id=? AND action_signature=?
                  AND status IN ('reserved', 'executed')
                """,
                (engagement_id, signature),
            ).fetchone()[0]
            if int(repeated) >= max(1, int(loop_threshold)):
                connection.rollback()
                return LedgerReservation(False, "loop:repeated_hypothesis", int(repeated), 0.0)
            existing = connection.execute(
                """
                SELECT status FROM action_ledger
                WHERE engagement_id = ? AND idempotency_key = ?
                """,
                (engagement_id, key),
            ).fetchone()
            if existing is not None:
                used = connection.execute(
                    """
                    SELECT COUNT(*) AS actions, COALESCE(SUM(estimated_cost), 0.0) AS budget
                    FROM action_ledger
                    WHERE engagement_id = ? AND status IN ('reserved', 'executed')
                    """,
                    (engagement_id,),
                ).fetchone()
                connection.rollback()
                return LedgerReservation(
                    False,
                    "idempotency:duplicate_reservation",
                    int(used["actions"]),
                    float(used["budget"]),
                )

            used = connection.execute(
                """
                SELECT COUNT(*) AS actions, COALESCE(SUM(estimated_cost), 0.0) AS budget
                FROM action_ledger
                WHERE engagement_id = ? AND status IN ('reserved', 'executed')
                """,
                (engagement_id,),
            ).fetchone()
            used_actions = int(used["actions"])
            used_budget = float(used["budget"])
            if used_actions >= max_actions:
                metadata = _rejection_metadata(
                    "budget:max_actions_exhausted",
                    used_actions=used_actions,
                    used_budget=used_budget,
                )
                connection.rollback()
                if metadata:
                    self._record_rejection({**metadata, "engagement_id": engagement_id})
                return LedgerReservation(
                    False, "budget:max_actions_exhausted", used_actions, used_budget, metadata
                )
            if used_budget + estimated_cost > max_budget:
                metadata = _rejection_metadata(
                    "budget:action_budget_exhausted",
                    used_actions=used_actions,
                    used_budget=used_budget,
                )
                connection.rollback()
                if metadata:
                    self._record_rejection({**metadata, "engagement_id": engagement_id})
                return LedgerReservation(
                    False, "budget:action_budget_exhausted", used_actions, used_budget, metadata
                )

            connection.execute(
                """
                INSERT INTO action_ledger (
                    idempotency_key, engagement_id, task_id, target_origin, method,
                    action_family, identity_ref, tenant_context, vulnerability_class,
                    validator_id, action_signature, estimated_cost, status, reserved_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)
                """,
                (
                    key,
                    engagement_id[:128],
                    task_id[:128],
                    target_origin[:256],
                    method.upper()[:16],
                    action_family[:64],
                    identity_ref[:128],
                    tenant_context[:128],
                    vulnerability_class[:128],
                    validator_id[:128],
                    signature,
                    float(estimated_cost),
                    now,
                    now,
                ),
            )
            connection.commit()
            return LedgerReservation(True, "", used_actions + 1, used_budget + estimated_cost)
        except sqlite3.Error:
            connection.rollback()
            return LedgerReservation(False, "ledger:reservation_failure")
        finally:
            connection.close()

    def loop_detected(self, engagement_id: str, action_signature: str, threshold: int = 3) -> bool:
        """Return true when a hypothesis signature has been attempted repeatedly."""
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT COUNT(*) FROM action_ledger
                    WHERE engagement_id=? AND action_signature=?
                      AND status IN ('reserved', 'executed')
                    """,
                    (str(engagement_id)[:128], str(action_signature)[:256]),
                ).fetchone()
            return int(row[0]) >= max(1, int(threshold))
        except sqlite3.Error:
            return True

    def request_halt(self, engagement_id: str, requested_by: str = "operator") -> bool:
        """Request a cooperative halt; the current action is never interrupted."""
        engagement_id = str(engagement_id or "").strip()
        if not engagement_id:
            return False
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO campaign_controls
                        (engagement_id, halt_requested, requested_by, requested_at, resumed_at)
                    VALUES (?, 1, ?, ?, NULL)
                    ON CONFLICT(engagement_id) DO UPDATE SET
                        halt_requested=1, requested_by=excluded.requested_by,
                        requested_at=excluded.requested_at, resumed_at=NULL
                    """,
                    (engagement_id[:128], str(requested_by or "operator")[:128], self._now()),
                )
            return True
        except sqlite3.Error:
            return False

    def clear_halt(self, engagement_id: str) -> bool:
        """Clear a halt request before a deliberate operator resume."""
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    UPDATE campaign_controls
                    SET halt_requested=0, resumed_at=?
                    WHERE engagement_id=?
                    """,
                    (self._now(), str(engagement_id)[:128]),
                )
            return cursor.rowcount == 1
        except sqlite3.Error:
            return False

    def is_halted(self, engagement_id: str) -> bool:
        """Read the cooperative stop flag at the reservation checkpoint."""
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT halt_requested FROM campaign_controls WHERE engagement_id=?",
                    (str(engagement_id)[:128],),
                ).fetchone()
            return bool(row and row[0])
        except sqlite3.Error:
            # A control-plane read failure must not silently permit execution.
            return True

    def complete(
        self,
        engagement_id: str,
        idempotency_key: str,
        *,
        status: str,
        output_digest: str = "",
    ) -> bool:
        """Mark a reservation terminal without persisting sensitive output."""
        if not str(idempotency_key or "").strip():
            return False
        if str(status or "").strip() not in self._TERMINAL_STATUSES:
            return False
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    UPDATE action_ledger
                    SET status = ?, updated_at = ?, output_digest = ?
                    WHERE engagement_id = ? AND idempotency_key = ? AND status = 'reserved'
                    """,
                    (
                        str(status)[:32],
                        self._now(),
                        str(output_digest)[:128],
                        engagement_id,
                        idempotency_key,
                    ),
                )
                return cursor.rowcount == 1
        except sqlite3.Error:
            return False

    def snapshot(self, engagement_id: str) -> dict[str, Any]:
        """Return redacted usage counters for operator diagnostics."""
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT COUNT(*) AS actions, COALESCE(SUM(estimated_cost), 0.0) AS budget
                    FROM action_ledger
                    WHERE engagement_id = ? AND status IN ('reserved', 'executed')
                    """,
                    (engagement_id,),
                ).fetchone()
            return {
                "engagement_id": engagement_id[:128],
                "used_actions": int(row["actions"]),
                "used_budget": float(row["budget"]),
                "last_rejection": self._last_rejection(connection, engagement_id),
            }
        except sqlite3.Error:
            return {
                "engagement_id": engagement_id[:128],
                "used_actions": 0,
                "used_budget": 0.0,
                "error": "ledger_unavailable",
            }

    @staticmethod
    def _last_rejection(
        connection: sqlite3.Connection, engagement_id: str
    ) -> dict[str, Any] | None:
        row = connection.execute(
            """
            SELECT name, category, reason, used_actions, used_budget, rejected_at
            FROM reservation_rejections WHERE engagement_id=?
            """,
            (str(engagement_id)[:128],),
        ).fetchone()
        if row is None:
            return None
        return {
            "name": str(row["name"]),
            "category": str(row["category"]),
            "reason": str(row["reason"]),
            "used_actions": int(row["used_actions"]),
            "used_budget": float(row["used_budget"]),
            "rejected_at": str(row["rejected_at"]),
        }


__all__ = ["LedgerReservation", "SQLiteActionLedger"]
