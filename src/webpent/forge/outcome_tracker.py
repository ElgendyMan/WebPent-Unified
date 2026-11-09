"""U-FORGE-13 — The Outcome Tracker.

Record every payload's real-world result — success or failure with the
evidence, the failure reason, and the phase/campaign that produced it
— in a queryable store beside the corpus. Records are only ever
written from an actual outcome (FORGE-L-1); nothing here invents
results. Zero network.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime

_SCHEMA = """
CREATE TABLE IF NOT EXISTS outcome_records (
    outcome_id TEXT PRIMARY KEY,
    payload_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    family TEXT NOT NULL,
    context TEXT,
    sent_at TEXT NOT NULL,
    success INTEGER NOT NULL,
    evidence TEXT,
    failure_reason TEXT,
    phase_id TEXT,
    campaign_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_outcome_records_payload
    ON outcome_records (payload_id, sent_at);
"""


@dataclass(frozen=True)
class PayloadOutcome:
    outcome_id: str
    payload_id: str
    target_id: str
    family: str
    context: dict | None
    sent_at: datetime
    success: bool
    evidence: dict
    failure_reason: str | None
    phase_id: str | None = None
    campaign_id: str | None = None


class OutcomeTracker:
    """Owns the outcome_records table on the corpus's database."""

    def __init__(self, indexer) -> None:
        self._indexer = indexer
        conn = indexer._conn
        conn.executescript(_SCHEMA)
        conn.commit()

    # ------------------------------------------------------------------

    def _outcome_id(self, outcome: PayloadOutcome) -> str:
        digest = hashlib.sha256()
        digest.update(outcome.payload_id.encode())
        digest.update(outcome.target_id.encode())
        digest.update(outcome.sent_at.isoformat().encode())
        digest.update(b"1" if outcome.success else b"0")
        return digest.hexdigest()[:16]

    def record(self, outcome: PayloadOutcome) -> str:
        """Store one real outcome; idempotent on identical input."""
        outcome_id = outcome.outcome_id or self._outcome_id(outcome)
        conn = self._indexer._conn
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO outcome_records "
                "(outcome_id, payload_id, target_id, family, context, "
                " sent_at, success, evidence, failure_reason, phase_id, "
                " campaign_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    outcome_id, outcome.payload_id, outcome.target_id,
                    outcome.family,
                    json.dumps(outcome.context, sort_keys=True)
                    if outcome.context is not None else None,
                    outcome.sent_at.isoformat(),
                    1 if outcome.success else 0,
                    json.dumps(outcome.evidence, sort_keys=True)
                    if outcome.evidence else None,
                    outcome.failure_reason, outcome.phase_id,
                    outcome.campaign_id,
                ))
        return outcome_id

    def outcomes_for(self, payload_id: str) -> list[PayloadOutcome]:
        conn = self._indexer._conn
        with conn:
            rows = conn.execute(
                "SELECT * FROM outcome_records WHERE payload_id = ? "
                "ORDER BY sent_at, outcome_id", (payload_id,)
            ).fetchall()
        return [self._row_to_outcome(dict(row)) for row in rows]

    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_outcome(row: dict) -> PayloadOutcome:
        return PayloadOutcome(
            outcome_id=row["outcome_id"],
            payload_id=row["payload_id"],
            target_id=row["target_id"],
            family=row["family"],
            context=json.loads(row["context"])
            if row["context"] else None,
            sent_at=datetime.fromisoformat(row["sent_at"]),
            success=bool(row["success"]),
            evidence=json.loads(row["evidence"])
            if row["evidence"] else {},
            failure_reason=row["failure_reason"],
            phase_id=row["phase_id"],
            campaign_id=row["campaign_id"],
        )
