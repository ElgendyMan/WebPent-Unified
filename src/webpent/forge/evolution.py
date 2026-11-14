"""U-FORGE-14 — The Evolution Engine.

Adjust payload standing from REAL outcomes only (FORGE-L-1): success
boosts the payload and its similar siblings (same family/subfamily,
half the boost), failure decreases it, a WAF failure marks the payload
WAF-susceptible, and a heavily-failing payload gets candidate variants
generated for testing — candidates are flagged ``needs_testing`` and
are never stored as proven results. The engine keeps its own
adjustment layer over the corpus (the indexer's published success-rate
arithmetic is untouched). Zero network.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evolution_adjustments (
    payload_id TEXT PRIMARY KEY,
    delta REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS evolution_context_boost (
    payload_id TEXT NOT NULL,
    context_key TEXT NOT NULL,
    boost REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (payload_id, context_key)
);
CREATE TABLE IF NOT EXISTS evolution_waf_marks (
    payload_id TEXT PRIMARY KEY,
    reason TEXT,
    marked_at TEXT
);
CREATE TABLE IF NOT EXISTS evolution_candidates (
    payload_id TEXT NOT NULL,
    name TEXT NOT NULL,
    encoded TEXT NOT NULL,
    needs_testing INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (payload_id, name)
);
"""

_SUCCESS_STEP = 0.05
_SIBLING_FACTOR = 0.5
_FAILURE_STEP = 0.05
_CONTEXT_STEP = 0.1
_CANDIDATE_MIN_FAILURES = 5
_CANDIDATE_MAX_SUCCESS_RATIO = 0.2


class EvolutionEngine:
    """Learns per-payload adjustments from recorded outcomes."""

    def __init__(self, indexer, tracker) -> None:
        self._indexer = indexer
        self._tracker = tracker
        conn = indexer._conn
        conn.executescript(_SCHEMA)
        conn.commit()

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------

    def success_rate(self, payload_id: str) -> float:
        """The engine's learned adjustment for this payload, in [0, 1]."""
        conn = self._indexer._conn
        with conn:
            row = conn.execute(
                "SELECT delta FROM evolution_adjustments "
                "WHERE payload_id = ?", (payload_id,)).fetchone()
        if row is None:
            return 0.0
        return max(0.0, min(1.0, row["delta"]))

    def waf_susceptible(self, payload_id: str) -> bool:
        conn = self._indexer._conn
        with conn:
            row = conn.execute(
                "SELECT 1 FROM evolution_waf_marks "
                "WHERE payload_id = ?", (payload_id,)).fetchone()
        return row is not None

    def context_boost(self, payload_id: str, context_key: str) -> float:
        conn = self._indexer._conn
        with conn:
            row = conn.execute(
                "SELECT boost FROM evolution_context_boost "
                "WHERE payload_id = ? AND context_key = ?",
                (payload_id, context_key)).fetchone()
        return row["boost"] if row else 0.0

    def candidates_for(self, payload_id: str) -> list[tuple[str, str]]:
        conn = self._indexer._conn
        with conn:
            rows = conn.execute(
                "SELECT name, encoded FROM evolution_candidates "
                "WHERE payload_id = ? ORDER BY name", (payload_id,)
            ).fetchall()
        return [(row["name"], row["encoded"]) for row in rows]

    # ------------------------------------------------------------------
    # learning
    # ------------------------------------------------------------------

    def update_after_outcome(self, outcome) -> None:
        self._tracker.record(outcome)
        conn = self._indexer._conn
        with conn:
            if outcome.success:
                self._apply_delta(conn, outcome.payload_id,
                                  _SUCCESS_STEP)
                self._boost_context(conn, outcome)
                for sibling in self._similar_payloads(outcome.payload_id):
                    self._apply_delta(conn, sibling,
                                      _SUCCESS_STEP * _SIBLING_FACTOR)
            else:
                self._apply_delta(conn, outcome.payload_id,
                                  -_FAILURE_STEP)
                reason = (outcome.failure_reason or "").lower()
                if "waf" in reason:
                    conn.execute(
                        "INSERT OR REPLACE INTO evolution_waf_marks "
                        "(payload_id, reason, marked_at) VALUES (?,?,?)",
                        (outcome.payload_id, outcome.failure_reason,
                         datetime.now(timezone.utc).isoformat()))

    # ------------------------------------------------------------------

    def _apply_delta(self, conn, payload_id: str, delta: float) -> None:
        conn.execute(
            "INSERT INTO evolution_adjustments (payload_id, delta) "
            "VALUES (?, ?) "
            "ON CONFLICT(payload_id) DO UPDATE SET "
            "delta = max(0.0, min(1.0, delta + excluded.delta))",
            (payload_id, delta))

    def _boost_context(self, conn, outcome) -> None:
        if not outcome.context:
            return
        for key, value in outcome.context.items():
            if isinstance(value, list) and value:
                for item in value:
                    self._bump_context(conn, outcome.payload_id, item)
            elif isinstance(value, str) and value:
                self._bump_context(conn, outcome.payload_id, value)

    def _bump_context(self, conn, payload_id: str, key: str) -> None:
        conn.execute(
            "INSERT INTO evolution_context_boost "
            "(payload_id, context_key, boost) VALUES (?, ?, ?) "
            "ON CONFLICT(payload_id, context_key) DO UPDATE SET "
            "boost = boost + excluded.boost",
            (payload_id, key, _CONTEXT_STEP))

    def _similar_payloads(self, payload_id: str) -> list[str]:
        """Payloads sharing this one's family and subfamily."""
        me = self._indexer.get_payload(payload_id)
        if me is None:
            return []
        siblings = [p.payload_id for p in
                    self._indexer.list_by_family(me.family)
                    if p.subfamily == me.subfamily
                    and p.payload_id != payload_id]
        return sorted(siblings)

    # ------------------------------------------------------------------
    # candidate generation (flagged untested, never proven)
    # ------------------------------------------------------------------

    def generate_new_variants(self, payload_id: str):
        from webpent.forge.encoding_engine import EncodedVariant, \
            generate_variants
        outcomes = self._tracker.outcomes_for(payload_id)
        if len(outcomes) < _CANDIDATE_MIN_FAILURES:
            return []
        successes = sum(1 for o in outcomes if o.success)
        if successes / len(outcomes) > _CANDIDATE_MAX_SUCCESS_RATIO:
            return []
        payload = self._indexer.get_payload(payload_id)
        if payload is None:
            return []
        candidates: list[EncodedVariant] = []
        conn = self._indexer._conn
        with conn:
            for variant in generate_variants(payload.raw):
                conn.execute(
                    "INSERT OR REPLACE INTO evolution_candidates "
                    "(payload_id, name, encoded, needs_testing) "
                    "VALUES (?, ?, ?, 1)",
                    (payload_id, variant.name, variant.encoded))
                candidates.append(variant)
        return candidates
