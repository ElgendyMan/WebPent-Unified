"""U-FORGE-15 — The Cross-Target Transfer.

Knowledge moves only between SIMILAR targets (spec threshold 0.7,
similarity as the Jaccard overlap of the two targets' tech stacks,
WAFs and contexts), carries only payloads that actually SUCCEEDED
on the source target (never failures), and always lands weaker than
direct success: the transfer factor is similarity * 0.7. Boosts are
stored once (idempotent) on the corpus database in a table this
unit owns, the same ownership pattern as the OutcomeTracker's
outcome_records.

Zero network; advisory evidence only.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

SIMILARITY_THRESHOLD = 0.7

TRANSFER_BASE_FACTOR = 0.7

_TRANSFER_SCHEMA = """
CREATE TABLE IF NOT EXISTS transfer_boosts (
    payload_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    boost REAL NOT NULL,
    PRIMARY KEY (payload_id, target_id)
);
"""


@dataclass(frozen=True)
class TargetProfile:
    target_id: str
    tech_stack: tuple[str, ...] = ()
    waf: tuple[str, ...] = ()
    contexts: tuple[str, ...] = ()


def _profile_items(profile: TargetProfile) -> set[str]:
    items = {f"tech:{t}" for t in profile.tech_stack}
    items |= {f"waf:{w}" for w in profile.waf}
    items |= {f"ctx:{c}" for c in profile.contexts}
    return items


def compute_similarity(a: TargetProfile, b: TargetProfile) -> float:
    """Jaccard overlap of the two profiles' dimension-tagged items."""
    items_a = _profile_items(a)
    items_b = _profile_items(b)
    union = items_a | items_b
    if not union:
        return 0.0
    return len(items_a & items_b) / len(union)


@dataclass(frozen=True)
class TransferResult:
    from_target: str
    to_target: str
    similarity: float
    transferred: tuple[tuple[str, float], ...]


class CrossTargetTransfer:
    """Moves successful payloads between similar targets, storing a
    per-target ranking boost weaker than direct success."""

    def __init__(self, indexer) -> None:
        self._indexer = indexer
        self._conn: sqlite3.Connection = indexer._conn
        self._conn.executescript(_TRANSFER_SCHEMA)
        self._conn.commit()
        self._profiles: dict[str, TargetProfile] = {}

    # ------------------------------------------------------------------

    def set_profile(self, profile: TargetProfile) -> None:
        self._profiles[profile.target_id] = profile

    def successful_payloads(self, target_id: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT payload_id FROM outcome_records "
            "WHERE target_id = ? AND success = 1 "
            "ORDER BY payload_id", (target_id,))
        return [row["payload_id"] for row in rows]

    def transfer(self, from_target: str, to_target: str) \
            -> TransferResult | None:
        profile_from = self._profiles.get(from_target)
        profile_to = self._profiles.get(to_target)
        if profile_from is None or profile_to is None:
            return None
        similarity = compute_similarity(profile_from, profile_to)
        if similarity < SIMILARITY_THRESHOLD:
            return None
        factor = similarity * TRANSFER_BASE_FACTOR
        transferred: list[tuple[str, float]] = []
        for payload_id in self.successful_payloads(from_target):
            self._conn.execute(
                "INSERT OR IGNORE INTO transfer_boosts "
                "(payload_id, target_id, boost) VALUES (?, ?, ?)",
                (payload_id, to_target, factor))
            transferred.append((payload_id, factor))
        self._conn.commit()
        return TransferResult(from_target=from_target,
                              to_target=to_target,
                              similarity=similarity,
                              transferred=tuple(transferred))

    def boost_for(self, payload_id: str, target_id: str) -> float:
        row = self._conn.execute(
            "SELECT boost FROM transfer_boosts WHERE payload_id = ? "
            "AND target_id = ?", (payload_id, target_id)).fetchone()
        return float(row["boost"]) if row is not None else 0.0

    def effective_score(self, payload_id: str, target_id: str) -> float:
        """Base quality plus the target's transfer boost — the
        ranking key that carries transferred knowledge."""
        payload = self._indexer.get_payload(payload_id)
        base = payload.quality_score if payload is not None else 0.0
        return base + self.boost_for(payload_id, target_id)
