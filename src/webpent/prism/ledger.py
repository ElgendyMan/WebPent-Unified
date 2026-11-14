"""THE PRISM — U-PRISM-5, the Campaign Ledger (v89).

A local SQLite ledger of what Prism saw, scored and learned during a
campaign. Privacy laws are enforced structurally (PRISM-L-6/L-7): the
target name is stored only as a SHA-256 hash, every text blob passes
PII redaction before insert, and the schema is versioned — an unknown
newer schema fails closed instead of guessing. Everything is offline
and deterministic (PRISM-L-9).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.oracle.models import redact_pii, sha256_text
from webpent.prism.errors import PrismLawError
from webpent.prism.scorer import ScoreResult
from webpent.prism.taxonomy import EvidenceProfile

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,
    target_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    opened_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    source TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    strength TEXT NOT NULL,
    reproducibility TEXT NOT NULL,
    corroboration TEXT NOT NULL,
    score REAL NOT NULL,
    tier TEXT NOT NULL,
    rationale TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outcomes (
    outcome_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    result TEXT NOT NULL,
    notes TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS adjustments (
    adjustment_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    pattern_id TEXT NOT NULL,
    delta REAL NOT NULL,
    reason TEXT NOT NULL,
    confidence REAL NOT NULL,
    recorded_at TEXT NOT NULL
);
"""

VALID_RESULTS = ("confirmed", "refuted", "inconclusive")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class CampaignRecord:
    campaign_id: str
    target_hash: str
    name: str
    opened_at: str


class CampaignLedger:
    """Offline SQLite campaign ledger (U-PRISM-5)."""

    def __init__(self, db_path: Path | str) -> None:
        path = Path(db_path)
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        # R2-prism-01: the schema declares foreign keys; SQLite defaults
        # to OFF, so without this pragma they were never enforced.
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)
        row = self._conn.execute(
            "SELECT version FROM schema_version LIMIT 1"
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
        elif int(row["version"]) > SCHEMA_VERSION:
            self._conn.close()
            raise PrismLawError(
                f"ledger schema version {row['version']} is newer than "
                f"supported {SCHEMA_VERSION}; refusing to guess",
                law="PRISM-L-4",
            )
        self._conn.commit()

    # -- campaigns ---------------------------------------------------------------

    def open_campaign(self, target: str, name: str) -> str:
        if not target or not name:
            raise PrismLawError(
                "a campaign needs both a target and a name", law="PRISM-L-4"
            )
        # the raw target never touches the disk, only its hash (PRISM-L-6);
        # every text blob, including the operator-authored name, passes
        # PII redaction before insert (PRISM-L-7)
        name = redact_pii(name)
        target_hash = sha256_text(target)
        campaign_id = sha256_text(f"{target_hash}|{name}")[:16]
        self._conn.execute(
            "INSERT OR IGNORE INTO campaigns "
            "(campaign_id, target_hash, name, opened_at) VALUES (?, ?, ?, ?)",
            (campaign_id, target_hash, name, _utc_now()),
        )
        self._conn.commit()
        return campaign_id

    def get_campaign(self, campaign_id: str) -> CampaignRecord:
        row = self._conn.execute(
            "SELECT * FROM campaigns WHERE campaign_id = ?",
            (campaign_id,),
        ).fetchone()
        if row is None:
            raise PrismLawError(
                f"unknown campaign: {campaign_id}", law="PRISM-L-4"
            )
        return CampaignRecord(
            campaign_id=row["campaign_id"],
            target_hash=row["target_hash"],
            name=row["name"],
            opened_at=row["opened_at"],
        )

    # -- evidence / outcomes / adjustments -----------------------------------------

    def record_evidence(
        self, campaign_id: str, profile: EvidenceProfile, score: ScoreResult
    ) -> str:
        self.get_campaign(campaign_id)  # fail fast on unknown campaigns
        # R2-prism-02: the dedup key must include the taxonomy dimensions.
        # Two DIFFERENT profiles of one evidence_hash can produce the same
        # float score (verified collision in the shipped weights:
        # decisive/single_shot/corroborated == strong/single_shot/
        # independent_multiple = 0.134); the second must not silently
        # collapse into the first row.
        evidence_id = sha256_text(
            f"{campaign_id}|{profile.evidence_hash}|{score.score}|"
            f"{profile.strength.value}|{profile.reproducibility.value}|"
            f"{profile.corroboration.value}"
        )[:16]
        self._conn.execute(
            "INSERT OR IGNORE INTO evidence "
            "(evidence_id, campaign_id, source, evidence_type, strength, "
            " reproducibility, corroboration, score, tier, rationale, "
            " recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                evidence_id, campaign_id, profile.source.value,
                profile.evidence_type.value, profile.strength.value,
                profile.reproducibility.value, profile.corroboration.value,
                float(score.score), score.tier,
                redact_pii(profile.rationale), _utc_now(),
            ),
        )
        self._conn.commit()
        return evidence_id

    def record_outcome(
        self, campaign_id: str, evidence_id: str, result: str,
        notes: str = "",
    ) -> str:
        self.get_campaign(campaign_id)
        if result not in VALID_RESULTS:
            raise PrismLawError(
                f"outcome result must be one of {VALID_RESULTS}, got {result!r}",
                law="PRISM-L-3",
            )
        exists = self._conn.execute(
            "SELECT 1 FROM evidence WHERE evidence_id = ? AND campaign_id = ?",
            (evidence_id, campaign_id),
        ).fetchone()
        if exists is None:
            raise PrismLawError(
                f"outcome references unknown evidence in this campaign: "
                f"{evidence_id} (R2-prism-01: cross-campaign evidence is refused)",
                law="PRISM-L-4",
            )
        outcome_id = sha256_text(f"{campaign_id}|{evidence_id}|{result}")[:16]
        self._conn.execute(
            "INSERT OR IGNORE INTO outcomes "
            "(outcome_id, campaign_id, evidence_id, result, notes, "
            " recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
            (outcome_id, campaign_id, evidence_id, result,
             redact_pii(notes), _utc_now()),
        )
        self._conn.commit()
        return outcome_id

    def record_adjustment(
        self, campaign_id: str, pattern_id: str, delta: float,
        reason: str, confidence: float,
    ) -> str:
        self.get_campaign(campaign_id)
        if not reason:
            raise PrismLawError(
                "an adjustment without a reason is a law breach (PRISM-L-1)",
                law="PRISM-L-1",
            )
        adjustment_id = sha256_text(
            f"{campaign_id}|{pattern_id}|{delta}|{reason}"
        )[:16]
        self._conn.execute(
            "INSERT OR IGNORE INTO adjustments "
            "(adjustment_id, campaign_id, pattern_id, delta, reason, "
            " confidence, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (adjustment_id, campaign_id, pattern_id, float(delta),
             redact_pii(reason), float(confidence), _utc_now()),
        )
        self._conn.commit()
        return adjustment_id

    # -- export ---------------------------------------------------------------------

    def export(self, campaign_id: str) -> dict[str, Any]:
        self.get_campaign(campaign_id)
        evidence = [
            dict(row) for row in self._conn.execute(
                "SELECT * FROM evidence WHERE campaign_id = ? "
                "ORDER BY recorded_at, evidence_id",
                (campaign_id,),
            )
        ]
        outcomes = [
            dict(row) for row in self._conn.execute(
                "SELECT * FROM outcomes WHERE campaign_id = ? "
                "ORDER BY recorded_at, outcome_id",
                (campaign_id,),
            )
        ]
        adjustments = [
            dict(row) for row in self._conn.execute(
                "SELECT * FROM adjustments WHERE campaign_id = ? "
                "ORDER BY recorded_at, adjustment_id",
                (campaign_id,),
            )
        ]
        campaign = self.get_campaign(campaign_id)
        return {
            "schema_version": SCHEMA_VERSION,
            "campaign": {
                "campaign_id": campaign.campaign_id,
                "target_hash": campaign.target_hash,
                "name": campaign.name,
                "opened_at": campaign.opened_at,
            },
            "evidence": evidence,
            "outcomes": outcomes,
            "adjustments": adjustments,
        }

    def export_json(self, campaign_id: str) -> str:
        return json.dumps(self.export(campaign_id), indent=2, sort_keys=True)

    def close(self) -> None:
        self._conn.close()


__all__ = ["SCHEMA_VERSION", "CampaignLedger", "CampaignRecord",
           "VALID_RESULTS"]
