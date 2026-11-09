# src/webpent/production/confidence_calibration.py
"""webpent.production.confidence_calibration — Track 12, item 8.

Roadmap contract (المسار 12، البند 8 — تعلم معاير):

    استخدام قرارات القبول والرفض البشرية في تحسين ترتيب الثقة، مع فصل
    بيانات العملاء ومنع الاعتماد على بيانات خام.

    ("Use human accept/reject decisions to improve CONFIDENCE ORDERING,
    with client data isolation and NO reliance on raw data.")

Design
------
``ConfidenceCalibrator`` turns human triage decisions (accepted /
rejected) into bounded per-(client, vuln_class) multipliers that REORDER
findings by calibrated confidence:

1. **Aggregates only — never raw data.** The store records, per
   (client_id, vuln_class), the counts of accepted/rejected decisions
   and coarse confidence buckets. No finding titles, URLs, payloads, or
   evidence ever enter the store (enforced by the record type itself:
   the fields do not exist).
2. **Client isolation by construction** — statistics live in a
   per-client namespace (hashed directory, like the worker
   coordination ledger). Cross-client influence is impossible: the
   calibrator NEVER reads another client's aggregate (a global
   fallback prior is the only shared thing, and it is a CONSTANT, not
   client data).
3. **Bounded, smoothed adjustment** — Laplace-smoothed acceptance rate
   blended with a neutral prior; the resulting multiplier is clamped to
   ``[MIN_MULTIPLIER, MAX_MULTIPLIER]`` (0.5..2.0), so a handful of
   decisions can reorder candidates but cannot wildly swing ranking,
   and a cold class is exactly neutral (1.0). Raw confidence is NEVER
   modified — only the ORDER of candidates changes.
4. **Deterministic** — identical feedback + candidates → identical
   ordering (stable ties by finding id).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "HumanDecision",
    "CalibrationRecord",
    "ConfidenceCalibrator",
    "calibrated_order",
]

#: Multiplier bounds — reordering power is deliberately limited.
MIN_MULTIPLIER = 0.5
MAX_MULTIPLIER = 2.0
#: Laplace smoothing strength (pseudo-counts on each side).
SMOOTHING_ALPHA = 3.0
#: Neutral blend weight of the class rate vs the constant prior.
PRIOR_WEIGHT = 0.5
#: Maximum kept decision records per (client, class) — bounded memory.
MAX_RECORDS_PER_CLASS = 500


class HumanDecision(str, Enum):
    """The only human triage vocabulary the calibrator consumes."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass
class CalibrationRecord:
    """One bounded, aggregate-safe feedback record (NO raw data fields)."""

    client_id: str
    vuln_class: str
    decision: HumanDecision
    severity: str = "info"  # coarse bucket only
    confidence_bucket: str = ""  # e.g. "0.6-0.8" — coarse bucket only
    decided_at: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "vuln_class": self.vuln_class,
            "decision": self.decision.value,
            "severity": self.severity,
            "confidence_bucket": self.confidence_bucket,
            "decided_at": self.decided_at,
        }


@dataclass
class ConfidenceCalibrator:
    """Per-client, per-class calibrated reordering from human decisions."""

    store_dir: str | os.PathLike[str]
    min_multiplier: float = MIN_MULTIPLIER
    max_multiplier: float = MAX_MULTIPLIER

    def __post_init__(self) -> None:
        self._root = Path(self.store_dir).expanduser()
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)

    # ------------------------------------------------------------------
    # storage (client-isolated by construction)
    # ------------------------------------------------------------------
    def _client_dir(self, client_id: str) -> Path:
        slug = "".join(c if c.isalnum() or c in "-_" else "_" for c in client_id)[:48]
        digest = hashlib.sha256(client_id.encode("utf-8", "replace")).hexdigest()[:12]
        path = self._root / f"{slug or 'blank'}-{digest}"
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    def _class_path(self, client_id: str, vuln_class: str) -> Path:
        digest = hashlib.sha256(vuln_class.encode("utf-8", "replace")).hexdigest()[:12]
        return self._client_dir(client_id) / f"class-{digest}.json"

    def record_decision(self, record: CalibrationRecord) -> bool:
        """Append a human decision to the client's own aggregate store."""
        try:
            path = self._class_path(record.client_id, record.vuln_class)
            data: dict[str, Any] = {"records": []}
            if path.exists():
                try:
                    loaded = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict) and isinstance(loaded.get("records"), list):
                        data = loaded
                except ValueError:
                    data = {"records": []}
            records = [r for r in data["records"] if isinstance(r, dict)]
            records.append(record.as_dict())
            # Bounded memory: keep the most recent decisions only.
            data["records"] = records[-MAX_RECORDS_PER_CLASS:]
            data["updated_at"] = time.time()
            path.write_text(
                json.dumps(data, separators=(",", ":")), encoding="utf-8"
            )
            return True
        except OSError:
            logger.warning("confidence_calibration: store write failed", exc_info=True)
            return False

    def class_stats(self, client_id: str, vuln_class: str) -> tuple[int, int]:
        """(accepted, rejected) counts for ONE client's class — never
        reads any other client's data."""
        path = self._class_path(client_id, vuln_class)
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return 0, 0
        records = loaded.get("records") if isinstance(loaded, dict) else None
        accepted = rejected = 0
        if isinstance(records, list):
            for raw in records:
                if not isinstance(raw, dict):
                    continue
                if raw.get("decision") == HumanDecision.ACCEPTED.value:
                    accepted += 1
                elif raw.get("decision") == HumanDecision.REJECTED.value:
                    rejected += 1
        return accepted, rejected

    # ------------------------------------------------------------------
    # calibration
    # ------------------------------------------------------------------
    def class_multiplier(self, client_id: str, vuln_class: str) -> float:
        """Bounded multiplier for one (client, class) from human history.

        rate = (accepted + α·prior) / (accepted + rejected + 2α), blended
        50/50 with the neutral prior (0.5), mapped linearly onto
        [min_multiplier, max_multiplier]. Cold class → exactly 1.0.
        """
        accepted, rejected = self.class_stats(client_id, vuln_class)
        total = accepted + rejected
        if total == 0:
            return 1.0
        alpha = SMOOTHING_ALPHA
        smoothed = (accepted + alpha * 0.5) / (total + 2 * alpha)
        blended = PRIOR_WEIGHT * smoothed + (1.0 - PRIOR_WEIGHT) * 0.5
        span = self.max_multiplier - self.min_multiplier
        return self.min_multiplier + blended * span

    def calibrated_order(
        self,
        candidates: list[tuple[str, str, float]],
        client_id: str,
    ) -> list[tuple[str, float]]:
        """Reorder ``(candidate_id, vuln_class, raw_confidence)`` tuples.

        Returns ``[(candidate_id, calibrated_confidence), ...]`` sorted
        by calibrated confidence desc with stable id ties. Raw
        confidence is clamped to [0,1] and multiplied by the class
        multiplier (itself bounded), then clamped again — the result
        stays a confidence, only the ORDER is the product.
        """
        scored: list[tuple[float, str, float]] = []
        for candidate_id, vuln_class, raw_confidence in candidates:
            raw = min(1.0, max(0.0, float(raw_confidence)))
            multiplier = self.class_multiplier(client_id, vuln_class)
            calibrated = min(1.0, max(0.0, raw * multiplier))
            scored.append((-calibrated, str(candidate_id), calibrated))
        scored.sort()  # deterministic: confidence desc, id asc
        return [(cid, conf) for _neg, cid, conf in scored]


def calibrated_order(
    candidates: list[tuple[str, str, float]],
    client_id: str,
    *,
    store_dir: str | os.PathLike[str],
) -> list[tuple[str, float]]:
    """Convenience wrapper: build a calibrator and reorder in one call."""
    return ConfidenceCalibrator(store_dir).calibrated_order(candidates, client_id)
