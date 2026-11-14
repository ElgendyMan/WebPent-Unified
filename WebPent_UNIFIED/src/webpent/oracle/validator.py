"""THE ORACLE — U-ORACLE-10, the Prediction Validator (v88).

Tracks how the Oracle's predictions fared over time. Below MIN_SAMPLES
outcomes the validator refuses to state any accuracy figure at all —
no claim without evidence (ORACLE-L-8). The ledger records prediction
ids, kinds and outcomes only; no secrets, no raw findings, no target
paths (ORACLE-L-3).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from webpent.oracle.models import OracleLawError

MIN_SAMPLES = 10
ALLOWED_OUTCOMES = ("confirmed", "refuted")


@dataclass
class PredictionRecord:
    prediction_id: str
    kind: str
    created_at: str
    outcome: str | None = None      # None until the operator decides

    def to_dict(self) -> dict[str, Any]:
        return {
            "prediction_id": self.prediction_id,
            "kind": self.kind,
            "created_at": self.created_at,
            "outcome": self.outcome,
        }


class PredictionValidator:
    def __init__(self, config_path: Path,
                 ledger_path: Path | None = None) -> None:
        data = yaml.safe_load(
            Path(config_path).read_text(encoding="utf-8")
        ) or {}
        self._min_samples = int(data.get("min_samples", MIN_SAMPLES))
        if self._min_samples < 1:
            raise OracleLawError("min_samples must be at least 1")
        self._allowed = tuple(
            data.get("allowed_outcomes", ALLOWED_OUTCOMES)
        ) or ALLOWED_OUTCOMES
        self._ledger_path = Path(ledger_path) if ledger_path else None
        self._records: dict[str, PredictionRecord] = {}
        if self._ledger_path and self._ledger_path.exists():
            self._load()

    # -- ledger I/O (append-only JSONL, ids and outcomes only) -----------------

    def _load(self) -> None:
        assert self._ledger_path is not None
        for line in self._ledger_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            raw = json.loads(line)
            record = PredictionRecord(
                prediction_id=raw["prediction_id"],
                kind=raw["kind"],
                created_at=raw["created_at"],
                outcome=raw.get("outcome"),
            )
            self._records[record.prediction_id] = record

    def _append(self, record: PredictionRecord) -> None:
        if self._ledger_path is None:
            return
        self._ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with self._ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(record.to_dict(), sort_keys=True) + "\n"
            )

    # -- public surface -----------------------------------------------------------

    def record(self, prediction_id: str, kind: str) -> PredictionRecord:
        if prediction_id in self._records:
            raise OracleLawError(
                f"prediction {prediction_id!r} is already on the ledger"
            )
        record = PredictionRecord(
            prediction_id=prediction_id,
            kind=kind,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._records[prediction_id] = record
        self._append(record)
        return record

    def record_outcome(self, prediction_id: str, outcome: str) -> None:
        if outcome not in self._allowed:
            raise OracleLawError(
                f"outcome must be one of {self._allowed}, got {outcome!r}"
            )
        record = self._records.get(prediction_id)
        if record is None:
            raise OracleLawError(
                f"unknown prediction {prediction_id!r}"
            )
        record.outcome = outcome
        self._append(record)

    def resolved_outcomes(self) -> int:
        return sum(
            1 for r in self._records.values() if r.outcome is not None
        )

    def accuracy(self) -> dict[str, Any] | None:
        """The accuracy claim. None below MIN_SAMPLES — the validator
        refuses to state a rate it cannot back."""
        resolved = [
            r for r in self._records.values() if r.outcome is not None
        ]
        if len(resolved) < self._min_samples:
            return None
        confirmed = sum(1 for r in resolved if r.outcome == "confirmed")
        per_kind: dict[str, dict[str, float]] = {}
        for kind in {r.kind for r in resolved}:
            kind_records = [r for r in resolved if r.kind == kind]
            kind_confirmed = sum(
                1 for r in kind_records if r.outcome == "confirmed"
            )
            per_kind[kind] = {
                "samples": len(kind_records),
                "accuracy": round(kind_confirmed / len(kind_records), 3),
            }
        return {
            "samples": len(resolved),
            "accuracy": round(confirmed / len(resolved), 3),
            "per_kind": per_kind,
        }

    def accuracy_or_raise(self) -> dict[str, Any]:
        claim = self.accuracy()
        if claim is None:
            raise OracleLawError(
                f"accuracy claimable only at {self._min_samples} resolved "
                f"outcomes; {self.resolved_outcomes()} so far "
                f"(no claim without evidence)"
            )
        return claim


__all__ = ["MIN_SAMPLES", "PredictionRecord", "PredictionValidator"]
