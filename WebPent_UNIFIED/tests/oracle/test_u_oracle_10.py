"""U-ORACLE-10 — the Prediction Validator (v88, plan 2026-10-17-v88-oracle.md)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from webpent.oracle.models import OracleLawError
from webpent.oracle.validator import MIN_SAMPLES, PredictionValidator

WORK = Path(__file__).resolve().parents[2]
VCONF = WORK / "config" / "oracle" / "validator.yaml"

CONFIG = yaml.safe_load(VCONF.read_text(encoding="utf-8"))


def _filled(tmp_path: Path, confirmed: int, refuted: int,
            kind: str = "path_prediction") -> PredictionValidator:
    validator = PredictionValidator(
        VCONF, ledger_path=tmp_path / "ledger.jsonl"
    )
    for i in range(confirmed + refuted):
        validator.record(f"pred-{kind}-{i}", kind)
    for i in range(confirmed):
        validator.record_outcome(f"pred-{kind}-{i}", "confirmed")
    for i in range(refuted):
        validator.record_outcome(f"pred-{kind}-{confirmed + i}", "refuted")
    return validator


# -- law checks -----------------------------------------------------------------

def test_min_samples_is_ten() -> None:
    assert CONFIG["min_samples"] == 10
    assert MIN_SAMPLES == 10


@pytest.mark.parametrize(
    "outcome",
    CONFIG["allowed_outcomes"],
)
def test_allowed_outcomes_recorded(outcome: str) -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        validator = PredictionValidator(
            VCONF, ledger_path=tmp_path / "ledger.jsonl"
        )
        validator.record("p1", "path_prediction")
        validator.record_outcome("p1", outcome)
        assert validator.resolved_outcomes() == 1


# -- spec test 1: no accuracy claim below MIN_SAMPLES --------------------------------

def test_refuses_accuracy_below_min_samples(tmp_path: Path) -> None:
    validator = _filled(tmp_path, confirmed=6, refuted=3)   # 9 resolved
    assert validator.resolved_outcomes() == MIN_SAMPLES - 1
    assert validator.accuracy() is None
    with pytest.raises(OracleLawError):
        validator.accuracy_or_raise()


# -- spec test 2: accuracy claim at exactly MIN_SAMPLES ----------------------------------

def test_accuracy_at_min_samples(tmp_path: Path) -> None:
    validator = _filled(tmp_path, confirmed=7, refuted=3)   # 10 resolved
    claim = validator.accuracy()
    assert claim is not None
    assert claim["samples"] == 10
    assert claim["accuracy"] == pytest.approx(0.7)
    assert validator.accuracy_or_raise() == claim


# -- spec test 3: unresolved records excluded -----------------------------------------------

def test_unresolved_excluded(tmp_path: Path) -> None:
    validator = _filled(tmp_path, confirmed=5, refuted=5)
    validator.record("pending-1", "path_prediction")   # stays unresolved
    claim = validator.accuracy()
    assert claim is not None
    assert claim["samples"] == 10
    assert validator.resolved_outcomes() == 10


# -- spec test 4: redacted ledger round trip ---------------------------------------------------

def test_ledger_redacted_round_trip(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    _filled(tmp_path, confirmed=4, refuted=1)
    # write a fresh validator that replays the same ledger file
    replay = PredictionValidator(VCONF, ledger_path=ledger)
    record = replay._records.get("pred-path_prediction-0")
    assert record is not None and record.outcome == "confirmed"
    for line in ledger.read_text(encoding="utf-8").splitlines():
        payload = json.loads(line)
        assert set(payload) <= {
            "prediction_id", "kind", "created_at", "outcome",
        }
        # no raw findings, secrets or paths ever reach the ledger
        assert "raw" not in payload and "detail" not in payload


# -- spec test 5: per-kind breakdown -------------------------------------------------------------

def test_per_kind_breakdown(tmp_path: Path) -> None:
    validator = _filled(tmp_path, confirmed=6, refuted=2,
                        kind="path_prediction")
    for i in range(2):
        validator.record(f"pred-signal-{i}", "signal_strength")
        validator.record_outcome(f"pred-signal-{i}", "refuted")
    claim = validator.accuracy()
    assert claim is not None
    assert claim["per_kind"]["path_prediction"]["samples"] == 8
    assert claim["per_kind"]["signal_strength"]["samples"] == 2
    assert claim["per_kind"]["signal_strength"]["accuracy"] == 0.0


# -- guards ------------------------------------------------------------------------------------

def test_invalid_outcome_rejected(tmp_path: Path) -> None:
    validator = PredictionValidator(
        VCONF, ledger_path=tmp_path / "ledger.jsonl"
    )
    validator.record("p1", "path_prediction")
    with pytest.raises(OracleLawError):
        validator.record_outcome("p1", "maybe")


def test_unknown_prediction_outcome_rejected(tmp_path: Path) -> None:
    validator = PredictionValidator(
        VCONF, ledger_path=tmp_path / "ledger.jsonl"
    )
    with pytest.raises(OracleLawError):
        validator.record_outcome("ghost", "confirmed")


def test_duplicate_prediction_rejected(tmp_path: Path) -> None:
    validator = PredictionValidator(
        VCONF, ledger_path=tmp_path / "ledger.jsonl"
    )
    validator.record("p1", "path_prediction")
    with pytest.raises(OracleLawError):
        validator.record("p1", "path_prediction")
