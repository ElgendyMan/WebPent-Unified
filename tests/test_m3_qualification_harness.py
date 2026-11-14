"""M3 UM-DR-17: the Charter §4.1 qualification measurement harness.

UM-DR-16 built the gate (``production/hypothesis_charter.py``) with no
runner; the registry's remaining M3 scope named the gap: "the
recall/precision measurement harness wiring against the blind_v3
corpus (the charter gate is built; the corpus harness run is the next
step)".

Contract under test:

1. **Corpus contract** — the blind_v3 manifest loader validates the
   shape fail-closed (bad manifest = ValueError, never a measurement).
2. **Producer measurement** — TP/FP/FN classification, producer
   crashes counted honestly, the verdict flows through the REAL gate.
3. **Verdict store** — deterministic round-trip; latest-wins; the
   freshness gate consumes stored verdicts end-to-end.
4. **Baseline replay** — the RECORDED blind_v3 mode_a metrics
   (reports/goed_v1_8_4/differential_v184.json) are replayed through
   the gate AND cross-checked against the pinned constants (drift =
   ValueError); the deterministic engine is refused budget by
   construction.
5. **A genuinely qualifying producer clears the gate end-to-end.**
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from webpent.production.hypothesis_charter import (
    DETERMINISTIC_BASELINE_PRECISION,
    DETERMINISTIC_BASELINE_RECALL,
)
from webpent.production.hypothesis_qualification_harness import (
    budget_decision_for,
    load_blind_v3_ground_truth,
    load_latest_verdict,
    measure_producer,
    replay_deterministic_baseline,
    save_verdict,
)

REPO = Path(__file__).resolve().parents[1]


def _write_manifest(path: Path, cases: list[dict]) -> Path:
    path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
    return path


def _corpus(n_vulnerable: int, n_clean: int) -> list[dict]:
    cases = []
    for index in range(n_vulnerable):
        cases.append(
            {"case_id": f"bv3_{index:03d}", "family": "simple", "is_vulnerable": True}
        )
    for index in range(n_clean):
        cases.append(
            {
                "case_id": f"bv3_{n_vulnerable + index:03d}",
                "family": "reasoning",
                "is_vulnerable": False,
            }
        )
    return cases


# ---------------------------------------------------------------------------
# 1. Corpus contract
# ---------------------------------------------------------------------------


def test_manifest_loader_validates_shape_fail_closed(tmp_path: Path) -> None:
    good = _write_manifest(tmp_path / "good.json", _corpus(3, 2))
    truth = load_blind_v3_ground_truth(good)
    assert truth == {
        "bv3_000": True,
        "bv3_001": True,
        "bv3_002": True,
        "bv3_003": False,
        "bv3_004": False,
    }

    (tmp_path / "missing.json").write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="unreadable"):
        load_blind_v3_ground_truth(tmp_path / "missing.json")

    (tmp_path / "empty.json").write_text(json.dumps({"cases": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="no cases"):
        load_blind_v3_ground_truth(tmp_path / "empty.json")

    (tmp_path / "nolabel.json").write_text(
        json.dumps({"cases": [{"case_id": "x"}]}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="boolean is_vulnerable"):
        load_blind_v3_ground_truth(tmp_path / "nolabel.json")

    (tmp_path / "dupe.json").write_text(
        json.dumps(
            {"cases": [{"case_id": "x", "is_vulnerable": True}, {"case_id": "x", "is_vulnerable": False}]}
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="appears twice"):
        load_blind_v3_ground_truth(tmp_path / "dupe.json")


# ---------------------------------------------------------------------------
# 2. Producer measurement
# ---------------------------------------------------------------------------


def test_measure_producer_classifies_through_the_real_gate(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path / "corpus.json", _corpus(20, 15))

    def perfect_producer(record: dict) -> bool:
        return bool(record["is_vulnerable"])

    verdict = measure_producer(
        perfect_producer, producer_name="perfect", manifest_path=manifest
    )
    assert verdict.true_positives == 20
    assert verdict.false_positives == 0
    assert verdict.false_negatives == 0
    assert verdict.sample_size == 35
    assert verdict.qualified is True
    assert verdict.recall == 1.0 and verdict.precision == 1.0


def test_measure_producer_counts_crashes_honestly(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path / "corpus.json", _corpus(20, 15))

    def crashing_producer(record: dict) -> bool:
        if record["is_vulnerable"]:
            raise RuntimeError("producer bug on a vulnerable case")
        return False

    verdict = measure_producer(
        crashing_producer, producer_name="crashy", manifest_path=manifest
    )
    # Every vulnerable case crashed -> not flagged -> FN.
    assert verdict.true_positives == 0
    assert verdict.false_negatives == 20
    assert any(
        "producer_error_counted_as_not_flagged:20" in reason
        for reason in verdict.reasons
    )
    assert verdict.qualified is False


def test_measure_producer_refuses_small_corpora(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path / "tiny.json", _corpus(5, 5))
    verdict = measure_producer(
        lambda record: bool(record["is_vulnerable"]),
        producer_name="tiny-run",
        manifest_path=manifest,
    )
    assert verdict.qualified is False
    assert any("sample_size_below_minimum" in r for r in verdict.reasons)


# ---------------------------------------------------------------------------
# 3. Verdict store
# ---------------------------------------------------------------------------


def test_verdict_store_roundtrip_and_latest_wins(tmp_path: Path) -> None:
    store = tmp_path / "verdicts.json"
    manifest = _write_manifest(tmp_path / "corpus.json", _corpus(20, 15))

    first = measure_producer(
        lambda r: False, producer_name="p1", manifest_path=manifest
    )
    save_verdict(first, store)
    second = measure_producer(
        lambda r: bool(r["is_vulnerable"]), producer_name="p1", manifest_path=manifest
    )
    save_verdict(second, store)

    latest = load_latest_verdict("p1", store)
    assert latest is not None
    assert latest.qualified is True  # the SECOND measurement is the latest
    assert load_latest_verdict("never-measured", store) is None


def test_budget_decision_end_to_end_with_freshness(tmp_path: Path) -> None:
    store = tmp_path / "verdicts.json"
    manifest = _write_manifest(tmp_path / "corpus.json", _corpus(20, 15))
    fresh = measure_producer(
        lambda r: bool(r["is_vulnerable"]),
        producer_name="fresh-producer",
        manifest_path=manifest,
        measured_at=datetime.now(timezone.utc),
    )
    save_verdict(fresh, store)
    allowed, reason, verdict = budget_decision_for("fresh-producer", store)
    assert allowed is True, reason
    assert verdict is not None and verdict.qualified

    stale = measure_producer(
        lambda r: bool(r["is_vulnerable"]),
        producer_name="stale-producer",
        manifest_path=manifest,
        measured_at=datetime.now(timezone.utc) - timedelta(days=30),
    )
    save_verdict(stale, store)
    allowed, reason, _ = budget_decision_for("stale-producer", store)
    assert allowed is False
    assert "stale" in reason or "fresh" in reason.lower() or "measurement" in reason.lower()


# ---------------------------------------------------------------------------
# 4. Baseline replay
# ---------------------------------------------------------------------------


def test_baseline_replay_matches_recorded_report_and_refuses_budget(
    tmp_path: Path,
) -> None:
    verdict = replay_deterministic_baseline()
    assert verdict.producer == "deterministic_engine_blind_v3_mode_a"
    assert verdict.sample_size == 120
    assert verdict.recall == pytest.approx(DETERMINISTIC_BASELINE_RECALL, abs=1e-4)
    assert verdict.precision == pytest.approx(DETERMINISTIC_BASELINE_PRECISION, abs=1e-4)
    # The deterministic engine IS the baseline: the gate refuses it by
    # construction (recall not above itself + below the charter bar).
    assert verdict.qualified is False
    assert any("recall_not_above_deterministic_baseline" in r for r in verdict.reasons)
    assert any("recall_below_threshold" in r for r in verdict.reasons)


def test_baseline_replay_detects_report_drift(tmp_path: Path) -> None:
    drifted = {
        "mode_a_llm_off": {
            "metrics": {"tp": 1, "fp": 2, "fn": 3, "tn": 4, "recall": 0.9, "precision": 0.9}
        }
    }
    path = tmp_path / "drifted.json"
    path.write_text(json.dumps(drifted), encoding="utf-8")
    with pytest.raises(ValueError, match="drifted"):
        replay_deterministic_baseline(path)


def test_baseline_report_exists_in_repo() -> None:
    assert (REPO / "reports" / "goed_v1_8_4" / "differential_v184.json").is_file()


# ---------------------------------------------------------------------------
# 5. The runner script wiring
# ---------------------------------------------------------------------------


def test_runner_script_replays_baseline(tmp_path: Path) -> None:
    import subprocess
    import sys

    store = tmp_path / "verdicts.json"
    result = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "run_hypothesis_qualification.py"),
            "--replay-baseline",
            "--store",
            str(store),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "deterministic_engine_blind_v3_mode_a" in result.stdout
    assert "REFUSED" in result.stdout
    assert load_latest_verdict("deterministic_engine_blind_v3_mode_a", store) is not None
