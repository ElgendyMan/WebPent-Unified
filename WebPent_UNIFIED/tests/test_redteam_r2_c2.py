"""RED-TEAM ROUND 2 — C2 batch (my items), fail-first (0.34.0 window).

Covers the Medium findings fixed directly by the orchestrator:
    R2-jc-04      calibration bucket edges misfile 0.3/0.6/0.7 (IEEE-754)
    R2-jc-05      one corrupt "ts" row crashes calibrator/bias detector/memory
    R2-jc-06      a repeated advocate_id silently erases the first argument
    R2-prism-02   evidence dedup key omits taxonomy dimensions (equal scores
                  collapse distinct profiles)
    R2-prism-03   compliance log write is non-atomic (crash after truncate
                  destroys the whole audit trail)
    R2-prism-04   request_cost_step config key is read by no code; the two
                  curiosity layers disagree 4x per extra request
    R2-prism-05   scorer loads a noise_penalties mapping missing rule keys
                  and silently stops penalizing that condition
    R2-prism-08   value_weighter/anomaly_filter validate only part of the
                  config keys they consume at decision time
    R2-graph-05   checkpoint redaction corrupts channel_versions /
                  versions_seen metadata for sensitive-named channels
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PRISM_CFG = REPO_ROOT / "config" / "prism"
NOW_TS = 1_800_000_000.0
NOW = datetime.fromtimestamp(NOW_TS, tz=timezone.utc)


# ---------------------------------------------------------------------------
# R2-jc-04
# ---------------------------------------------------------------------------

def test_r2jc_04_bucket_edges_are_float_exact(tmp_path):
    from webpent.jc.calibration import ConfidenceCalibrator

    cal = ConfidenceCalibrator(tmp_path / "c.jsonl", min_samples=1)
    for _ in range(5):
        cal.record(0.7, True, ts=NOW_TS)
    report = cal.report(now_ts=NOW_TS + 60)
    assert "0.7-0.8" in report.buckets, (
        f"prediction 0.7 misfiled into {sorted(report.buckets)}"
    )


def test_r2jc_04_bucket_edges_low_side(tmp_path):
    from webpent.jc.calibration import ConfidenceCalibrator

    cal = ConfidenceCalibrator(tmp_path / "c.jsonl", min_samples=1)
    for _ in range(5):
        cal.record(0.3, False, ts=NOW_TS)
    report = cal.report(now_ts=NOW_TS + 60)
    assert "0.3-0.4" in report.buckets


# ---------------------------------------------------------------------------
# R2-jc-05
# ---------------------------------------------------------------------------

def test_r2jc_05_calibrator_tolerates_corrupt_ts_row(tmp_path):
    from webpent.jc.calibration import ConfidenceCalibrator

    path = tmp_path / "c.jsonl"
    path.write_text(
        '{"predicted":0.5,"actual":1,"ts":1800000000.0}\n'
        '{"predicted":0.5,"actual":1,"ts":"corrupt"}\n',
        encoding="utf-8",
    )
    cal = ConfidenceCalibrator(path, min_samples=1)
    report = cal.report(now_ts=NOW_TS + 60)
    assert report.n_samples == 1


def test_r2jc_05_bias_detector_tolerates_corrupt_ts_row(tmp_path):
    from webpent.jc.bias_detector import BiasDetector

    path = tmp_path / "s.jsonl"
    path.write_text(
        json.dumps({
            "ts": NOW_TS,
            "verdict": {"advocates_summary": {
                "a1": {"score": 0.5, "claim": "c"},
            }},
        }) + "\n"
        '{"ts":"corrupt","verdict":{}}\n',
        encoding="utf-8",
    )
    detector = BiasDetector(path)
    facts = detector.detect(now_ts=NOW_TS + 60)
    assert isinstance(facts, list)


def test_r2jc_05_memory_compaction_tolerates_corrupt_ts_row(tmp_path):
    from webpent.jc.contracts import CouncilSession, Verdict
    from webpent.jc.memory import CouncilMemory

    path = tmp_path / "m.jsonl"
    path.write_text('{"session_id":"bad","ts":"corrupt"}\n', encoding="utf-8")
    memory = CouncilMemory(path, retention_days=30)
    session = CouncilSession(
        session_id="s2", question="q", context={"k": 1}, started_at=NOW,
    )
    verdict = Verdict(
        action="none", reasoning="r", confidence=0.0, confidence_tier="low",
        dissent=[], escalate=True, escalation_reason="r",
        advocates_summary={}, session_id="s2", timestamp=NOW,
    )
    memory.record(session, verdict, ts=NOW_TS + 60)
    rows = [json.loads(line) for line in path.read_text().splitlines()
            if line.strip()]
    assert any(row.get("session_id") == "s2" for row in rows)


# ---------------------------------------------------------------------------
# R2-jc-06
# ---------------------------------------------------------------------------

def _arg(advocate_id: str, claim: str):
    from webpent.jc.contracts import Argument

    return Argument(
        advocate_id=advocate_id, claim=claim, evidence=[], reasoning="r",
        confidence=0.5, alternatives=["x"], timestamp=NOW,
    )


def test_r2jc_06_duplicate_advocate_id_rejected():
    from webpent.jc.chamber import CouncilChamber

    chamber = CouncilChamber(now=NOW)
    session = chamber.convene("dup test?", {"k": 1})
    chamber.submit_argument(session.session_id, _arg("dupe", "STRONG"))
    with pytest.raises(ValueError, match="already"):
        chamber.submit_argument(session.session_id, _arg("dupe", "WEAK"))


# ---------------------------------------------------------------------------
# R2-prism-02
# ---------------------------------------------------------------------------

def test_r2prism_02_distinct_profiles_with_equal_score_kept(tmp_path):
    from webpent.prism.ledger import CampaignLedger
    from webpent.prism.scorer import EvidenceScorer
    from webpent.prism.taxonomy import EvidenceTaxonomy

    taxonomy = EvidenceTaxonomy(PRISM_CFG / "taxonomy.yaml")
    scorer = EvidenceScorer(PRISM_CFG / "scorer_weights.yaml", taxonomy)
    ledger = CampaignLedger(tmp_path / "l.db")
    try:
        campaign = ledger.open_campaign("t.example", "n")
        profile_a = taxonomy.profile(
            evidence_hash="a" * 64, source="probe",
            signal_kind="direct_response", strength="decisive",
            reproducibility="single_shot", corroboration="corroborated",
            rationale="A",
        )
        profile_b = taxonomy.profile(
            evidence_hash="a" * 64, source="probe",
            signal_kind="direct_response", strength="strong",
            reproducibility="single_shot",
            corroboration="independent_multiple", rationale="B",
        )
        score_a = scorer.score(profile_a)
        score_b = scorer.score(profile_b)
        assert score_a.score == score_b.score, "fixture must collide on score"
        ledger.record_evidence(campaign, profile_a, score_a)
        ledger.record_evidence(campaign, profile_b, score_b)
        assert len(ledger.export(campaign)["evidence"]) == 2, (
            "two distinct profiles with an equal score collapsed to one row"
        )
    finally:
        ledger.close()


# ---------------------------------------------------------------------------
# R2-prism-03
# ---------------------------------------------------------------------------

def _violation(violation_id: str):
    from webpent.prism.compliance import ComplianceViolation

    return ComplianceViolation(
        violation_id=violation_id, type="unscored_finding",
        severity="high", details={"rule": "x"}, auto_action="block",
    )


def test_r2prism_03_enforce_is_atomic_under_crash(tmp_path, monkeypatch):
    from webpent.prism.compliance import SilentFailureDetector

    audit = tmp_path / "audit.log"
    detector = SilentFailureDetector(audit)
    detector.enforce(_violation("v1"))
    assert len(audit.read_text().splitlines()) == 1

    def evil_replace(src, dst, **kwargs):
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(os, "replace", evil_replace)
    with pytest.raises(RuntimeError):
        detector.enforce(_violation("v2"))
    monkeypatch.undo()
    assert len(audit.read_text().splitlines()) == 1, (
        "a crash during the write destroyed the existing audit trail"
    )


# ---------------------------------------------------------------------------
# R2-prism-04
# ---------------------------------------------------------------------------

def _anomaly(requests: int):
    from webpent.prism.anomaly_filter import RawAnomaly

    return RawAnomaly(
        anomaly_id="an-1", anomaly_type="sqli_union",
        raw={"estimated_requests": requests, "estimated_impact": 0.5},
    )


def _ctx():
    from webpent.prism.anomaly_filter import FilterContext

    return FilterContext(target_hash="b" * 64)


def test_r2prism_04_request_cost_step_is_read_from_config(tmp_path):
    from webpent.prism.anomaly_filter import AnomalyFilter

    shipped = (PRISM_CFG / "curiosity_params.yaml").read_text(encoding="utf-8")
    wide = tmp_path / "wide.yaml"
    wide.write_text(
        shipped.replace("request_cost_step: 0.25", "request_cost_step: 1.0"),
        encoding="utf-8",
    )
    anomaly = _anomaly(2)
    ctx = _ctx()
    # shipped config: step 0.25 -> cost 1.25 for a 2-request anomaly
    assert "cost=1.250" in AnomalyFilter(
        PRISM_CFG / "curiosity_params.yaml"
    ).filter(anomaly, ctx).reasoning
    # configured step 1.0 -> cost 2.0 for the same anomaly
    assert "cost=2.000" in AnomalyFilter(wide).filter(anomaly, ctx).reasoning


def test_r2prism_04_weighter_reads_request_cost_step(tmp_path):
    from webpent.prism.value_weighter import (
        Signal, ValueWeighter, WeightingContext,
    )

    shipped = (PRISM_CFG / "curiosity_params.yaml").read_text(encoding="utf-8")
    wide = tmp_path / "wide.yaml"
    wide.write_text(
        shipped.replace("request_cost_step: 0.25", "request_cost_step: 1.0"),
        encoding="utf-8",
    )
    signal = Signal(
        signal_id="s1", anomaly_type="sqli_union", estimated_requests=5,
        evidence_strength=0.5, novelty=0.5, detection_risk=0.0,
    )
    ctx = WeightingContext(target_hash="b" * 64)
    narrow = ValueWeighter(PRISM_CFG / "curiosity_params.yaml").weight(
        signal, ctx
    )
    wide_run = ValueWeighter(wide).weight(signal, ctx)
    # requests=5: shipped step 0.25 -> 1/(1+0.25*4) = 0.500; step 1.0 -> 0.200
    assert narrow.components["cost_penalty"] == pytest.approx(0.5)
    assert wide_run.components["cost_penalty"] == pytest.approx(0.2), (
        "value_weighter ignores the request_cost_step config key"
    )


# ---------------------------------------------------------------------------
# R2-prism-05
# ---------------------------------------------------------------------------

def test_r2prism_05_scorer_rejects_incomplete_noise_penalties(tmp_path):
    from webpent.prism.errors import PrismLawError
    from webpent.prism.scorer import EvidenceScorer
    from webpent.prism.taxonomy import EvidenceTaxonomy

    shipped = (PRISM_CFG / "scorer_weights.yaml").read_text(encoding="utf-8")
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        shipped.replace("  unreproducible: 0.10\n", ""), encoding="utf-8"
    )
    assert "unreproducible" not in bad.read_text(encoding="utf-8"), (
        "fixture must actually drop the key"
    )
    taxonomy = EvidenceTaxonomy(PRISM_CFG / "taxonomy.yaml")
    with pytest.raises(PrismLawError, match="noise_penalties"):
        EvidenceScorer(bad, taxonomy)


# ---------------------------------------------------------------------------
# R2-prism-08
# ---------------------------------------------------------------------------

_WEIGHTER_MINIMAL = (
    "value_weighter:\n"
    "  component_weights:\n"
    "    prior_probability: 0.2\n"
    "    historical_success: 0.15\n"
    "    context_match: 0.15\n"
    "    evidence_strength: 0.2\n"
    "    novelty: 0.1\n"
    "    cost_penalty: 0.1\n"
    "    risk_penalty: 0.1\n"
    "  recommendation_thresholds:\n"
    "    prioritize: 0.75\n"
    "    keep: 0.5\n"
    "    backlog: 0.25\n"
)


def test_r2prism_08_weighter_missing_confidence_width_is_law_error(tmp_path):
    from webpent.prism.errors import PrismLawError
    from webpent.prism.value_weighter import ValueWeighter

    cfg = tmp_path / "w.yaml"
    cfg.write_text(_WEIGHTER_MINIMAL, encoding="utf-8")
    with pytest.raises(PrismLawError):
        ValueWeighter(cfg)


def test_r2prism_08_weighter_non_monotonic_thresholds_rejected(tmp_path):
    from webpent.prism.errors import PrismLawError
    from webpent.prism.value_weighter import ValueWeighter

    cfg = tmp_path / "w.yaml"
    cfg.write_text(
        _WEIGHTER_MINIMAL + "  confidence_width: 0.1\n", encoding="utf-8"
    )
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        _WEIGHTER_MINIMAL.replace("    keep: 0.5\n", "    keep: 0.1\n")
        + "  confidence_width: 0.1\n",
        encoding="utf-8",
    )
    ValueWeighter(cfg)  # valid config loads
    with pytest.raises(PrismLawError, match="descend"):
        ValueWeighter(bad)


def test_r2prism_08_anomaly_filter_rejects_missing_cost_keys(tmp_path):
    from webpent.prism.anomaly_filter import AnomalyFilter
    from webpent.prism.errors import PrismLawError

    shipped = (PRISM_CFG / "curiosity_params.yaml").read_text(encoding="utf-8")
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "\n".join(
            line for line in shipped.splitlines()
            if not line.strip().startswith("hour_cost_step:")
        ) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(PrismLawError):
        AnomalyFilter(bad)


# ---------------------------------------------------------------------------
# R2-graph-05
# ---------------------------------------------------------------------------

def test_r2graph_05_redaction_never_touches_version_metadata():
    from webpent.graph.checkpoints import _redact_checkpoint

    checkpoint = {
        "v": 1, "id": "cp1", "ts": "t",
        "channel_values": {"credentials": {"password": "p"}},
        "channel_versions": {
            "credentials": "0000000000000000.0.1",
            "messages": "0000000000000000.0.2",
        },
        "versions_seen": {
            "node1": {"credentials": "0000000000000000.0.3"},
        },
    }
    out = _redact_checkpoint(checkpoint)
    assert out["channel_versions"]["credentials"] == "0000000000000000.0.1"
    assert out["channel_versions"]["messages"] == "0000000000000000.0.2"
    assert out["versions_seen"]["node1"]["credentials"] == (
        "0000000000000000.0.3"
    )
    # channel_values secrets are still redacted (the designed behavior)
    assert out["channel_values"]["credentials"]["password"] == ""
