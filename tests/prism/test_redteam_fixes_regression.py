"""v89 PRISM — regression tests for the red-team review fixes.

Each test pins one finding from
docs/reviews/2026-10-18-v89-prism-red-team.md
so the fix cannot silently regress:
  F-003 order-invariant apply_priors (PRISM-L-9)
  F-004 PII-redacted campaign names (PRISM-L-7)
  F-005 capped on-disk audit log
  F-006 corroborating anomaly earns no conflict penalty
  F-007 prune() accepts naive/aware datetime mixes
  F-008 refusal is returned, never raised (PRISM-L-2)
  F-010 integrator config validation (coherence keys, threshold order)
  F-011 metrics time_saved_hours follows max_time_hours from config
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from webpent.prism.compliance import (
    ComplianceViolation,
    SilentFailureDetector,
)
from webpent.prism.errors import PrismLawError
from webpent.prism.integration import BrainState, Finding, PrismIntegration
from webpent.prism.ledger import CampaignLedger
from webpent.prism.metrics import MetricsEngine, Observation
from webpent.prism.patterns import Pattern, PatternExtractor, _confidence
from webpent.prism.priors import PriorAdjuster
from webpent.prism.scorer import EvidenceScorer, ScoreResult
from webpent.prism.taxonomy import EvidenceTaxonomy
from webpent.prism.tiering import MultiSignalIntegrator

WORK = Path(__file__).resolve().parents[2]
TAXONOMY = WORK / "config" / "prism" / "taxonomy.yaml"
SCORER = WORK / "config" / "prism" / "scorer_weights.yaml"
LEARNING = WORK / "config" / "prism" / "learning_params.yaml"
CURIOSITY = WORK / "config" / "prism" / "curiosity_params.yaml"

NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)


def _profile(source: str = "validator", kind: str = "direct_response",
             strength: str = "decisive", evidence_hash: str = "c" * 64):
    taxonomy = EvidenceTaxonomy(TAXONOMY)
    return taxonomy.profile(
        evidence_hash=evidence_hash, source=source, signal_kind=kind,
        strength=strength, reproducibility="deterministic",
        corroboration="independent_multiple", rationale="validated",
    )


def _integration(ledger: CampaignLedger | None = None) -> PrismIntegration:
    taxonomy = EvidenceTaxonomy(TAXONOMY)
    scorer = EvidenceScorer(SCORER, taxonomy)
    integrator = MultiSignalIntegrator(SCORER)
    adjuster = PriorAdjuster(LEARNING)
    from webpent.prism.value_weighter import ValueWeighter
    return PrismIntegration(
        taxonomy, scorer, integrator, ValueWeighter(CURIOSITY), adjuster,
        ledger=ledger,
    )


def _pattern(samples: int = 20, successes: int = 16,
             key: str = "sqli_union") -> Pattern:
    return Pattern(
        pattern_id="pat" * 4, pattern_type="technique_effectiveness",
        key=key, samples=samples, successes=successes,
        success_rate=successes / samples, confidence=_confidence(samples),
        updated_at=NOW.isoformat(), reason=f"{successes}/{samples} confirmed",
    )


# -- F-003: apply_priors order invariance ------------------------------------------

def test_apply_priors_is_order_invariant() -> None:
    integration = _integration()
    state = BrainState(priors={"sqli_union": 0.5, "nosqli_auth_bypass": 0.5})
    a = _pattern(key="sqli_union")
    b = _pattern(samples=10, successes=4, key="nosqli_auth_bypass")
    forward = integration.apply_priors(state, [a, b])
    backward = integration.apply_priors(state, [b, a])
    assert forward.priors == backward.priors
    assert forward.history == backward.history


def test_apply_priors_does_not_mutate_input_state() -> None:
    integration = _integration()
    state = BrainState(priors={"sqli_union": 0.5})
    integration.apply_priors(state, [_pattern()])
    assert state.priors["sqli_union"] == 0.5


# -- F-004: campaign name PII redaction ---------------------------------------------

def test_campaign_name_is_pii_redacted(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign(
            "target.example", "contact john.doe@corp.com 01001234567"
        )
        record = ledger.get_campaign(campaign_id)
        assert "john.doe@corp.com" not in record.name
        assert "01001234567" not in record.name
        assert "[pii-redacted:" in record.name
    finally:
        ledger.close()


# -- F-005: on-disk audit log is capped ----------------------------------------------

def test_audit_log_is_capped(tmp_path: Path) -> None:
    detector = SilentFailureDetector(tmp_path / "audit.log")
    violation = ComplianceViolation(
        violation_id="v" * 16, type="unlogged_score", severity="high",
        details={"subject": "f-1"}, auto_action="flag",
    )
    extra = SilentFailureDetector.MAX_LOG_LINES + 250
    for _ in range(extra):
        detector.enforce(violation)
    lines = (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()
    assert len(lines) == SilentFailureDetector.MAX_LOG_LINES
    # in-memory log still keeps every entry (zero silent drops)
    assert len(detector._log) == extra


def test_enforce_all_batched_matches_enforce_loop(tmp_path: Path) -> None:
    violation = ComplianceViolation(
        violation_id="a" * 16, type="unlogged_score", severity="high",
        details={"subject": "f-1"}, auto_action="flag",
    )
    batched_detector = SilentFailureDetector()
    batched_detector.enforce_all([violation] * 7, tmp_path / "batched.log")
    loop_detector = SilentFailureDetector()
    for _ in range(7):
        loop_detector.enforce(violation, tmp_path / "loop.log")
    assert (tmp_path / "batched.log").read_text(encoding="utf-8") == \
        (tmp_path / "loop.log").read_text(encoding="utf-8")


# -- F-006: corroborating anomaly earns no conflict penalty ---------------------------

def _score(hash_prefix: str, score: float) -> ScoreResult:
    return ScoreResult(
        evidence_hash=hash_prefix + "0" * (64 - len(hash_prefix)),
        score=score, tier="B", recommendation="investigate soon",
    )


def test_agreeing_anomaly_is_not_penalized() -> None:
    integrator = MultiSignalIntegrator(SCORER)
    anomaly = (_profile(source="oracle", kind="header_anomaly",
                        strength="moderate", evidence_hash="a" * 64),
               _score("a", 0.80))
    active = (_profile(source="validator", kind="direct_response",
                       strength="moderate", evidence_hash="b" * 64),
              _score("b", 0.60))
    penalty, conflicts = integrator._conflicts([anomaly, active])
    assert penalty == 0.0
    assert conflicts == ()


def test_genuine_disagreement_is_still_penalized() -> None:
    integrator = MultiSignalIntegrator(SCORER)
    anomaly = (_profile(source="oracle", kind="header_anomaly",
                        strength="moderate", evidence_hash="a" * 64),
               _score("a", 0.40))
    active = (_profile(source="validator", kind="direct_response",
                       strength="moderate", evidence_hash="b" * 64),
              _score("b", 0.60))
    penalty, conflicts = integrator._conflicts([anomaly, active])
    assert penalty > 0.0
    assert len(conflicts) == 1


# -- F-007: prune() handles naive/aware datetime mixes --------------------------------

def _extractor() -> PatternExtractor:
    return PatternExtractor(LEARNING)


def test_prune_with_aware_now_and_naive_updated_at() -> None:
    extractor = _extractor()
    stale = _pattern(key="old_technique")
    stale = Pattern(**{**stale.__dict__, "updated_at":
                       (NOW - timedelta(days=200)).isoformat()})
    fresh = _pattern(key="new_technique")
    fresh = Pattern(**{**fresh.__dict__, "updated_at":
                       NOW.replace(tzinfo=None).isoformat()})  # naive string
    kept = extractor.prune([stale, fresh], NOW)
    assert [p.key for p in kept] == ["new_technique"]


def test_prune_with_naive_now_and_aware_updated_at() -> None:
    extractor = _extractor()
    fresh = _pattern(key="aware_pattern")  # updated_at is aware (NOW)
    kept = extractor.prune([fresh], NOW.replace(tzinfo=None))
    assert [p.key for p in kept] == ["aware_pattern"]


# -- F-008: refusal is returned, never raised -----------------------------------------

def test_validate_finding_without_profiles_passes_through() -> None:
    integration = _integration()
    result = integration.validate_finding(
        Finding(finding_id="f-x", title="t", anomaly_type="a", profiles=())
    )
    assert result.verdict == "refused"
    assert result.integrated_score == 0.0
    assert result.blocked is False
    assert result.reasons


def test_record_outcome_without_profiles_returns_empty(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("target.example", "proj")
        integration = _integration(ledger)
        recorded = integration.record_outcome(
            Finding(finding_id="f-y", title="t", anomaly_type="a",
                    profiles=()),
            "confirmed", campaign_id,
        )
        assert recorded == []
    finally:
        ledger.close()


# -- F-010: integrator config validation ----------------------------------------------

def test_integrator_accepts_three_coherence_keys() -> None:
    integrator = MultiSignalIntegrator(SCORER)
    assert integrator._config["coherence"] == {
        "three_or_more": 1.0, "two": 0.7, "one": 0.4,
    }


def test_integrator_rejects_missing_coherence_key(tmp_path: Path) -> None:
    data = yaml.safe_load(SCORER.read_text(encoding="utf-8"))
    del data["integration"]["coherence"]["one"]
    broken = tmp_path / "broken.yaml"
    broken.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(PrismLawError):
        MultiSignalIntegrator(broken)


def test_integrator_rejects_unordered_thresholds(tmp_path: Path) -> None:
    data = yaml.safe_load(SCORER.read_text(encoding="utf-8"))
    data["integration"]["verdict_thresholds"]["confirmed"] = 0.5  # < likely
    broken = tmp_path / "broken.yaml"
    broken.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(PrismLawError):
        MultiSignalIntegrator(broken)


# -- F-011: time_saved_hours follows config -------------------------------------------

def _observations(avoided: int) -> list[Observation]:
    obs = [
        Observation(phase="before", accepted=True, time_hours=2.0,
                    evidence_score=0.6),
        Observation(phase="after", accepted=True, time_hours=1.0,
                    evidence_score=0.8),
    ]
    obs += [
        Observation(phase="after", accepted=True, time_hours=0.5,
                    evidence_score=0.7, rabbit_hole_avoided=True)
        for _ in range(avoided)
    ]
    return obs


def test_time_saved_uses_configured_max_time_hours(tmp_path: Path) -> None:
    config = yaml.safe_load(CURIOSITY.read_text(encoding="utf-8"))
    config["rabbit_hole"]["max_time_hours"] = 1.5
    custom = tmp_path / "curiosity.yaml"
    custom.write_text(yaml.safe_dump(config), encoding="utf-8")
    engine = MetricsEngine(custom)
    assert engine.time_saved_per_rabbit_hole == 1.5
    for obs in _observations(avoided=2):
        engine.record(obs)
    metrics = engine.compute(NOW)
    assert metrics.time_saved_hours == pytest.approx(3.0)


def test_metrics_default_matches_curiosity_config() -> None:
    config = yaml.safe_load(CURIOSITY.read_text(encoding="utf-8"))
    assert float(config["rabbit_hole"]["max_time_hours"]) == \
        MetricsEngine.DEFAULT_TIME_SAVED_HOURS


def test_metrics_rejects_missing_or_bad_config(tmp_path: Path) -> None:
    with pytest.raises(PrismLawError):
        MetricsEngine(tmp_path / "does_not_exist.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("rabbit_hole:\n  max_time_hours: -1\n", encoding="utf-8")
    with pytest.raises(PrismLawError):
        MetricsEngine(bad)
