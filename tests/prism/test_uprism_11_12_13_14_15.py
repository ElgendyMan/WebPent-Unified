"""v89 PRISM — U-PRISM-11 (integration), 12 (metrics), 13 (dashboard),
14 (cold start), 15 (compliance) tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from webpent.prism import PREAMBLE_LINE
from webpent.prism.cold_start import ColdStartAccelerator
from webpent.prism.compliance import (
    AuditedAdjustment,
    AuditedFinding,
    AuditedPattern,
    AuditFlow,
    SilentFailureDetector,
)
from webpent.prism.dashboard import render_dashboard
from webpent.prism.errors import PrismLawError
from webpent.prism.integration import (
    BrainState,
    Finding,
    PrismIntegration,
)
from webpent.prism.ledger import CampaignLedger
from webpent.prism.metrics import MetricsEngine, Observation
from webpent.prism.patterns import Pattern, _confidence
from webpent.prism.priors import PriorAdjuster
from webpent.prism.scorer import EvidenceScorer
from webpent.prism.taxonomy import EvidenceTaxonomy
from webpent.prism.tiering import MultiSignalIntegrator
from webpent.prism.value_weighter import Signal, ValueWeighter, WeightingContext

WORK = Path(__file__).resolve().parents[2]
TAXONOMY = WORK / "config" / "prism" / "taxonomy.yaml"
SCORER = WORK / "config" / "prism" / "scorer_weights.yaml"
LEARNING = WORK / "config" / "prism" / "learning_params.yaml"
CURIOSITY = WORK / "config" / "prism" / "curiosity_params.yaml"
ARCHETYPES = WORK / "config" / "prism" / "archetypes.yaml"

NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)


def _profile(source: str = "validator", kind: str = "direct_response",
             strength: str = "decisive", evidence_hash: str = "c" * 64):
    taxonomy = EvidenceTaxonomy(TAXONOMY)
    return taxonomy.profile(
        evidence_hash=evidence_hash, source=source, signal_kind=kind,
        strength=strength, reproducibility="deterministic",
        corroboration="independent_multiple", rationale="validated",
    )


# -- U-PRISM-11: integration -----------------------------------------------------------

def _integration(ledger: CampaignLedger | None = None) -> PrismIntegration:
    taxonomy = EvidenceTaxonomy(TAXONOMY)
    scorer = EvidenceScorer(SCORER, taxonomy)
    integrator = MultiSignalIntegrator(SCORER)
    weighter = ValueWeighter(CURIOSITY)
    adjuster = PriorAdjuster(LEARNING)
    return PrismIntegration(taxonomy, scorer, integrator, weighter,
                            adjuster, ledger=ledger)


def _pattern(samples: int = 20, successes: int = 16,
             key: str = "sqli_union") -> Pattern:
    return Pattern(
        pattern_id="pat" * 4, pattern_type="technique_effectiveness",
        key=key, samples=samples, successes=successes,
        success_rate=successes / samples, confidence=_confidence(samples),
        updated_at=NOW.isoformat(), reason=f"{successes}/{samples} confirmed",
    )


def test_enrich_signal_adds_score() -> None:
    integration = _integration()
    signal = Signal(signal_id="s-1", anomaly_type="sqli_union",
                    evidence_strength=0.8, novelty=0.3)
    enriched = integration.enrich_signal(signal, WeightingContext("b" * 64))
    assert enriched.weight.weight > 0.0
    assert enriched.weight.components


def test_validate_finding_returns_verdict() -> None:
    integration = _integration()
    finding = Finding(
        finding_id="f-1", title="auth bypass", anomaly_type="authz",
        profiles=(
            _profile(),
            _profile(evidence_hash="d" * 64),
            _profile(evidence_hash="e" * 64),
        ),
    )
    result = integration.validate_finding(finding)
    assert result.verdict == "confirmed"
    assert 0.0 <= result.integrated_score <= 1.0
    assert result.reasons


def test_apply_priors_changes_brain_state() -> None:
    integration = _integration()
    state = BrainState(priors={"sqli_union": 0.5})
    new_state = integration.apply_priors(state, [_pattern()])
    assert new_state.priors["sqli_union"] > 0.5
    assert new_state.priors["sqli_union"] <= 0.7  # cap ±0.20


def test_record_outcome_feeds_ledger(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("target.example", "proj")
        integration = _integration(ledger)
        finding = Finding(
            finding_id="f-2", title="sqli", anomaly_type="sqli",
            profiles=(_profile(),),
        )
        recorded = integration.record_outcome(
            finding, "confirmed", campaign_id, notes="validated manually"
        )
        assert recorded
        data = ledger.export(campaign_id)
        assert data["outcomes"][0]["result"] == "confirmed"
    finally:
        ledger.close()


def test_advisory_only() -> None:
    integration = _integration()
    signal = Signal(signal_id="s-2", anomaly_type="x", evidence_strength=0.5,
                    novelty=0.5)
    enriched = integration.enrich_signal(signal, WeightingContext("b" * 64))
    assert enriched.passed_through
    assert enriched.mode == "advisory-only (PRISM-L-2)"
    finding = Finding(finding_id="f-3", title="t", anomaly_type="a",
                      profiles=(_profile(),))
    validated = integration.validate_finding(finding)
    assert not validated.blocked
    assert validated.mode == "advisory-only (PRISM-L-2)"


def test_override_requires_justification() -> None:
    state = BrainState(priors={"x": 0.5})
    with pytest.raises(PrismLawError):
        state.with_override("x", 0.9, "")
    overridden = state.with_override("x", 0.9, "operator confirmed live")
    assert overridden.priors["x"] == 0.9
    assert "operator confirmed live" in overridden.justifications["x"]
    assert any("override x" in entry for entry in overridden.history)


def test_integration_bidirectional(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("target.example", "proj")
        integration = _integration(ledger)
        # brain → prism: a signal gets a value weight
        signal = Signal(signal_id="s-3", anomaly_type="sqli_union",
                        evidence_strength=0.9, novelty=0.4)
        enriched = integration.enrich_signal(
            signal, WeightingContext("b" * 64)
        )
        assert enriched.weight.weight > 0.0
        # prism → brain: an outcome lands in the ledger the brain reads
        finding = Finding(finding_id="f-4", title="sqli", anomaly_type="sqli",
                          profiles=(_profile(),))
        integration.record_outcome(finding, "refuted", campaign_id)
        data = ledger.export(campaign_id)
        assert data["outcomes"][0]["result"] == "refuted"
    finally:
        ledger.close()


def test_no_circular_feedback() -> None:
    integration = _integration()
    state = BrainState(priors={"sqli_union": 0.5})
    snapshot = dict(state.priors)
    pattern = _pattern()
    patterns_snapshot = (pattern.samples, pattern.successes,
                         pattern.confidence)
    new_state = integration.apply_priors(state, [pattern])
    # the input BrainState is untouched; a new object came back
    assert state.priors == snapshot
    assert new_state is not state
    assert new_state.priors["sqli_union"] != snapshot["sqli_union"]
    # the input pattern is untouched too
    assert (pattern.samples, pattern.successes, pattern.confidence) \
        == patterns_snapshot


# -- U-PRISM-12: metrics ------------------------------------------------------------------

def _obs(phase: str, accepted: bool, score: float,
         avoided: bool = False, recorded_on: str = "2026-10-18") -> Observation:
    return Observation(
        phase=phase, accepted=accepted,
        time_hours=1.0 if not accepted else 0.5,
        evidence_score=score, rabbit_hole_avoided=avoided,
        recorded_on=recorded_on,
    )


def _engine() -> MetricsEngine:
    engine = MetricsEngine()
    # before: mediocre signal, plenty of noise
    for _ in range(4):
        engine.record(_obs("before", True, 0.5))
    for _ in range(4):
        engine.record(_obs("before", False, 0.4))
    # after: sharper signal, fewer but better acceptances
    for _ in range(6):
        engine.record(_obs("after", True, 0.9))
    for _ in range(2):
        engine.record(_obs("after", False, 0.3))
    for _ in range(3):
        engine.record(_obs("after", True, 0.8, avoided=True))
    return engine


def test_metrics_computed() -> None:
    metrics = _engine().compute(NOW)
    assert 0.0 <= metrics.acceptance_before <= 1.0
    assert 0.0 <= metrics.acceptance_after <= 1.0
    assert metrics.avg_evidence_score_after > metrics.avg_evidence_score_before
    assert metrics.rabbit_holes_avoided == 3
    assert "signal_to_noise" in metrics.methodology


def test_improvement_calculated() -> None:
    metrics = _engine().compute(NOW)
    assert metrics.improvement_pct > 0.0
    assert metrics.acceptance_after > metrics.acceptance_before


def test_baseline_comparison() -> None:
    flat_engine = MetricsEngine()
    for _ in range(4):
        flat_engine.record(_obs("before", True, 0.5))
        flat_engine.record(_obs("before", False, 0.4))
        flat_engine.record(_obs("after", True, 0.5))
        flat_engine.record(_obs("after", False, 0.4))
    baseline = flat_engine.compute(NOW)
    report = flat_engine.compare_to_baseline(baseline, baseline)
    assert report.verdict == "flat"
    better = MetricsEngine()
    for _ in range(8):
        better.record(_obs("before", True, 0.5))
    for _ in range(8):
        better.record(_obs("after", True, 0.9))
    current = better.compute(NOW)
    report = flat_engine.compare_to_baseline(baseline, current)
    assert report.verdict == "improved"
    assert report.evidence_score_delta > 0.0


def test_export_valid(tmp_path: Path) -> None:
    engine = _engine()
    path = tmp_path / "metrics" / "export.json"
    engine.export(path, NOW)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "metrics" in data and "observations" in data
    assert data["metrics"]["methodology"] == data["methodology"]


def test_metrics_persist(tmp_path: Path) -> None:
    engine = _engine()
    path = tmp_path / "metrics.json"
    engine.export(path, NOW)
    reloaded = MetricsEngine.load(path)
    first = engine.compute(NOW).to_dict()
    second = reloaded.compute(NOW).to_dict()
    assert first == second


def test_metrics_deterministic() -> None:
    first = _engine().compute(NOW).to_dict()
    second = _engine().compute(NOW).to_dict()
    assert first == second


def test_no_metrics_without_data() -> None:
    engine = MetricsEngine()
    with pytest.raises(PrismLawError):
        engine.compute(NOW)
    stale = MetricsEngine()
    stale.record(_obs("before", True, 0.5, recorded_on="2026-01-01"))
    with pytest.raises(PrismLawError):
        stale.compute(NOW, period_days=30)  # outside the window


# -- U-PRISM-13: dashboard ---------------------------------------------------------------------

def _dashboard_kwargs() -> dict:
    engine = _engine()
    metrics = engine.compute(NOW)
    pattern = _pattern(samples=10, successes=8)
    return {
        "metrics": metrics,
        "patterns": [pattern],
        "tier_distribution": {"A": 2, "B": 5, "F": 1},
        "ranked_signals": [("s-1", 0.81), ("s-2", 0.44)],
        "rabbit_holes_avoided": 3,
    }


def test_dashboard_renders() -> None:
    text = render_dashboard(**_dashboard_kwargs())
    assert PREAMBLE_LINE in text
    assert "signals" in text and "patterns" in text
    assert "pat" * 4 in text
    assert "A: 2" in text


def test_metrics_display() -> None:
    text = render_dashboard(**_dashboard_kwargs())
    assert "acceptance" in text
    assert "avg evidence score" in text
    assert "time per finding" in text


def test_export_valid_dashboard(tmp_path: Path) -> None:
    from webpent.prism.dashboard import export_dashboard
    path = tmp_path / "dash.txt"
    text = export_dashboard(path, **_dashboard_kwargs())
    assert path.read_text(encoding="utf-8") == text
    assert "PRISM advisory" in text


def test_audit_log_written(tmp_path: Path) -> None:
    log_path = tmp_path / "audit" / "violations.log"
    detector = SilentFailureDetector(log_path=log_path)
    flow = AuditFlow(
        findings=(
            AuditedFinding(finding_id="f-1",
                           has_evidence_profile=False, has_score=False,
                           score_has_reason=False),
        ),
    )
    violations = detector.audit(flow)
    detector.enforce_all(violations)
    assert log_path.exists()
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(violations)
    assert all(line.count("|") == 3 for line in lines)


def test_advisory_only_enforced() -> None:
    text = render_dashboard(**_dashboard_kwargs())
    assert PREAMBLE_LINE in text
    assert "never blocks" in text


# -- U-PRISM-14: cold start -----------------------------------------------------------------------

FEATURES = {
    "industry": "fintech", "api": "true", "mobile": "true",
}


def test_plan_generated_for_new_target() -> None:
    accel = ColdStartAccelerator(ARCHETYPES)
    plan = accel.plan("new-target", FEATURES)
    assert plan.target_id == "new-target"
    assert plan.recommended_techniques
    assert plan.recommended_priorities
    assert plan.mode == "advisory-only (PRISM-L-2)"


def test_archetype_matching() -> None:
    accel = ColdStartAccelerator(ARCHETYPES)
    matches = accel.match_archetypes(FEATURES)
    assert matches
    assert matches[0][0].name == "fintech_api"
    assert matches[0][1] == pytest.approx(1.0)


def test_recommendations_from_matched_archetype() -> None:
    accel = ColdStartAccelerator(ARCHETYPES)
    plan = accel.plan("new-target", FEATURES)
    union: set[str] = set()
    for archetype in accel.archetypes:
        if archetype.name in plan.matched_archetypes:
            union.update(archetype.typical_techniques)
    assert plan.recommended_techniques
    assert set(plan.recommended_techniques) <= union


def test_confidence_based_on_match_quality() -> None:
    accel = ColdStartAccelerator(ARCHETYPES)
    full = accel.plan("new-target", FEATURES)
    # an unrelated extra feature dilutes the match coverage
    partial = accel.plan("new-target", {"industry": "fintech",
                                        "unrelated": "x"})
    assert partial.confidence < full.confidence
    assert 0.0 < partial.confidence <= 1.0


def test_time_estimate_reasonable() -> None:
    accel = ColdStartAccelerator(ARCHETYPES)
    plan = accel.plan("new-target", FEATURES)
    estimate = accel.estimate_first_finding_time(plan)
    assert 0.0 < estimate <= 4.0


def test_no_plan_without_data() -> None:
    accel = ColdStartAccelerator(ARCHETYPES)
    with pytest.raises(PrismLawError):
        accel.plan("new-target", {"quantum": "flux"})


def test_deterministic_plan() -> None:
    accel = ColdStartAccelerator(ARCHETYPES)
    first = accel.plan("new-target", FEATURES).to_dict()
    second = accel.plan("new-target", FEATURES).to_dict()
    assert first == second


# -- U-PRISM-15: compliance ------------------------------------------------------------

def test_detects_unscored_finding() -> None:
    detector = SilentFailureDetector()
    flow = AuditFlow(findings=(
        AuditedFinding(finding_id="f-1", has_evidence_profile=False,
                       has_score=False, score_has_reason=False),
    ))
    violations = detector.audit(flow)
    assert len(violations) == 1
    assert violations[0].type == "unscored_finding"
    assert violations[0].auto_action == "block"


def test_detects_unlogged_score() -> None:
    detector = SilentFailureDetector()
    flow = AuditFlow(findings=(
        AuditedFinding(finding_id="f-1", has_evidence_profile=True,
                       has_score=False, score_has_reason=False),
    ))
    violations = detector.audit(flow)
    assert [v.type for v in violations] == ["unlogged_score"]


def test_detects_missing_justification() -> None:
    detector = SilentFailureDetector()
    flow = AuditFlow(findings=(
        AuditedFinding(finding_id="f-1", has_evidence_profile=True,
                       has_score=True, score_has_reason=False),
    ))
    violations = detector.audit(flow)
    assert [v.type for v in violations] == ["missing_justification"]


def test_detects_unpatterned_adjustment() -> None:
    detector = SilentFailureDetector()
    flow = AuditFlow(adjustments=(
        AuditedAdjustment(adjustment_id="adj-1", has_pattern_id=False),
    ))
    violations = detector.audit(flow)
    assert [v.type for v in violations] == ["unpatterned_adjustment"]


def test_detects_undersampled_pattern() -> None:
    detector = SilentFailureDetector()
    flow = AuditFlow(patterns=(
        AuditedPattern(pattern_id="p-1", samples=3),
    ))
    violations = detector.audit(flow)
    assert [v.type for v in violations] == ["undersampled_pattern"]
    assert violations[0].severity == "medium"


def test_detects_unlogged_decision() -> None:
    detector = SilentFailureDetector()
    flow = AuditFlow(findings=(
        AuditedFinding(finding_id="f-1", has_evidence_profile=True,
                       has_score=True, score_has_reason=True,
                       has_decision=True, decision_logged=False),
    ))
    violations = detector.audit(flow)
    assert [v.type for v in violations] == ["unlogged_decision"]


def test_no_false_positives() -> None:
    detector = SilentFailureDetector()
    flow = AuditFlow(
        findings=(
            AuditedFinding(finding_id="f-1", has_evidence_profile=True,
                           has_score=True, score_has_reason=True,
                           has_decision=True, decision_logged=True),
            AuditedFinding(finding_id="f-2", has_evidence_profile=True,
                           has_score=True, score_has_reason=True,
                           has_decision=False, decision_logged=False),
        ),
        adjustments=(AuditedAdjustment("adj-1", True),),
        patterns=(AuditedPattern("p-1", 12),),
    )
    assert detector.audit(flow) == []


def test_all_violations_logged(tmp_path: Path) -> None:
    detector = SilentFailureDetector(log_path=tmp_path / "audit.log")
    flow = AuditFlow(
        findings=(
            AuditedFinding(finding_id="f-1", has_evidence_profile=False,
                           has_score=False, score_has_reason=False),
            AuditedFinding(finding_id="f-2", has_evidence_profile=True,
                           has_score=False, score_has_reason=False),
        ),
        adjustments=(AuditedAdjustment("adj-1", False),),
        patterns=(AuditedPattern("p-1", 2),),
    )
    violations = detector.audit(flow)
    detector.enforce_all(violations)
    stats = detector.get_violation_stats()
    assert stats["total"] == len(violations)
    assert sum(stats["by_type"].values()) == stats["total"]
    assert "unscored_finding" in stats["by_type"]


def test_audit_deterministic() -> None:
    detector = SilentFailureDetector()
    flow = AuditFlow(findings=(
        AuditedFinding(finding_id="f-1", has_evidence_profile=False,
                       has_score=False, score_has_reason=False),
    ))
    first = [v.to_dict() for v in detector.audit(flow)]
    second = [v.to_dict() for v in detector.audit(flow)]
    assert first == second


def test_audit_or_raise_blocks_silent_failures() -> None:
    detector = SilentFailureDetector()
    bad = AuditFlow(findings=(
        AuditedFinding(finding_id="f-1", has_evidence_profile=False,
                       has_score=False, score_has_reason=False),
    ))
    with pytest.raises(PrismLawError):
        detector.audit_or_raise(bad)
    good = AuditFlow(findings=(
        AuditedFinding(finding_id="f-2", has_evidence_profile=True,
                       has_score=True, score_has_reason=True,
                       has_decision=True, decision_logged=True),
    ))
    assert detector.audit_or_raise(good) == []
