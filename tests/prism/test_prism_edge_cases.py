"""v89 PRISM — edge-case tests across all 15 units (laws, validation,
determinism, ledger integrity, config floors)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from webpent.prism.anomaly_filter import AnomalyFilter, FilterContext, RawAnomaly
from webpent.prism.classifier import EvidenceClassifier
from webpent.prism.cold_start import ColdStartAccelerator
from webpent.prism.compliance import (
    AuditedFinding,
    AuditFlow,
    SilentFailureDetector,
)
from webpent.prism.dashboard import export_dashboard, render_dashboard
from webpent.prism.errors import PrismLawError
from webpent.prism.integration import BrainState, Finding, PrismIntegration
from webpent.prism.ledger import CampaignLedger
from webpent.prism.metrics import MetricsEngine, Observation
from webpent.prism.patterns import Pattern, PatternExtractor, _confidence
from webpent.prism.priors import PriorAdjuster
from webpent.prism.rabbit_hole import (
    ExplorationState,
    RabbitHoleProtector,
)
from webpent.prism.rabbit_hole import (
    Signal as HoleSignal,
)
from webpent.prism.scorer import EvidenceScorer
from webpent.prism.taxonomy import EvidenceTaxonomy
from webpent.prism.tiering import MultiSignalIntegrator
from webpent.prism.value_weighter import (
    Signal,
    ValueWeighter,
    WeightingContext,
)

WORK = Path(__file__).resolve().parents[2]
TAXONOMY = WORK / "config" / "prism" / "taxonomy.yaml"
CLASSIFIER = WORK / "config" / "prism" / "classifier_patterns.yaml"
SCORER = WORK / "config" / "prism" / "scorer_weights.yaml"
LEARNING = WORK / "config" / "prism" / "learning_params.yaml"
CURIOSITY = WORK / "config" / "prism" / "curiosity_params.yaml"
ARCHETYPES = WORK / "config" / "prism" / "archetypes.yaml"

NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)


def _profile(evidence_hash: str = "a" * 64, **overrides):
    taxonomy = EvidenceTaxonomy(TAXONOMY)
    kwargs = {
        "evidence_hash": evidence_hash, "source": "probe",
        "signal_kind": "direct_response", "strength": "strong",
        "reproducibility": "deterministic",
        "corroboration": "independent_multiple", "rationale": "edge case",
    }
    kwargs.update(overrides)
    return taxonomy.profile(**kwargs)


def _score(profile=None):
    scorer = EvidenceScorer(SCORER, EvidenceTaxonomy(TAXONOMY))
    return scorer.score(profile if profile is not None else _profile())


# -- taxonomy / scorer (PRISM-L-1) -------------------------------------------------------

def test_profile_requires_evidence_hash() -> None:
    taxonomy = EvidenceTaxonomy(TAXONOMY)
    with pytest.raises(PrismLawError):
        taxonomy.profile(
            evidence_hash="", source="probe",
            signal_kind="direct_response", strength="strong",
            reproducibility="deterministic",
            corroboration="independent_multiple", rationale="r",
        )


def test_profile_requires_rationale() -> None:
    taxonomy = EvidenceTaxonomy(TAXONOMY)
    with pytest.raises(PrismLawError):
        taxonomy.profile(
            evidence_hash="a" * 64, source="probe",
            signal_kind="direct_response", strength="strong",
            reproducibility="deterministic",
            corroboration="independent_multiple", rationale="",
        )


def test_profile_rejects_unknown_source() -> None:
    with pytest.raises(PrismLawError):
        _profile(source="not_a_source")


def test_profile_rejects_unknown_signal_kind() -> None:
    with pytest.raises(PrismLawError):
        _profile(signal_kind="quantum_flux")


def test_profile_is_deterministic() -> None:
    first = _profile()
    second = _profile()
    assert first.to_dict() == second.to_dict()


def test_score_components_are_earned_and_hashed() -> None:
    result = _score()
    assert 0.0 <= result.score <= 1.0
    assert result.components
    assert result.formula
    assert result.rationale
    assert result.evidence_hash == "a" * 64


# -- classifier (PRISM-L-4) --------------------------------------------------------------

def test_classifier_rejects_empty_observation() -> None:
    classifier = EvidenceClassifier(CLASSIFIER, EvidenceTaxonomy(TAXONOMY))
    with pytest.raises(PrismLawError):
        classifier.classify_observation({})


def test_classifier_rejects_unmatched_observation() -> None:
    classifier = EvidenceClassifier(CLASSIFIER, EvidenceTaxonomy(TAXONOMY))
    with pytest.raises(PrismLawError):
        classifier.classify_observation({"unrelated": "x"})


def test_classifier_maps_attempts_to_reproducibility() -> None:
    classifier = EvidenceClassifier(CLASSIFIER, EvidenceTaxonomy(TAXONOMY))
    base = {"reflected": True, "status_code": 200}
    for attempts, expected in [
        (1, "single_shot"), (2, "repeatable"), (10, "deterministic"),
    ]:
        classification = classifier.classify_observation(
            {**base, "attempts": attempts}
        )
        assert classification.reproducibility.value == expected
        assert classification.pattern_id == "direct_reflection_proven"


def test_classifier_full_pipeline_profiles_observation() -> None:
    classifier = EvidenceClassifier(CLASSIFIER, EvidenceTaxonomy(TAXONOMY))
    profile = classifier.profile_observation(
        {"reflected": True, "status_code": 404, "attempts": 3}, "b" * 64
    )
    assert profile.evidence_hash == "b" * 64
    assert profile.rationale
    assert profile.source == "crawler"  # default source from observation


def test_classifier_pattern_count_positive() -> None:
    classifier = EvidenceClassifier(CLASSIFIER, EvidenceTaxonomy(TAXONOMY))
    assert classifier.pattern_count >= 1


# -- tiering ------------------------------------------------------------------------------

def test_integrate_zero_signals_is_illegal() -> None:
    integrator = MultiSignalIntegrator(SCORER)
    with pytest.raises(PrismLawError):
        integrator.integrate([])


def test_integrate_is_deterministic() -> None:
    integrator = MultiSignalIntegrator(SCORER)
    signals = [(_profile(), _score())]
    first = integrator.integrate(signals).to_dict()
    second = integrator.integrate(signals).to_dict()
    assert first == second


def test_integrate_records_signal_count() -> None:
    integrator = MultiSignalIntegrator(SCORER)
    scorer = EvidenceScorer(SCORER, EvidenceTaxonomy(TAXONOMY))
    signals = [
        (_profile(), scorer.score(_profile())),
        (_profile(evidence_hash="d" * 64),
         scorer.score(_profile(evidence_hash="d" * 64))),
    ]
    result = integrator.integrate(signals)
    assert result.signal_count == 2


def test_higher_score_never_gives_lower_verdict() -> None:
    integrator = MultiSignalIntegrator(SCORER)
    taxonomy = EvidenceTaxonomy(TAXONOMY)
    scorer = EvidenceScorer(SCORER, taxonomy)
    weak = integrator.integrate([
        (taxonomy.profile(
            evidence_hash="c" * 64, source="crawler",
            signal_kind="direct_response", strength="weak",
            reproducibility="single_shot", corroboration="uncorroborated",
            rationale="weak case",
        ), scorer.score(taxonomy.profile(
            evidence_hash="c" * 64, source="crawler",
            signal_kind="direct_response", strength="weak",
            reproducibility="single_shot", corroboration="uncorroborated",
            rationale="weak case",
        ))),
    ])
    strong = integrator.integrate([(_profile(), _score())])
    order = ["noise", "weak", "possible", "likely", "confirmed"]
    assert order.index(strong.verdict) >= order.index(weak.verdict)


def test_conflicts_retain_both_sides_for_audit() -> None:
    integrator = MultiSignalIntegrator(SCORER)
    taxonomy = EvidenceTaxonomy(TAXONOMY)
    scorer = EvidenceScorer(SCORER, taxonomy)
    conflicting = [
        taxonomy.profile(
            evidence_hash="c" * 64, source="probe",
            signal_kind="direct_response", strength="decisive",
            reproducibility="deterministic",
            corroboration="independent_multiple", rationale="hit",
        ),
        taxonomy.profile(
            evidence_hash="d" * 64, source="probe",
            signal_kind="behavior_diff", strength="decisive",
            reproducibility="deterministic",
            corroboration="independent_multiple",
            rationale="behavior contradicts the direct signal",
        ),
    ]
    signals = [(p, scorer.score(p)) for p in conflicting]
    result = integrator.integrate(signals)
    for record in result.conflicts:
        assert record["winner"] and record["loser"]
        assert record["resolution"]


# -- ledger (PRISM-L-6: redaction) ---------------------------------------------------------

def test_campaign_target_stored_hashed_only(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("secret-target.example", "proj")
        record = ledger.get_campaign(campaign_id)
        assert "secret-target.example" not in record.target_hash
        data = ledger.export(campaign_id)
        assert "secret-target.example" not in json.dumps(data)
    finally:
        ledger.close()


def test_unknown_campaign_fails_fast(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        with pytest.raises(PrismLawError):
            ledger.get_campaign("nope")
    finally:
        ledger.close()


def test_outcome_result_whitelist(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("target.example", "proj")
        evidence_id = ledger.record_evidence(
            campaign_id, _profile(), _score()
        )
        with pytest.raises(PrismLawError):
            ledger.record_outcome(campaign_id, evidence_id, "maybe")
    finally:
        ledger.close()


def test_outcome_requires_known_evidence(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("target.example", "proj")
        with pytest.raises(PrismLawError):
            ledger.record_outcome(campaign_id, "ghost", "confirmed")
    finally:
        ledger.close()


def test_adjustment_requires_reason(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("target.example", "proj")
        with pytest.raises(PrismLawError):
            ledger.record_adjustment(
                campaign_id, "pat-1", 0.1, "", 0.8
            )
    finally:
        ledger.close()


def test_export_json_round_trip(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("target.example", "proj")
        ledger.record_adjustment(
            campaign_id, "pat-1", 0.12, "5/6 confirmed outcomes", 0.86
        )
        data = json.loads(ledger.export_json(campaign_id))
        assert data["adjustments"][0]["pattern_id"] == "pat-1"
        assert data["schema_version"]
    finally:
        ledger.close()


def test_duplicate_outcomes_are_ignored(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("target.example", "proj")
        evidence_id = ledger.record_evidence(
            campaign_id, _profile(), _score()
        )
        first = ledger.record_outcome(campaign_id, evidence_id, "confirmed")
        second = ledger.record_outcome(campaign_id, evidence_id, "confirmed")
        assert first == second
        data = ledger.export(campaign_id)
        assert len(data["outcomes"]) == 1
    finally:
        ledger.close()


# -- patterns / priors (PRISM-L-3) ---------------------------------------------------------

def _records(technique: str = "sqli_union", outcome: str = "confirmed",
             n: int = 6) -> list[dict]:
    return [
        {"technique": technique, "signal_kind": "direct_response",
         "stack": "nginx", "family": "sqli", "archetype": "fintech_api",
         "outcome": outcome}
        for _ in range(n)
    ]


def test_extract_below_min_samples_is_empty() -> None:
    extractor = PatternExtractor(LEARNING)
    assert extractor.extract(_records(n=4), NOW) == []


def test_extraction_is_deterministic() -> None:
    extractor = PatternExtractor(LEARNING)
    records = _records()
    first = [p.to_dict() for p in extractor.extract(records, NOW)]
    second = [p.to_dict() for p in extractor.extract(records, NOW)]
    assert first == second


def test_pattern_confidence_grows_with_samples() -> None:
    assert _confidence(10) > _confidence(5)
    assert _confidence(100) > _confidence(10)


def test_prior_rejects_baseline_out_of_range() -> None:
    adjuster = PriorAdjuster(LEARNING)
    extractor = PatternExtractor(LEARNING)
    pattern = extractor.extract(_records(), NOW)[0]
    with pytest.raises(PrismLawError):
        adjuster.adjust(1.5, pattern, {"technique": pattern.key})


def test_prior_rejects_mismatched_context() -> None:
    adjuster = PriorAdjuster(LEARNING)
    extractor = PatternExtractor(LEARNING)
    pattern = extractor.extract(_records(), NOW)[0]
    with pytest.raises(PrismLawError):
        adjuster.adjust(0.5, pattern, {"technique": "other_technique"})


def test_prior_delta_is_capped() -> None:
    adjuster = PriorAdjuster(LEARNING)
    extractor = PatternExtractor(LEARNING)
    records = _records(outcome="confirmed", n=20)
    patterns = [
        p for p in extractor.extract(records, NOW)
        if p.pattern_type == "technique_effectiveness"
    ]
    pattern = patterns[0]
    adjustment = adjuster.adjust(0.1, pattern, {"technique": pattern.key})
    assert abs(adjustment.delta) <= adjuster.adjustment_cap


def test_prior_requires_reasonful_pattern() -> None:
    adjuster = PriorAdjuster(LEARNING)
    extractor = PatternExtractor(LEARNING)
    patterns = [
        p for p in extractor.extract(_records(), NOW)
        if p.pattern_type == "technique_effectiveness"
    ]
    pattern = patterns[0]
    broken = Pattern(
        pattern_id=pattern.pattern_id,
        pattern_type=pattern.pattern_type, key=pattern.key,
        samples=pattern.samples, successes=pattern.successes,
        success_rate=pattern.success_rate,
        confidence=pattern.confidence, updated_at=pattern.updated_at,
        reason="",
    )
    with pytest.raises(PrismLawError):
        adjuster.adjust(0.5, broken, {"technique": pattern.key})


# -- anomaly filter ------------------------------------------------------------------------

def test_filter_requires_anomaly_id() -> None:
    f = AnomalyFilter(CURIOSITY)
    with pytest.raises(PrismLawError):
        f.filter(
            RawAnomaly(anomaly_id="", anomaly_type="x", raw={}),
            FilterContext(target_hash="b" * 64),
        )


def test_filter_requires_anomaly_type() -> None:
    f = AnomalyFilter(CURIOSITY)
    with pytest.raises(PrismLawError):
        f.filter(
            RawAnomaly(anomaly_id="a", anomaly_type="", raw={}),
            FilterContext(target_hash="b" * 64),
        )


def test_cost_grows_with_requests() -> None:
    f = AnomalyFilter(CURIOSITY)
    context = FilterContext(target_hash="b" * 64)
    cheap = f.filter(
        RawAnomaly(anomaly_id="a", anomaly_type="x",
                   raw={"estimated_requests": 1, "estimated_impact": 0.5}),
        context,
    )
    dear = f.filter(
        RawAnomaly(anomaly_id="a", anomaly_type="x",
                   raw={"estimated_requests": 40, "estimated_impact": 0.5}),
        context,
    )
    assert dear.estimated_value < cheap.estimated_value


def test_explicit_context_match_beats_defaults() -> None:
    f = AnomalyFilter(CURIOSITY)
    context = FilterContext(target_hash="b" * 64)
    explicit = f.filter(
        RawAnomaly(anomaly_id="a", anomaly_type="x",
                   raw={"context_match": 1.0, "estimated_impact": 0.5}),
        context,
    )
    default = f.filter(
        RawAnomaly(anomaly_id="a", anomaly_type="x",
                   raw={"estimated_impact": 0.5}),
        context,
    )
    assert explicit.estimated_value > default.estimated_value
    assert "context_match=1.000" in explicit.reasoning


def test_filter_decision_arithmetic_is_published() -> None:
    f = AnomalyFilter(CURIOSITY)
    result = f.filter(
        RawAnomaly(anomaly_id="a", anomaly_type="x",
                   raw={"estimated_requests": 2, "estimated_impact": 0.5}),
        FilterContext(target_hash="b" * 64),
    )
    assert "prior=" in result.reasoning
    assert "0.600 × value" in result.reasoning or "0.6" in result.reasoning


# -- value weighter -------------------------------------------------------------------------

def test_rank_orders_by_weight() -> None:
    weighter = ValueWeighter(CURIOSITY)
    context = WeightingContext("b" * 64)
    signals = [
        Signal(signal_id="low", anomaly_type="x", evidence_strength=0.1,
               novelty=0.1),
        Signal(signal_id="high", anomaly_type="x", evidence_strength=0.9,
               novelty=0.9),
    ]
    ranked = weighter.rank(signals, context)
    assert ranked[0].signal_id == "high"
    assert ranked[0].weight >= ranked[-1].weight


def test_confidence_interval_tightens_with_evidence() -> None:
    weighter = ValueWeighter(CURIOSITY)
    context = WeightingContext("b" * 64)
    strong = weighter.weight(
        Signal(signal_id="s", anomaly_type="x", evidence_strength=0.95,
               novelty=0.5), context,
    )
    weak = weighter.weight(
        Signal(signal_id="s", anomaly_type="x", evidence_strength=0.05,
               novelty=0.5), context,
    )
    strong_width = strong.confidence_interval[1] \
        - strong.confidence_interval[0]
    weak_width = weak.confidence_interval[1] - weak.confidence_interval[0]
    assert strong_width < weak_width


def test_recommendation_thresholds_honored() -> None:
    weighter = ValueWeighter(CURIOSITY)
    hot_context = WeightingContext(
        "b" * 64, priors={"x": 1.0}, historical={"x": 1.0},
        explicit_context_match=1.0,
    )
    hot = weighter.weight(
        Signal(signal_id="s", anomaly_type="x", evidence_strength=1.0,
               novelty=1.0), hot_context,
    )
    cold = weighter.weight(
        Signal(signal_id="s", anomaly_type="x", evidence_strength=0.0,
               novelty=0.0), WeightingContext("b" * 64),
    )
    assert hot.recommendation == "prioritize"
    assert cold.recommendation in {"backlog", "drop"}


def test_explanation_publishes_all_components() -> None:
    weighter = ValueWeighter(CURIOSITY)
    context = WeightingContext("b" * 64)
    weight = weighter.weight(
        Signal(signal_id="s", anomaly_type="x", evidence_strength=0.5,
               novelty=0.5), context,
    )
    for component in weight.components:
        assert component in weight.explanation


def test_weights_stay_in_unit_interval() -> None:
    weighter = ValueWeighter(CURIOSITY)
    context = WeightingContext("b" * 64)
    for strength in (0.0, 0.25, 0.5, 0.75, 1.0):
        for novelty in (0.0, 0.5, 1.0):
            weight = weighter.weight(
                Signal(signal_id="s", anomaly_type="x",
                       evidence_strength=strength, novelty=novelty),
                context,
            )
            assert 0.0 <= weight.weight <= 1.0


# -- rabbit holes ---------------------------------------------------------------------------

PROTECTOR = RabbitHoleProtector(CURIOSITY)


def _state(**overrides) -> ExplorationState:
    kwargs = {
        "depth": 1, "time_spent_hours": 0.1, "requests_spent": 2,
        "recent_new_evidence": (True,), "reason_for_continuing": "fresh",
    }
    kwargs.update(overrides)
    return ExplorationState(**kwargs)


def test_healthy_exploration_continues() -> None:
    result = PROTECTOR.check(
        HoleSignal(signal_id="s", anomaly_type="authz"), _state()
    )
    assert not result.is_hole
    assert result.recommendation == "continue"


def test_depth_rule_triggers() -> None:
    result = PROTECTOR.check(
        HoleSignal(signal_id="s", anomaly_type="authz"),
        _state(depth=PROTECTOR.max_depth + 1),
    )
    assert result.is_hole
    assert result.recommendation == "pause"


def test_time_rule_triggers() -> None:
    result = PROTECTOR.check(
        HoleSignal(signal_id="s", anomaly_type="authz"),
        _state(time_spent_hours=PROTECTOR.max_time_hours + 0.1),
    )
    assert result.is_hole


def test_diminishing_returns_rule_triggers() -> None:
    result = PROTECTOR.check(
        HoleSignal(signal_id="s", anomaly_type="authz"),
        _state(recent_new_evidence=(False, False, False)),
    )
    assert result.is_hole
    assert result.diminishing_returns


def test_sunk_cost_language_triggers() -> None:
    result = PROTECTOR.check(
        HoleSignal(signal_id="s", anomaly_type="authz"),
        _state(reason_for_continuing="we already spent so much here"),
    )
    assert result.is_hole
    assert result.sunk_cost_warning


def test_known_hole_pattern_abandons() -> None:
    result = PROTECTOR.check(
        HoleSignal(signal_id="s", anomaly_type="endless_subdomain_enum"),
        _state(),
    )
    assert result.is_hole
    assert result.recommendation == "abandon"


def test_check_to_dict_round_trip() -> None:
    result = PROTECTOR.check(
        HoleSignal(signal_id="s", anomaly_type="authz"), _state()
    )
    data = result.to_dict()
    assert data["signal_id"] == "s"
    assert data["mode"] == "advisory-only (PRISM-L-2)"


# -- integration ------------------------------------------------------------------------------

def _integration(ledger: CampaignLedger | None = None) -> PrismIntegration:
    taxonomy = EvidenceTaxonomy(TAXONOMY)
    return PrismIntegration(
        taxonomy, EvidenceScorer(SCORER, taxonomy),
        MultiSignalIntegrator(SCORER), ValueWeighter(CURIOSITY),
        PriorAdjuster(LEARNING), ledger=ledger,
    )


def test_validate_finding_requires_profiles() -> None:
    # F-008 fix: refusal is returned, never raised — the Prism never
    # blocks a finding (PRISM-L-2); an unscored finding passes through
    # unvalidated with verdict "refused".
    integration = _integration()
    result = integration.validate_finding(
        Finding(finding_id="f", title="t", anomaly_type="a", profiles=())
    )
    assert result.verdict == "refused"
    assert result.blocked is False
    assert result.integrated_score == 0.0
    assert result.reasons


def test_record_outcome_requires_ledger() -> None:
    integration = _integration()
    with pytest.raises(PrismLawError):
        integration.record_outcome(
            Finding(finding_id="f", title="t", anomaly_type="a",
                    profiles=(_profile(),)),
            "confirmed", "campaign-x",
        )


def test_apply_priors_skips_unknown_keys() -> None:
    integration = _integration()
    extractor = PatternExtractor(LEARNING)
    pattern = extractor.extract(_records(), NOW)[0]
    state = BrainState(priors={"unrelated": 0.5})
    new_state = integration.apply_priors(state, [pattern])
    assert new_state.priors == {"unrelated": 0.5}
    assert new_state.history == ()


def test_override_clamps_out_of_range_values() -> None:
    state = BrainState(priors={"x": 0.5})
    high = state.with_override("x", 7.0, "operator confirmed")
    low = state.with_override("x", -2.0, "operator refuted")
    assert high.priors["x"] == 1.0
    assert low.priors["x"] == 0.0


def test_override_preserves_existing_justifications() -> None:
    state = BrainState(priors={"x": 0.5})
    once = state.with_override("x", 0.9, "first reason")
    twice = once.with_override("x", 0.4, "second reason")
    assert twice.justifications["x"] == "second reason"
    assert len(twice.history) == 2


# -- metrics (PRISM-L-10) ---------------------------------------------------------------------

def _observation(phase: str, accepted: bool = True) -> Observation:
    return Observation(phase=phase, accepted=accepted, time_hours=0.5,
                       evidence_score=0.5, rabbit_hole_avoided=False,
                       recorded_on="2026-10-18")


def test_metrics_reject_invalid_phase() -> None:
    engine = MetricsEngine()
    with pytest.raises(PrismLawError):
        engine.record(_observation("during"))


def test_metrics_reject_nonpositive_period() -> None:
    engine = MetricsEngine()
    engine.record(_observation("before"))
    with pytest.raises(PrismLawError):
        engine.compute(NOW, period_days=0)


def test_metrics_reject_empty_data() -> None:
    engine = MetricsEngine()
    with pytest.raises(PrismLawError):
        engine.compute(NOW)


def test_metrics_reject_zero_accepted() -> None:
    engine = MetricsEngine()
    engine.record(_observation("before", accepted=False))
    engine.record(_observation("after", accepted=False))
    with pytest.raises(PrismLawError):
        engine.compute(NOW)


def test_metrics_export_load_round_trip(tmp_path: Path) -> None:
    engine = MetricsEngine()
    for _ in range(3):
        engine.record(_observation("before"))
    for _ in range(3):
        engine.record(_observation("after"))
    path = tmp_path / "metrics.json"
    engine.export(path, NOW)
    reloaded = MetricsEngine.load(path)
    original = engine.compute(NOW).to_dict()
    restored = reloaded.compute(NOW).to_dict()
    assert original == restored


# -- dashboard --------------------------------------------------------------------------------

def test_dashboard_sections_render() -> None:
    text = render_dashboard(
        tier_distribution={"tier2": 3, "tier3": 1},
        ranked_signals=[("s-1", 0.7)],
        rabbit_holes_avoided=4,
    )
    assert "PRISM advisory" in text
    assert "signals" in text
    assert "patterns" in text
    assert "priors" in text
    assert "4" in text


def test_dashboard_export_writes_file(tmp_path: Path) -> None:
    path = tmp_path / "dash.txt"
    text = export_dashboard(path, tier_distribution={"tier2": 2})
    assert path.exists()
    assert text == path.read_text(encoding="utf-8")


def test_dashboard_empty_state_renders() -> None:
    text = render_dashboard()
    assert "PRISM advisory" in text
    assert "(no signals ranked yet)" in text


# -- cold start (PRISM-L-8) -------------------------------------------------------------------

FEATURES = {"industry": "fintech", "interface": "api",
            "auth": "jwt", "rate_limit": "token_bucket"}


def test_empty_features_match_nothing() -> None:
    accel = ColdStartAccelerator(ARCHETYPES)
    assert accel.match_archetypes({}) == []


def test_plan_requires_target_id() -> None:
    accel = ColdStartAccelerator(ARCHETYPES)
    with pytest.raises(PrismLawError):
        accel.plan("", FEATURES)


def test_plan_priorities_cover_all_techniques() -> None:
    accel = ColdStartAccelerator(ARCHETYPES)
    plan = accel.plan("t", FEATURES)
    high = [p for p in plan.recommended_priorities if p.startswith("high:")]
    assert len(high) == 2  # exactly the first two techniques
    assert len(plan.recommended_priorities) == len(
        plan.recommended_techniques
    )


def test_match_ordering_is_deterministic() -> None:
    accel = ColdStartAccelerator(ARCHETYPES)
    first = accel.match_archetypes(FEATURES)
    second = accel.match_archetypes(FEATURES)
    assert [(a.name, s) for a, s in first] == [(a.name, s) for a, s in second]


# -- compliance -------------------------------------------------------------------------------

def test_violation_id_is_stable_per_subject() -> None:
    detector = SilentFailureDetector()
    flow = AuditFlow(findings=(
        AuditedFinding(finding_id="f-1", has_evidence_profile=False,
                       has_score=False, score_has_reason=False),
    ))
    first = detector.audit(flow)[0].violation_id
    second = detector.audit(flow)[0].violation_id
    assert first == second


def test_stats_track_actions() -> None:
    detector = SilentFailureDetector()
    flow = AuditFlow(findings=(
        AuditedFinding(finding_id="f-1", has_evidence_profile=False,
                       has_score=False, score_has_reason=False),
    ))
    detector.enforce_all(detector.audit(flow))
    stats = detector.get_violation_stats()
    assert stats["by_action"] == {"block": 1}


def test_clean_flow_produces_no_violations() -> None:
    detector = SilentFailureDetector()
    flow = AuditFlow(findings=(
        AuditedFinding(finding_id="f-1", has_evidence_profile=True,
                       has_score=True, score_has_reason=True,
                       has_decision=False, decision_logged=False),
    ))
    assert detector.audit(flow) == []
