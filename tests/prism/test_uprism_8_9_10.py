"""v89 PRISM — U-PRISM-8 (anomaly filter), U-PRISM-9 (value weighter),
U-PRISM-10 (rabbit hole protector) tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from webpent.prism.anomaly_filter import (
    AnomalyFilter,
    FilterContext,
    RawAnomaly,
)
from webpent.prism.errors import PrismLawError
from webpent.prism.rabbit_hole import (
    ExplorationState,
    RabbitHoleProtector,
)
from webpent.prism.rabbit_hole import (
    Signal as HoleSignal,
)
from webpent.prism.value_weighter import (
    Signal,
    ValueWeighter,
    WeightingContext,
)

WORK = Path(__file__).resolve().parents[2]
CURIOSITY = WORK / "config" / "prism" / "curiosity_params.yaml"

CTX = FilterContext(target_hash="b" * 64)
WCTX = WeightingContext(target_hash="b" * 64)


# -- U-PRISM-8: anomaly filter -----------------------------------------------------

def _anomaly(**raw) -> RawAnomaly:
    raw.setdefault("estimated_requests", 1)
    return RawAnomaly(anomaly_id="an-1", anomaly_type="sqli_union", raw=raw)


def _hot_anomaly() -> RawAnomaly:
    return _anomaly(estimated_impact=0.9, context_match=0.9)


def test_filter_high_value_anomaly() -> None:
    f = AnomalyFilter(CURIOSITY)
    result = f.filter(
        _hot_anomaly(), CTX, prior=0.9, historical=0.9,
    )
    assert result.decision == "pursue"
    assert result.estimated_value > 0.5
    assert result.mode == "advisory-only (PRISM-L-2)"


def test_filter_low_value_anomaly() -> None:
    f = AnomalyFilter(CURIOSITY)
    result = f.filter(
        _anomaly(estimated_requests=10, estimated_impact=0.1),
        CTX, prior=0.1, historical=0.1,
    )
    assert result.decision == "discard"


def test_historical_success_used() -> None:
    f = AnomalyFilter(CURIOSITY)
    low = f.filter(_hot_anomaly(), CTX, prior=0.5, historical=0.2)
    high = f.filter(_hot_anomaly(), CTX, prior=0.5, historical=0.9)
    assert high.estimated_value > low.estimated_value


def test_context_match_score() -> None:
    f = AnomalyFilter(CURIOSITY)
    proven_ctx = FilterContext(
        target_hash="b" * 64, proven_types=("sqli_union",)
    )
    with_proven = f.filter(
        _anomaly(estimated_impact=0.9), proven_ctx, prior=0.5, historical=0.5
    )
    with_default = f.filter(
        _anomaly(estimated_impact=0.9), CTX, prior=0.5, historical=0.5
    )
    assert with_proven.estimated_value > with_default.estimated_value


def test_cost_estimation() -> None:
    f = AnomalyFilter(CURIOSITY)
    cheap = f.filter(_anomaly(estimated_requests=1), CTX,
                     prior=0.5, historical=0.5)
    pricey = f.filter(_anomaly(estimated_requests=20, estimated_hours=3.0),
                      CTX, prior=0.5, historical=0.5)
    assert cheap.estimated_value > pricey.estimated_value


def test_thresholds_configurable(tmp_path: Path) -> None:
    f = AnomalyFilter(CURIOSITY)
    thresholds = f.get_decision_thresholds()
    assert thresholds["pursue_threshold"] == pytest.approx(0.60)
    custom = tmp_path / "curiosity.yaml"
    custom.write_text(
        "anomaly_filter:\n"
        "  default_prior: 0.3\n"
        "  default_historical: 0.5\n"
        "  default_context_match: 0.4\n"
        "  proven_context_match: 0.8\n"
        "  default_impact: 0.5\n"
        "  pursue_threshold: 0.95\n"
        "  hold_threshold: 0.90\n"
        "  request_cost_step: 0.25\n"
        "  hour_cost_step: 2.0\n",
        encoding="utf-8",
    )
    strict = AnomalyFilter(custom)
    assert strict.get_decision_thresholds()["pursue_threshold"] == 0.95
    # the same anomaly that pursues under defaults only holds here
    result = strict.filter(_hot_anomaly(), CTX, prior=0.9, historical=0.9)
    assert result.decision in ("hold", "discard")


def test_reasoning_always_present() -> None:
    f = AnomalyFilter(CURIOSITY)
    for prior in (0.1, 0.5, 0.9):
        result = f.filter(_hot_anomaly(), CTX, prior=prior, historical=0.5)
        assert result.reasoning
        assert "combined" in result.reasoning


def test_batch_filter_consistent() -> None:
    f = AnomalyFilter(CURIOSITY)
    anomalies = [_hot_anomaly(), _anomaly(estimated_impact=0.1)]
    batch = f.batch_filter(anomalies, CTX)
    single = [f.filter(a, CTX) for a in anomalies]
    assert [b.to_dict() for b in batch] == [s.to_dict() for s in single]


def test_deterministic() -> None:
    f = AnomalyFilter(CURIOSITY)
    first = f.filter(_hot_anomaly(), CTX, prior=0.7, historical=0.7)
    second = f.filter(_hot_anomaly(), CTX, prior=0.7, historical=0.7)
    assert first.to_dict() == second.to_dict()


def test_no_learned_prior_uses_default() -> None:
    f = AnomalyFilter(CURIOSITY)
    # no prior passed → the config default (0.3) is used, visible in reasoning
    result = f.filter(_hot_anomaly(), CTX)
    assert "prior=0.300" in result.reasoning


# -- U-PRISM-9: value weighter -------------------------------------------------------

def _signal(**overrides) -> Signal:
    values = {
        "signal_id": "sig-1", "anomaly_type": "sqli_union",
        "evidence_strength": 0.8, "novelty": 0.3,
        "estimated_requests": 1, "detection_risk": 0.1,
    }
    values.update(overrides)
    return Signal(**values)


def test_weight_all_components() -> None:
    w = ValueWeighter(CURIOSITY)
    result = w.weight(_signal(), WCTX)
    assert set(result.components) == set(
        w.component_weights
    )
    assert len(result.components) == 7


def test_ranking_by_weight() -> None:
    w = ValueWeighter(CURIOSITY)
    signals = [
        _signal(signal_id="weak", evidence_strength=0.1),
        _signal(signal_id="strong", evidence_strength=0.9),
        _signal(signal_id="mid", evidence_strength=0.5),
    ]
    ranked = w.rank(signals, WCTX)
    ids = [r.signal_id for r in ranked]
    assert ids == sorted(
        ids, key=lambda i: -next(r.weight for r in ranked
                                 if r.signal_id == i)
    )
    assert ids[0] == "strong"


def test_confidence_interval_computed() -> None:
    w = ValueWeighter(CURIOSITY)
    result = w.weight(_signal(), WCTX)
    low, high = result.confidence_interval
    assert 0.0 <= low <= result.weight <= high <= 1.0


def test_novelty_affects_weight() -> None:
    w = ValueWeighter(CURIOSITY)
    plain = w.weight(_signal(novelty=0.1), WCTX)
    novel = w.weight(_signal(novelty=0.9), WCTX)
    assert novel.weight > plain.weight


def test_risk_penalty_applied() -> None:
    w = ValueWeighter(CURIOSITY)
    quiet = w.weight(_signal(detection_risk=0.0), WCTX)
    loud = w.weight(_signal(detection_risk=0.9), WCTX)
    assert loud.weight < quiet.weight


def test_explanation_readable() -> None:
    w = ValueWeighter(CURIOSITY)
    result = w.weight(_signal(), WCTX)
    text = w.explain(result)
    assert result.signal_id in text
    assert "prior_probability" in text
    assert result.recommendation in text


def test_deterministic_weight() -> None:
    w = ValueWeighter(CURIOSITY)
    assert w.weight(_signal(), WCTX).to_dict() == \
        w.weight(_signal(), WCTX).to_dict()


def test_weights_sum_to_one() -> None:
    w = ValueWeighter(CURIOSITY)
    assert sum(w.component_weights.values()) == pytest.approx(1.0)


def test_edge_cases_handled() -> None:
    w = ValueWeighter(CURIOSITY)
    zero = w.weight(
        _signal(evidence_strength=0.0, novelty=0.0, detection_risk=1.0,
                estimated_requests=1000),
        WCTX,
    )
    assert 0.0 <= zero.weight <= 1.0
    top = w.weight(
        _signal(evidence_strength=1.0, novelty=1.0, detection_risk=0.0),
        WCTX,
    )
    assert 0.0 <= top.weight <= 1.0


# -- U-PRISM-10: rabbit hole protector ------------------------------------------------

def _hole_signal(**overrides) -> HoleSignal:
    values = {"signal_id": "sig-h", "anomaly_type": "sqli_union"}
    values.update(overrides)
    return HoleSignal(**values)


def _healthy_state() -> ExplorationState:
    return ExplorationState(
        depth=2, time_spent_hours=0.1, requests_spent=8,
        recent_new_evidence=(True, True),
        reason_for_continuing="fresh leads each step",
    )


def test_detects_depth_violation() -> None:
    p = RabbitHoleProtector(CURIOSITY)
    deep = ExplorationState(
        depth=6, time_spent_hours=0.1, requests_spent=50,
        recent_new_evidence=(True, True),
    )
    result = p.check(_hole_signal(), deep)
    assert result.is_hole
    assert result.recommendation == "pause"
    assert result.depth == 6


def test_detects_time_violation() -> None:
    p = RabbitHoleProtector(CURIOSITY)
    slow = ExplorationState(
        depth=2, time_spent_hours=1.0, requests_spent=30,
        recent_new_evidence=(True, True),
    )
    result = p.check(_hole_signal(), slow)
    assert result.is_hole
    assert result.recommendation == "pause"


def test_detects_diminishing_returns() -> None:
    p = RabbitHoleProtector(CURIOSITY)
    stuck = ExplorationState(
        depth=3, time_spent_hours=0.2, requests_spent=60,
        recent_new_evidence=(False, False, False),
    )
    result = p.check(_hole_signal(), stuck)
    assert result.is_hole
    assert result.diminishing_returns
    assert result.recommendation == "abandon"


def test_detects_sunk_cost() -> None:
    p = RabbitHoleProtector(CURIOSITY)
    invested = ExplorationState(
        depth=3, time_spent_hours=0.2, requests_spent=80,
        recent_new_evidence=(True, True),
        reason_for_continuing="we already spent 80 requests here",
    )
    result = p.check(_hole_signal(), invested)
    assert result.is_hole
    assert result.sunk_cost_warning
    assert result.recommendation == "abandon"


def test_detects_known_hole() -> None:
    p = RabbitHoleProtector(CURIOSITY)
    result = p.check(
        _hole_signal(anomaly_type="endless_subdomain_enum"),
        _healthy_state(),
    )
    assert result.is_hole
    assert result.recommendation == "abandon"


def test_no_false_positive_on_real_progress() -> None:
    p = RabbitHoleProtector(CURIOSITY)
    result = p.check(_hole_signal(), _healthy_state())
    assert not result.is_hole
    assert not result.diminishing_returns
    assert not result.sunk_cost_warning
    assert result.recommendation == "continue"


def test_recommendation_clear() -> None:
    p = RabbitHoleProtector(CURIOSITY)
    checks = [
        p.check(_hole_signal(), _healthy_state()),
        p.check(_hole_signal(), ExplorationState(
            depth=9, time_spent_hours=0.1, requests_spent=10,
            recent_new_evidence=(True,),
        )),
        p.check(_hole_signal(), ExplorationState(
            depth=2, time_spent_hours=0.2, requests_spent=10,
            recent_new_evidence=(False, False, False),
        )),
    ]
    assert all(c.recommendation in ("continue", "pause", "abandon")
               for c in checks)
    assert checks[0].recommendation == "continue"


def test_reasoning_present() -> None:
    p = RabbitHoleProtector(CURIOSITY)
    for state in (_healthy_state(), ExplorationState(
        depth=7, time_spent_hours=0.1, requests_spent=10,
        recent_new_evidence=(True,),
    )):
        result = p.check(_hole_signal(), state)
        assert result.reasoning


def test_configurable_thresholds(tmp_path: Path) -> None:
    custom = tmp_path / "curiosity.yaml"
    custom.write_text(
        "rabbit_hole:\n"
        "  max_depth: 2\n"
        "  max_time_hours: 0.25\n"
        "  diminishing_window: 2\n"
        "  sunk_cost_markers: [\"already spent\"]\n"
        "known_holes:\n"
        "  - name: endless_subdomain_enum\n"
        "    note: enum without follow-up\n",
        encoding="utf-8",
    )
    p = RabbitHoleProtector(custom)
    assert p.max_depth == 2
    # depth 3 would continue under defaults but pauses here
    result = p.check(_hole_signal(), ExplorationState(
        depth=3, time_spent_hours=0.1, requests_spent=5,
        recent_new_evidence=(True,),
    ))
    assert result.recommendation == "pause"
    # a smaller diminishing window catches a shorter stall too
    stall = p.check(_hole_signal(), ExplorationState(
        depth=2, time_spent_hours=0.1, requests_spent=5,
        recent_new_evidence=(False, False),
    ))
    assert stall.recommendation == "abandon"


def test_rabbit_hole_deterministic() -> None:
    p = RabbitHoleProtector(CURIOSITY)
    state = _healthy_state()
    first = p.check(_hole_signal(), state).to_dict()
    second = p.check(_hole_signal(), state).to_dict()
    assert first == second


def test_protector_missing_config_is_law_error(tmp_path: Path) -> None:
    with pytest.raises(PrismLawError):
        RabbitHoleProtector(tmp_path / "missing.yaml")
    with pytest.raises(PrismLawError):
        AnomalyFilter(tmp_path / "missing.yaml")
    with pytest.raises(PrismLawError):
        ValueWeighter(tmp_path / "missing.yaml")
