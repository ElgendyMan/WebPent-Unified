"""UM-DR-47 Phase W3 — the literal priority formula + sensitivity.

The owner's vision §6 formula, restored by UM-DR-47 after it was
dropped in 46:

    Priority = (ExpectedInformationGain × Impact × Confidence)
               / (Cost + Risk)

Law 47-3 ("Parity is not Proof") applies to the formula itself: the
tests must show the formula behaves EXACTLY as written (multiplicative
numerator, additive denominator) and that CHANGING ANY SINGLE VARIABLE
CHANGES THE RANKING — one sensitivity test per variable.
"""
from __future__ import annotations

import pytest

from webpent.production.brain_engine import (
    BrainPriorityContext,
    estimate_priority_inputs,
    priority_formula,
)


class TestLiteralFormula:
    def test_identity_multiplication_and_division(self):
        # (0.8 × 0.5 × 0.5) / (1.0 + 0.0 + epsilon)
        value = priority_formula(
            expected_information_gain=0.8, impact=0.5,
            confidence=0.5, cost=1.0, risk=0.0,
        )
        assert value == pytest.approx(0.2 / (1.0 + 1e-6), rel=1e-3)

    def test_zero_eig_means_zero_priority(self):
        assert priority_formula(
            expected_information_gain=0.0, impact=1.0,
            confidence=1.0, cost=1.0, risk=0.0,
        ) == pytest.approx(0.0, abs=1e-9)

    def test_zero_cost_zero_risk_is_bounded_not_infinite(self):
        value = priority_formula(
            expected_information_gain=1.0, impact=1.0,
            confidence=1.0, cost=0.0, risk=0.0,
        )
        # 1 / epsilon = 1e6 — huge but finite, never a crash
        assert value == pytest.approx(1e6, rel=1e-3)

    def test_higher_cost_lowers_priority_monotonically(self):
        kwargs = dict(expected_information_gain=0.9, impact=0.9,
                      confidence=0.9, risk=0.1)
        decreasing = [
            priority_formula(cost=cost, **kwargs) for cost in (1.0, 2.0, 3.0, 9.0)
        ]
        assert decreasing == sorted(decreasing, reverse=True)

    def test_higher_risk_lowers_priority_monotonically(self):
        kwargs = dict(expected_information_gain=0.9, impact=0.9,
                      confidence=0.9, cost=3.0)
        decreasing = [
            priority_formula(risk=risk, **kwargs) for risk in (0.0, 0.25, 0.5, 1.0)
        ]
        assert decreasing == sorted(decreasing, reverse=True)

    def test_pure_and_deterministic(self):
        kwargs = dict(expected_information_gain=0.7, impact=0.6,
                      confidence=0.5, cost=3.0, risk=0.2)
        assert priority_formula(**kwargs) == priority_formula(**kwargs)


def _two_hypotheses(**overrides):
    """Two minimal Hypothesis objects with independent dials."""
    from webpent.models.hypothesis import Hypothesis, HypothesisStatus
    from uuid import uuid5, NAMESPACE_URL

    base = dict(
        statement="wiring dial test hypothesis", vuln_class="idor",
        origin="heuristic", origin_detail="d",
        target_url="http://t/api/a",
        expected_behavior="expected behavior text",
        negative_control="negative control text",
        status=HypothesisStatus.UNEXPLORED,
    )
    h1 = Hypothesis(id=uuid5(NAMESPACE_URL, "w3-a"), **{**base, **overrides.get("a", {})})
    h2 = Hypothesis(id=uuid5(NAMESPACE_URL, "w3-b"), **{**base, **overrides.get("b", {})})
    return h1, h2


def _context_with(**fields):
    ctx = BrainPriorityContext(built=True)
    for key, value in fields.items():
        setattr(ctx, key, value)
    return ctx


class TestSensitivityEachVariable:
    """Law 47-3: flipping any single variable flips the ranking."""

    BASE = dict(
        expected_information_gain=0.5, impact=0.5,
        confidence=0.5, cost=3.0, risk=0.2,
    )

    def _estimate(self, hyp, ctx):
        return estimate_priority_inputs(hyp, ctx)

    def test_eig_change_flips_ranking(self, monkeypatch):
        # A: high EIG (info_gain recorded on the hypothesis)
        a, b = _two_hypotheses(
            a={"info_gain": 0.95}, b={"info_gain": 0.10})
        ctx = _context_with()
        monkeypatch.setattr(
            "webpent.production.brain_engine._skg_info_gain",
            lambda *a, **k: 0.5,
        )
        # direct estimator dial: info_gain feeds EIG
        ia = estimate_priority_inputs(a, ctx)["expected_information_gain"]
        ib = estimate_priority_inputs(b, ctx)["expected_information_gain"]
        assert ia > ib
        from webpent.production.brain_engine import brain_priority
        assert brain_priority(a, ctx) > brain_priority(b, ctx)

    def test_impact_change_flips_ranking(self):
        # A targets a path TO a sensitive resource, B does not
        a, b = _two_hypotheses(
            a={"vuln_class": "auth_bypass"},
            b={"vuln_class": "info_disclosure"},
        )
        ctx = _context_with(
            sensitive_reachable={"http://t/api/a": 0.9},
            plan_costs={}, risk_targets={},
        )
        from webpent.production.brain_engine import brain_priority
        assert brain_priority(a, ctx) > brain_priority(b, ctx)

    def test_confidence_change_flips_ranking(self):
        a, b = _two_hypotheses(
            a={"confidence_score": 0.9}, b={"confidence_score": 0.2})
        ctx = _context_with()
        from webpent.production.brain_engine import brain_priority
        assert brain_priority(a, ctx) > brain_priority(b, ctx)

    def test_cost_change_flips_ranking(self):
        a, b = _two_hypotheses(
            a={"target_url": "http://t/cheap"},
            b={"target_url": "http://t/expensive"})
        ctx = _context_with(
            plan_costs={"http://t/cheap": 1.0, "http://t/expensive": 9.0},
        )
        from webpent.production.brain_engine import brain_priority
        assert brain_priority(a, ctx) > brain_priority(b, ctx)

    def test_risk_change_flips_ranking(self):
        a, b = _two_hypotheses(
            a={"target_url": "http://t/safe"},
            b={"target_url": "http://t/risky"})
        ctx = _context_with(
            risk_targets={"http://t/safe": 0.1, "http://t/risky": 0.9},
        )
        from webpent.production.brain_engine import brain_priority
        assert brain_priority(a, ctx) > brain_priority(b, ctx)


class TestFormulaReachesStrategistRanking:
    """The formula is the LIVE strategist score when the flag is ON."""

    def test_rank_open_hypotheses_uses_formula_when_on(self, monkeypatch):
        from webpent.config.settings import get_settings
        from webpent.shared.prioritization import rank_open_hypotheses

        a, b = _two_hypotheses(
            a={"target_url": "http://t/cheap", "info_gain": 0.9},
            b={"target_url": "http://t/expensive", "info_gain": 0.1},
        )
        # both deterministic-match OFF so ordering is purely the score
        ctx = _context_with(
            plan_costs={"http://t/cheap": 1.0, "http://t/expensive": 12.0},
        )
        monkeypatch.setattr(get_settings(), "enable_brain_engine", True)
        monkeypatch.setattr(
            "webpent.shared.prioritization._brain_engine_context",
            lambda state: ctx,
        )
        ranked = rank_open_hypotheses([b, a], state={})
        assert ranked[0][0].id == a.id
        assert ranked[0][1] > ranked[1][1]

    def test_rank_open_hypotheses_legacy_when_off(self, monkeypatch):
        from webpent.config.settings import get_settings
        from webpent.shared.prioritization import rank_open_hypotheses

        monkeypatch.setattr(get_settings(), "enable_brain_engine", False)
        a, b = _two_hypotheses(
            a={"target_url": "http://t/cheap"},
            b={"target_url": "http://t/expensive", "confidence_score": 0.95},
        )
        # legacy scoring ignores plan_costs — B wins on confidence
        ranked = rank_open_hypotheses([a, b], state={})
        assert ranked[0][0].id == b.id
