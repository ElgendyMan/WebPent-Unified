"""UM-DR-33 §8.2 — information gain is operational in the strategist score.

The UM-DR-31 review found that varying ``info_gain`` did not change the
strategist's ranking score: the field was stored and populated
(``_INFO_GAIN_PRIORS``, hardcoded 0.6/0.55 in the frozen
identity_workflow producers) but ``score_hypothesis`` never read it.
UM-DR-33 makes it a real, bounded, documented input:

1. MONOTONICITY: score is strictly increasing in info_gain (mutation
   test — changing the value changes the score, ceteris paribus).
2. RANKING IMPACT: two otherwise-identical hypotheses rank by info_gain;
   changing one's info_gain flips the order (controlled ranking test).
3. DETERMINISM: identical inputs give identical scores.
4. NEUTRAL DEFAULT: ``info_gain=None`` (not yet scored) maps to the
   neutral midpoint 0.5 — unscored hypotheses are neither penalised nor
   boosted; explicit low ranks below unscored, explicit high above.
5. SAFETY INDEPENDENCE (the §8.2 boundary): a maximal info_gain can
   never make an out-of-scope endpoint admissible, never bypass the
   scope/authorization admission gates, and never reset or extend a
   budget — those gates are score-independent by construction. Pinned
   here with the real production gate functions.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from webpent.models.hypothesis import Hypothesis  # noqa: E402
from webpent.shared.prioritization import (  # noqa: E402
    W_INFO_GAIN,
    _INFO_GAIN_NEUTRAL,
    _W_SUM,
    rank_open_hypotheses,
    score_hypothesis,
)

STATE = {
    "hypotheses": [],
    "findings": [],
    "run_number": 1,
}


_NEXT_ID = [0]


def _hypothesis(**overrides) -> Hypothesis:
    import uuid

    _NEXT_ID[0] += 1
    base = dict(
        id=uuid.uuid5(uuid.NAMESPACE_URL, f"umdr33-ig-{_NEXT_ID[0]}"),
        target_url="https://target.test/api/orders/601",
        statement="foreign principal reads owner object",
        vuln_class="idor",
        confidence_score=0.5,
        status="unexplored",
        info_gain=None,
    )
    base.update(overrides)
    return Hypothesis(**base)


class TestMonotonicity:
    @pytest.mark.parametrize("ig", [0.0, 0.25, 0.5, 0.75, 1.0])
    def test_score_is_defined_for_all_info_gains(self, ig) -> None:
        h = _hypothesis(info_gain=ig)
        assert 0.0 <= score_hypothesis(h, STATE) <= 1.0

    def test_higher_info_gain_strictly_increases_score(self) -> None:
        h_low = _hypothesis(info_gain=0.1)
        h_mid = _hypothesis(info_gain=0.5)
        h_high = _hypothesis(info_gain=0.9)
        s_low = score_hypothesis(h_low, STATE)
        s_mid = score_hypothesis(h_mid, STATE)
        s_high = score_hypothesis(h_high, STATE)
        assert s_low < s_mid < s_high

    def test_mutation_changes_the_score(self) -> None:
        """The §8.2 mutation test: change info_gain, expect a changed score."""
        h = _hypothesis(info_gain=0.2)
        before = score_hypothesis(h, STATE)
        h.info_gain = 0.95
        after = score_hypothesis(h, STATE)
        assert after > before
        # the expected arithmetic delta is exactly the weight difference
        assert after - before == pytest.approx(W_INFO_GAIN * (0.95 - 0.2))

    def test_weight_is_real_and_documented(self) -> None:
        assert W_INFO_GAIN == 0.10
        assert _W_SUM == pytest.approx(1.0)
        assert _INFO_GAIN_NEUTRAL == 0.5


class TestRankingImpact:
    def test_two_identical_hypotheses_order_by_info_gain(self) -> None:
        low = _hypothesis(info_gain=0.1, statement="low")
        high = _hypothesis(info_gain=0.9, statement="high")
        ranked = rank_open_hypotheses([low, high], STATE)
        assert ranked[0][0].statement == "high"
        assert ranked[1][0].statement == "low"

    def test_flipping_info_gain_flips_the_order(self) -> None:
        """The controlled ranking test required by §8.2."""
        a = _hypothesis(info_gain=0.9, statement="h-a")
        b = _hypothesis(info_gain=0.1, statement="h-b")
        assert rank_open_hypotheses([a, b], STATE)[0][0].statement == "h-a"
        # mutate the info gains — the order must flip
        b.info_gain = 0.95
        a.info_gain = 0.05
        assert rank_open_hypotheses([a, b], STATE)[0][0].statement == "h-b"

    def test_determinism_same_inputs_same_ranking(self) -> None:
        pool = [
            _hypothesis(info_gain=i / 4.0, statement=f"h-{i}")
            for i in range(5)
        ]
        first = [h[0].statement for h in rank_open_hypotheses(pool, STATE)]
        second = [h[0].statement for h in rank_open_hypotheses(pool, STATE)]
        assert first == second == ["h-4", "h-3", "h-2", "h-1", "h-0"]


class TestNeutralDefault:
    def test_none_maps_to_neutral_midpoint(self) -> None:
        unscored = _hypothesis(info_gain=None)
        neutral = _hypothesis(info_gain=_INFO_GAIN_NEUTRAL)
        assert score_hypothesis(unscored, STATE) == pytest.approx(
            score_hypothesis(neutral, STATE)
        )

    def test_explicit_low_ranks_below_unscored(self) -> None:
        unscored = _hypothesis(info_gain=None, statement="h-unscored")
        low = _hypothesis(info_gain=0.05, statement="h-low")
        assert rank_open_hypotheses([low, unscored], STATE)[0][0].statement == "h-unscored"

    def test_explicit_high_ranks_above_unscored(self) -> None:
        unscored = _hypothesis(info_gain=None, statement="h-unscored")
        high = _hypothesis(info_gain=0.95, statement="h-high")
        assert rank_open_hypotheses([unscored, high], STATE)[0][0].statement == "h-high"

    def test_out_of_range_values_are_clamped_defensively(self) -> None:
        high = _hypothesis(info_gain=1.0)
        object.__setattr__(high, "info_gain", 7.5)  # bypass model bound
        assert score_hypothesis(high, STATE) == pytest.approx(
            score_hypothesis(_hypothesis(info_gain=1.0), STATE)
        )


class TestSafetyIndependence:
    """§8.2: increasing information gain can NEVER override authorization,
    scope admission, severity-independent safety requirements, or hard
    budget limits. These gates are score-independent by construction;
    these tests pin that with the REAL production gate functions."""

    def test_max_info_gain_cannot_admit_out_of_scope_endpoint(self) -> None:
        """The scope admission gate (adaptive_research._admit_endpoint)
        decides on scope membership ONLY — a maximal info_gain score is
        irrelevant to it."""
        from webpent.production.adaptive_research import _admit_endpoint

        origin = ("https", "authorized-target.test", 443)
        in_scope, _why = _admit_endpoint(
            "https://authorized-target.test/api/orders/1", origin,
            base_url="https://authorized-target.test",
        )
        out_of_scope, out_why = _admit_endpoint(
            "https://evil.example/api/orders/1", origin,
            base_url="https://authorized-target.test",
        )
        assert in_scope  # the normalized in-scope endpoint (truthy)
        assert not out_of_scope, out_why  # empty string — denied, regardless of any score

    def test_max_info_gain_score_cannot_make_a_budget_refile(self) -> None:
        """BudgetGuard denies on REQUESTS regardless of any hypothesis
        score: the guard's decision inputs are the counters, not scores."""
        from webpent.campaign.executor.budget_guard import (
            BudgetGuard,
            BudgetRequest,
            BudgetState,
        )

        guard = BudgetGuard()

        def _req(n):
            return BudgetRequest(requests=n, time_seconds=0.0, llm_calls=0)

        def _state():
            return BudgetState(
                phase_max=_req(10),
                campaign_max=_req(100),
                phase_used=_req(0),
                campaign_used=_req(0),
            )

        import dataclasses

        # spend the phase down to its cap — every step allowed
        for used in range(10):
            st = dataclasses.replace(_state(), phase_used=_req(used))
            assert guard.check(st, requested=_req(1)).allowed
        # the 11th request is denied on counters alone — no score input exists
        st = dataclasses.replace(_state(), phase_used=_req(10))
        decision = guard.check(st, requested=_req(1))
        assert not decision.allowed
        assert "phase_budget_exceeded" in decision.reason

    def test_corrupted_budget_state_still_fails_closed(self) -> None:
        """Ties to the Phase 2 fix: a corrupted trace consumes the budget —
        no score, however high, changes that."""
        from webpent.graph.budget_governor import budget_pressure

        state = {
            "enable_step_budget": True,
            "max_graph_steps": 40,
            "node_step_trace": "agent-corrupted",
        }
        result = budget_pressure(state)
        assert result["reason"] == "fail_closed_corrupted_trace"
        assert result["remaining"] == 0

    def test_info_gain_changes_the_strategist_decision_not_the_action_set(self) -> None:
        """The intended §8.2 semantics: information gain is strong enough
        to move a hypothesis ACROSS the promotion threshold (it is a real
        decision input, not decoration) — and the resulting action stays
        inside the closed action set. PROMOTE means execution CANDIDACY:
        the authorized executor still independently enforces scope,
        authorization and budget (pinned by the tests above)."""
        from webpent.shared.prioritization import (
            PrioritizationAction,
            recommend_action,
        )

        high = _hypothesis(vuln_class="deserialization",
                           info_gain=1.0, confidence_score=0.99)
        low = _hypothesis(vuln_class="deserialization",
                          info_gain=0.0, confidence_score=0.99)

        action_high, score_high, why_high = recommend_action(high, STATE)
        action_low, score_low, why_low = recommend_action(low, STATE)

        # the decision genuinely depends on info gain
        assert action_high == PrioritizationAction.PROMOTE
        assert "PROMOTION_THRESHOLD" in why_high
        assert action_low != PrioritizationAction.PROMOTE
        assert score_high - score_low == pytest.approx(W_INFO_GAIN)

        # the action set is closed — there is no bypass action
        assert action_high.value in {"promote", "defer", "rabbit_hole", "abandon"}
