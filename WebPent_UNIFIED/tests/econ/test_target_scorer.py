"""U-ECON-2 — TargetScorer tests (NC-ECON-1 charter, exact test names)."""

from __future__ import annotations

from pathlib import Path

from webpent.econ.market_kb import MarketKB, Target
from webpent.econ.target_scorer import ScorerContext, TargetScorer, tier_for

REPO = Path(__file__).resolve().parents[2]
SEED_CONFIG = REPO / "config" / "econ" / "programs.yaml"
NOW = 1_800_000_000.0  # fixed epoch: determinism by construction


def _scorer() -> TargetScorer:
    return TargetScorer(MarketKB(SEED_CONFIG))


def _ctx(**kw) -> ScorerContext:
    return ScorerContext(now=NOW, **kw)


def test_score_is_deterministic():
    scorer = _scorer()
    target = Target("app.example-corp.com", "example-corp", last_change_ts=NOW - 3600)
    first = scorer.score(target, _ctx())
    for _ in range(3):
        again = scorer.score(target, _ctx())
        assert again.score == first.score
        assert again.tier == first.tier
        assert again.components == first.components
        assert again.rationale == first.rationale


def test_score_is_clamped_0_100():
    scorer = _scorer()
    # absurd best case: max rhythm, minimum effort and competition
    best = Target("best.example-fintech.com", "example-fintech",
                  last_change_ts=NOW - 60, deploy_rhythm_bonus=1.5,
                  effort_estimate=0.5, saturation=0.0)
    worst = Target("worst.example-fintech.com", "example-fintech",
                   last_change_ts=NOW - 86400 * 365, deploy_rhythm_bonus=1.5,
                   effort_estimate=0.5, saturation=0.0)
    low = scorer.score(worst, _ctx(competition_level=2.0, saturation=100.0))
    high = scorer.score(best, _ctx(competition_level=0.5, saturation=0.0))
    assert 0.0 <= low.score <= 100.0
    assert 0.0 <= high.score <= 100.0
    assert high.score > low.score


def test_tier_assignment_matches_score():
    assert tier_for(100.0) == "S" and tier_for(80.0) == "S"
    assert tier_for(79.9) == "A" and tier_for(65.0) == "A"
    assert tier_for(64.9) == "B" and tier_for(50.0) == "B"
    assert tier_for(49.9) == "C" and tier_for(30.0) == "C"
    assert tier_for(29.9) == "D" and tier_for(0.0) == "D"
    scorer = _scorer()
    target = Target("t.example-corp.com", "example-corp", last_change_ts=NOW - 3600)
    scored = scorer.score(target, _ctx())
    assert scored.tier == tier_for(scored.score)


def test_high_payout_fresh_target_scores_S():  # noqa: N802 - charter name
    scorer = _scorer()
    # example-bank pays the most (weighted typical ~ top of the seed) and
    # is fresh, low-dup, easy effort: the charter's S scenario.
    target = Target("portal.example-bank.com", "example-bank",
                    last_change_ts=NOW - 3600, deploy_rhythm_bonus=1.4,
                    effort_estimate=0.5)
    scored = scorer.score(target, _ctx(saturation=10.0))
    assert scored.tier == "S", scored.as_dict()
    assert scored.components["payout_potential"] > 0.5
    assert scored.components["freshness_signal"] == 1.0


def test_stale_high_dup_target_scores_D():  # noqa: N802 - charter name
    scorer = _scorer()
    # example-social: high dup rate; stale change, saturated, heavy effort.
    target = Target("old.example-social.com", "example-social",
                    last_change_ts=NOW - 86400 * 120, deploy_rhythm_bonus=1.0,
                    effort_estimate=3.0)
    scored = scorer.score(target, _ctx(saturation=95.0, competition_level=2.0))
    assert scored.tier == "D", scored.as_dict()
    assert scored.components["dup_risk"] > 0.4
    assert scored.components["freshness_signal"] == 0.3


def test_components_sum_to_rationale():
    scorer = _scorer()
    target = Target("api.example-ecom.com", "example-ecom", last_change_ts=NOW - 86400 * 20)
    scored = scorer.score(target, _ctx())
    # every documented component appears in the rationale line, with the
    # final score and tier it explains
    assert "payout" in scored.rationale
    assert "fresh" in scored.rationale
    assert "dup" in scored.rationale
    assert "rhythm" in scored.rationale
    assert "effort" in scored.rationale
    assert "comp" in scored.rationale
    assert f"{scored.score:.1f}" in scored.rationale
    assert scored.tier in scored.rationale
    assert scored.timestamp.tzinfo is not None
