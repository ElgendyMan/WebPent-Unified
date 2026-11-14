"""U-ECON-6 — BudgetMapper tests (NC-ECON-1 charter, exact test names)."""

from __future__ import annotations

import math
from pathlib import Path

from webpent.econ.budget_mapper import BudgetContext, BudgetMapper
from webpent.econ.market_kb import MarketKB, Target
from webpent.econ.target_scorer import TargetScorer

REPO = Path(__file__).resolve().parents[2]
SEED_CONFIG = REPO / "config" / "econ" / "programs.yaml"
CURVES = REPO / "config" / "econ" / "payout_curves.yaml"
NOW = 1_800_000_000.0


def _mapper() -> BudgetMapper:
    kb = MarketKB(SEED_CONFIG, payout_curves_path=CURVES)
    return BudgetMapper(TargetScorer(kb))


def _targets(program: str, count: int, effort: float = 1.0) -> list[Target]:
    return [
        Target(target_id=f"t-{program}-{i}", program_id=program, effort_estimate=effort)
        for i in range(count)
    ]


def test_allocation_totals_match_input_hours():
    mapper = _mapper()
    targets = _targets("example-corp", 10) + _targets("example-bank", 10)
    allocations = mapper.allocate(targets, 40.0, BudgetContext(now=NOW))
    total = sum(a.hours_per_week for a in allocations)
    assert math.isclose(total, 40.0, rel_tol=1e-9)
    # every target got exactly one allocation
    assert len(allocations) == 20
    assert len({a.target_id for a in allocations}) == 20


def test_top_target_gets_most_hours():
    mapper = _mapper()
    targets = _targets("example-corp", 10)
    allocations = mapper.allocate(targets, 40.0, BudgetContext(now=NOW))
    # all targets here share effort, so rank 0 (highest EV/hour) tops the hours
    ranked = sorted(allocations, key=lambda a: -a.ev_per_hour)
    top = ranked[0]
    assert top.hours_per_week == max(a.hours_per_week for a in allocations)
    assert top.tier == "INTENSIVE"
    # 60% of 40h in the INTENSIVE pool, split evenly over 2 targets
    intensive = [a for a in allocations if a.tier == "INTENSIVE"]
    assert len(intensive) == 2
    assert math.isclose(
        sum(a.hours_per_week for a in intensive), 24.0, rel_tol=1e-9
    )


def test_ev_per_hour_ordering_respected():
    mapper = _mapper()
    # mix programs with different dup rates/payouts, all same effort
    targets = (
        _targets("example-bank", 4)  # high payout, low dup
        + _targets("example-social", 4)  # high dup
        + _targets("example-gov-portal", 2)  # low payout
    )
    allocations = mapper.allocate(targets, 20.0, BudgetContext(now=NOW))
    evs = [a.ev_per_hour for a in allocations]
    # output order is the charter's ranked order (descending EV/hour)
    assert evs == sorted(evs, reverse=True)
    # and the tier boundaries follow the ordering: INTENSIVE >= ROUTINE >= DORMANT
    tier_rank = {"INTENSIVE": 2, "ROUTINE": 1, "DORMANT": 0}
    tiers = [tier_rank[a.tier] for a in allocations]
    assert tiers == sorted(tiers, reverse=True)
    # every allocation carries a justification
    assert all(a.justification for a in allocations)


def test_zero_hours_raises():
    mapper = _mapper()
    for bad in (0.0, -5.0):
        try:
            mapper.allocate(_targets("example-corp", 3), bad, BudgetContext(now=NOW))
        except ValueError as exc:
            assert "total_hours" in str(exc)
        else:
            raise AssertionError(f"expected ValueError for total_hours={bad}")


def test_deterministic_across_runs():
    mapper = _mapper()
    targets = (
        _targets("example-corp", 6)
        + _targets("example-fintech", 5)
        + _targets("example-ecom", 4)
    )
    run1 = [a.as_dict() for a in mapper.allocate(targets, 35.0, BudgetContext(now=NOW))]
    run2 = [a.as_dict() for a in mapper.allocate(list(reversed(targets)), 35.0,
                                                 BudgetContext(now=NOW))]
    # same allocations (order included), input order must not matter
    assert run1 == run2
    # and a second mapper instance with the same config agrees too
    run3 = [a.as_dict() for a in _mapper().allocate(targets, 35.0, BudgetContext(now=NOW))]
    assert run1 == run3
