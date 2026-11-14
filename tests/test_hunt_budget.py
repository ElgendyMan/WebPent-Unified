"""v81 Task 2: pure round-budget recommendations.

Proven properties: determinism, bounds ([floor, base] and [1, max]),
monotone non-increasing in the dead-end ratio, clamped inputs.
"""

from __future__ import annotations

from webpent.autonomous.hunt_budget import (
    REHYPOTHESIZE_BASE,
    REHYPOTHESIZE_FLOOR,
    recommend_rehypothesize_rounds,
    recommend_round_budget,
)


def test_zero_ratio_returns_base_and_full_budget() -> None:
    assert recommend_rehypothesize_rounds(0.0) == REHYPOTHESIZE_BASE
    assert recommend_rehypothesize_rounds(0.0) == 3
    assert recommend_round_budget(5, 0.0) == 5


def test_full_ratio_floors() -> None:
    assert recommend_rehypothesize_rounds(1.0) == REHYPOTHESIZE_FLOOR
    assert recommend_rehypothesize_rounds(1.0) == 1
    assert recommend_round_budget(5, 1.0) >= 1


def test_monotone_non_increasing_and_bounded() -> None:
    previous = 10
    for i in range(11):
        ratio = i / 10.0
        rounds = recommend_rehypothesize_rounds(ratio)
        assert REHYPOTHESIZE_FLOOR <= rounds <= REHYPOTHESIZE_BASE
        assert rounds <= previous
        previous = rounds


def test_inputs_are_clamped_and_deterministic() -> None:
    assert recommend_rehypothesize_rounds(-3.0) == recommend_rehypothesize_rounds(0.0)
    assert recommend_rehypothesize_rounds(9.0) == recommend_rehypothesize_rounds(1.0)
    assert recommend_rehypothesize_rounds(0.5) == recommend_rehypothesize_rounds(0.5)


def test_round_budget_floor_is_one_never_zero() -> None:
    for iterations in (1, 2, 5, 10):
        for i in range(11):
            budget = recommend_round_budget(iterations, i / 10.0)
            assert 1 <= budget <= iterations
