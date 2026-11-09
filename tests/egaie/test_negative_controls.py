"""EGAIE negative-control discipline: neither loop may confirm a case
whose ground truth is negative, in adaptive OR baseline mode."""
from __future__ import annotations

from webpent.egaie.benchmark.runner import (
    _confirmed_case_ids,
    run_adaptive,
    run_baseline,
)


def test_baseline_never_confirms_negative_controls():
    state = run_baseline(max_rounds=14)
    confirmed = _confirmed_case_ids(state)
    negatives = [cid for cid in confirmed if cid.startswith("neg-")]
    assert negatives == [], (
        "baseline confirmed negative controls", confirmed)


def test_adaptive_never_confirms_negative_controls():
    state = run_adaptive(max_rounds=14)
    confirmed = _confirmed_case_ids(state)
    negatives = [cid for cid in confirmed if cid.startswith("neg-")]
    assert negatives == [], (
        "adaptive confirmed negative controls", confirmed)
