"""EGAIE benchmark: adaptive vs fixed baseline on the same ground truth,
acceptance thresholds defined before the run, reproducibility."""
from __future__ import annotations

import json

from webpent.egaie.benchmark.ground_truth import GROUND_TRUTH_V1
from webpent.egaie.benchmark.runner import (
    evaluate_thresholds,
    run_comparison,
)


def test_ground_truth_has_positives_and_negatives():
    positives = [c for c in GROUND_TRUTH_V1 if c.positive]
    negatives = [c for c in GROUND_TRUTH_V1 if not c.positive]
    assert len(positives) >= 3
    assert len(negatives) >= 2
    assert any(c.multi_step for c in positives)


def test_adaptive_meets_acceptance_thresholds():
    report = run_comparison(max_rounds=14)
    assert report.adaptive["recall"] >= 0.6, report.to_dict()
    assert report.adaptive["false_positives"] == 0
    assert report.thresholds_pass is True
    summary = json.loads(json.dumps(report.to_dict()))
    assert "adaptive" in summary and "baseline" in summary


def test_adaptive_not_worse_than_baseline_at_same_budget():
    report = run_comparison(max_rounds=14)
    adaptive, baseline = report.adaptive, report.baseline
    better_recall = adaptive["recall"] > baseline["recall"]
    equal_but_cheaper = (
        adaptive["recall"] == baseline["recall"]
        and adaptive["experiments_per_confirmed"]
        <= baseline["experiments_per_confirmed"])
    assert better_recall or equal_but_cheaper


def test_reproducibility_identical_confirmed_sets():
    report = run_comparison(max_rounds=14, repetitions=2)
    assert report.reproducible is True
    assert report.adaptive["confirmed_case_ids"] == report.replay_case_ids


def test_thresholds_reject_weak_adaptive():
    weak = {
        "recall": 0.2,
        "false_positives": 1,
        "experiments_per_confirmed": 9.0,
    }
    strong = {
        "recall": 0.8,
        "false_positives": 0,
        "experiments_per_confirmed": 2.0,
    }
    baseline_equal = {
        "recall": 0.8,
        "experiments_per_confirmed": 2.0,
    }
    assert evaluate_thresholds(weak, baseline_equal) is False
    assert evaluate_thresholds(strong, baseline_equal) is True
