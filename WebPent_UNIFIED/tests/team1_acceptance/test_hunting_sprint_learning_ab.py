"""Hunting Intelligence Sprint — learning A/B evidence tests.

Synthetic only. Proves Campaign B (with lessons) finds the same seeded bugs
with strictly fewer hypotheses than Campaign A (without lessons), and that
learning_loop.json validates against the evidence contract.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]  # hunting_sprint_work/
sys.path.insert(0, str(ROOT / "scripts"))

import learning_ab_harness as ab  # noqa: E402


def test_campaign_b_finds_same_bugs_with_fewer_hypotheses():
    metrics_a = ab.run_campaign_a()
    metrics_b, _meta = ab.run_campaign_b()
    # Same confirmed findings
    assert metrics_a.confirmed_findings == metrics_b.confirmed_findings
    assert metrics_a.confirmed_bug_ids == metrics_b.confirmed_bug_ids
    assert metrics_a.confirmed_findings >= 3  # seeded bugs present
    # Fewer hypotheses in B (learning works)
    assert metrics_b.hypotheses_generated < metrics_a.hypotheses_generated
    assert metrics_b.hypotheses_tested < metrics_a.hypotheses_tested


def test_lesson_consultant_wiring_produces_real_adjustment():
    _metrics_b, meta = ab.run_campaign_b()
    # LessonConsultant was actually consulted and returned hits
    assert meta.get("lesson_hits", 0) > 0 or meta.get("route_hits", 0) > 0 or meta.get("family_hits", 0) > 0
    assert meta.get("target_type")  # target type detected
    assert meta.get("applied_lesson_ids")  # lessons were applied


def test_verdict_is_learning_proven():
    metrics_a = ab.run_campaign_a()
    metrics_b, _ = ab.run_campaign_b()
    same = metrics_a.confirmed_bug_ids == metrics_b.confirmed_bug_ids
    reduction = metrics_a.hypotheses_generated - metrics_b.hypotheses_generated
    verdict = "learning_proven" if (same and reduction > 0) else "inconclusive"
    assert verdict == "learning_proven"


def test_learning_loop_json_exists_and_validates():
    loop_path = ROOT / "deliverables" / "learning_loop.json"
    # If the harness hasn't been run yet, run it
    if not loop_path.exists():
        ab.main()
    assert loop_path.exists(), "learning_loop.json must be produced"
    data = json.loads(loop_path.read_text())
    ll = data["learning_loop"]
    assert ll["honesty_label"].startswith("SYNTHETIC_PROOF_ONLY")
    assert ll["lesson_consultant_used"] is True
    ev = ll["evidence"]
    assert ev["verdict"] == "learning_proven"
    assert ev["same_findings"] is True
    assert ev["hypotheses_reduction"] > 0
    assert ev["before"]["confirmed"] == ev["after"]["confirmed"]
    assert ev["after"]["hypotheses"] < ev["before"]["hypotheses"]
