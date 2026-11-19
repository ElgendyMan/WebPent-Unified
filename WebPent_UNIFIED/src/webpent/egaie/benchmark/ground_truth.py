"""EGAIE benchmark ground truth v1.

Controlled local cases only. Positives: 3 simple + 1 multi-step (needs a
stage2 follow-up after an inconclusive stage1). Negatives: 2 properly
denied lookalikes. Declared BEFORE the benchmark run and used only to
score, never to steer the adaptive loop.
"""
from __future__ import annotations

from webpent.egaie.benchmark.fixture import FixtureCase

GROUND_TRUTH_V1: list[FixtureCase] = [
    FixtureCase(case_id="pos-idor-1", family="IDOR", positive=True),
    FixtureCase(case_id="pos-bola-1", family="BOLA", positive=True),
    FixtureCase(case_id="pos-authbypass-1", family="AUTH_BYPASS",
                positive=True),
    FixtureCase(case_id="pos-idor-multi", family="IDOR", positive=True,
                multi_step=True),
    FixtureCase(case_id="neg-idor-1", family="IDOR", positive=False),
    FixtureCase(case_id="neg-bola-1", family="BOLA", positive=False),
]
