"""U-FORGE-2 — The Quality Gate (8 tests per spec).

The gate applies the spec's QUALITY_RULES in a documented, safe-first
order: auto_reject conditions are evaluated BEFORE auto_accept, so a
deprecated or malware payload can never ride in on a high trust score
(FORGE-L-2 QUALITY_OVER_QUANTITY).
"""
from __future__ import annotations

import pytest

from webpent.forge.quality_gate import QualityGate, QualityDecision
from webpent.forge.schemas import PayloadAttribution, QualitySignal


def make_signal(**overrides):
    defaults = dict(
        payload_id="p-1",
        score=0.8,
        from_curated_source=True,
        has_cve=False,
        has_writeup=False,
        tested_publicly=True,
        is_deprecated=False,
        is_too_common=False,
        is_high_risk=False,
        has_documented_impact=True,
        is_known_malware=False,
        complexity="moderate",
        requires_specific_context=False,
        context_list=[],
        source_trust=0.95,
    )
    defaults.update(overrides)
    return QualitySignal(**defaults)


@pytest.fixture
def gate():
    return QualityGate()


def test_auto_accept_high_trust_with_cve(gate):
    decision = gate.evaluate(make_signal(has_cve=True))
    assert decision.decision == "auto_accept"


def test_auto_accept_high_trust_with_writeup(gate):
    decision = gate.evaluate(make_signal(has_writeup=True))
    assert decision.decision == "auto_accept"


def test_review_required_mid_trust(gate):
    decision = gate.evaluate(make_signal(
        has_cve=True, source_trust=0.75))
    assert decision.decision == "review_required"


def test_review_required_expert_complexity(gate):
    """Expert complexity forces review even from a curated source."""
    decision = gate.evaluate(make_signal(has_cve=True, complexity="expert"))
    assert decision.decision == "review_required"


def test_auto_reject_low_trust(gate):
    decision = gate.evaluate(make_signal(
        has_cve=True, source_trust=0.4))
    assert decision.decision == "auto_reject"


def test_auto_reject_high_risk_without_documented_impact(gate):
    decision = gate.evaluate(make_signal(
        has_cve=True, is_high_risk=True, has_documented_impact=False))
    assert decision.decision == "auto_reject"


def test_auto_reject_deprecated_and_malware(gate):
    assert gate.evaluate(make_signal(has_cve=True, is_deprecated=True)).decision \
        == "auto_reject"
    assert gate.evaluate(make_signal(has_cve=True, is_known_malware=True)).decision \
        == "auto_reject"


def test_reject_precedes_accept_and_reason_is_stated(gate):
    """A malware payload with a perfect trust score is still rejected."""
    decision = gate.evaluate(make_signal(
        has_cve=True, has_writeup=True, is_known_malware=True))
    assert isinstance(decision, QualityDecision)
    assert decision.decision == "auto_reject"
    assert decision.reason
