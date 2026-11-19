# tests/test_integration_priority_policy.py
"""Deterministic priority policy tests (protocol §12)."""

from __future__ import annotations

import pytest

from webpent.integration.priority_policy import (
    DEFAULT_WEIGHTS,
    POLICY_VERSION,
    PRIORITY_MAX,
    PRIORITY_MIN,
    PROPOSAL_MAX_BOOST,
    PriorityFactor,
    PriorityInput,
    PriorityProposal,
    compute_priority,
)


def _input(**overrides) -> PriorityInput:
    base = dict(
        severity_potential=8,
        evidence_strength=0.5,
        exploitability=0.5,
        asset_criticality=0.5,
        confidence=0.5,
        novelty=0.5,
        dependency_depth=0,
        exploration_cost=0,
    )
    base.update(overrides)
    return PriorityInput(**base)


def test_priority_is_bounded():
    assert PRIORITY_MIN == 0 and PRIORITY_MAX == 100
    low = compute_priority(_input(severity_potential=0, evidence_strength=0.0,
                                  exploitability=0.0, asset_criticality=0.0,
                                  confidence=0.0, novelty=0.0,
                                  dependency_depth=32, exploration_cost=10))
    assert low.priority == 0
    high = compute_priority(_input(severity_potential=10, evidence_strength=1.0,
                                   exploitability=1.0, asset_criticality=1.0,
                                   confidence=1.0, novelty=1.0))
    assert high.priority == 100


def test_priority_is_deterministic_and_reproducible():
    a = compute_priority(_input())
    b = compute_priority(_input())
    assert a == b
    assert a.to_audit_dict() == b.to_audit_dict()


def test_every_factor_moves_priority_in_expected_direction():
    baseline = compute_priority(_input()).priority
    assert compute_priority(_input(severity_potential=10)).priority >= baseline
    assert compute_priority(_input(evidence_strength=0.9)).priority >= baseline
    assert compute_priority(_input(exploitability=0.9)).priority >= baseline
    assert compute_priority(_input(dependency_depth=4)).priority <= baseline
    assert compute_priority(_input(exploration_cost=9)).priority <= baseline


def test_weights_are_respected():
    weights = dict(DEFAULT_WEIGHTS)
    weights[PriorityFactor.SEVERITY_POTENTIAL] = 100
    boosted = compute_priority(_input(severity_potential=10), weights=weights)
    neutral = compute_priority(_input(severity_potential=10))
    assert boosted.priority > neutral.priority


def test_llm_proposal_is_clamped_and_audited():
    # Out-of-range proposals are rejected at the model boundary.
    with pytest.raises(ValueError):
        PriorityProposal(suggested_delta=999, reason="x", proposer="llm")
    # Defense in depth: even a boundary-bypassed construction is
    # clamped by the policy itself before it can influence anything.
    bypassed = PriorityProposal.model_construct(
        suggested_delta=999,
        reason="llm escalation attempt",
        proposer="llm_researcher",
    )
    decision = compute_priority(_input(), proposal=bypassed)
    assert decision.proposal_applied == PROPOSAL_MAX_BOOST
    assert decision.proposal_reason == "llm escalation attempt"
    audit = decision.to_audit_dict()
    assert audit["proposal_applied"] == PROPOSAL_MAX_BOOST
    assert audit["policy_version"] == POLICY_VERSION


def test_negative_proposal_cannot_go_below_zero():
    proposal = PriorityProposal(
        suggested_delta=-PROPOSAL_MAX_BOOST,
        reason="llm deprioritization",
        proposer="llm_researcher",
    )
    decision = compute_priority(
        _input(severity_potential=0, evidence_strength=0.0, exploitability=0.0,
               asset_criticality=0.0, confidence=0.0, novelty=0.0,
               dependency_depth=32, exploration_cost=10),
        proposal=proposal,
    )
    assert decision.priority == 0


def test_proposal_requires_reason_and_proposer():
    with pytest.raises(ValueError):
        PriorityProposal(suggested_delta=1, reason="  ", proposer="llm_researcher")
    with pytest.raises(ValueError):
        PriorityProposal(suggested_delta=1, reason="x", proposer="")


def test_contributions_are_fully_auditable():
    decision = compute_priority(_input())
    assert set(decision.contributions) == {f.value for f in PriorityFactor}
    assert all(isinstance(v, float) for v in decision.contributions.values())
    # Deterministic ordering of the audit view.
    assert list(decision.to_audit_dict()["contributions"]) == sorted(decision.contributions)


def test_policy_input_validation_is_fail_closed():
    with pytest.raises(ValueError):
        _input(severity_potential=11)
    with pytest.raises(ValueError):
        _input(evidence_strength=1.5)
    with pytest.raises(ValueError):
        _input(dependency_depth=-1)
