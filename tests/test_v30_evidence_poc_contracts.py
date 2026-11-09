from __future__ import annotations

import json

from webpent.models.evidence import RelationalEvidence
from webpent.models.planner import (
    PlannerActionType,
    PlannerDecisionProposal,
    PlannerDecisionStatus,
    PlannerRiskLevel,
)
from webpent.shared.bac_identity_tester import build_relational_evidence
from webpent.shared.evidence_contract import EvidenceContract, EvidencePrimitive, evaluate_contract
from webpent.shared.planner_decisions import evaluate_proposal
from webpent.shared.poc_policy import evaluate_poc_risk


def _observation(identity: str, accessible: bool, fingerprint: str) -> dict:
    return {
        "identity": identity,
        "role": "user",
        "url": "https://lab.example.test/orders/42?token=do-not-retain",
        "accessible": accessible,
        "response_fingerprint": fingerprint,
    }


def test_relational_evidence_is_typed_redacted_and_not_a_finding() -> None:
    edges = build_relational_evidence(
        [
            _observation("alice", True, "fp-a"),
            _observation("bob", False, "fp-b"),
        ],
        owner_identity="alice",
        object_id="42",
    )

    assert len(edges) == 1
    edge = RelationalEvidence.model_validate(edges[0])
    assert edge.status == "observed"
    assert edge.confidence_level == "Needs Human Review"
    assert edge.differential is True
    assert edge.source_id == "identity:alice"
    assert edge.target_id == "identity:bob"
    assert "do-not-retain" not in json.dumps(edge.model_dump(mode="json"))
    assert edge.evidence_refs
    assert "confirmed" not in json.dumps(edge.model_dump(mode="json"))


def test_relational_edge_id_is_stable_across_repeated_generation() -> None:
    observations = [_observation("alice", True, "fp-a"), _observation("bob", True, "fp-b")]
    first = build_relational_evidence(observations)
    second = build_relational_evidence(observations)
    assert first[0]["id"] == second[0]["id"]


def test_poc_policy_fail_closes_destructive_and_requires_human_for_high() -> None:
    assert evaluate_poc_risk("destructive").status == "rejected"
    assert evaluate_poc_risk("high").status == "needs_approval"
    assert evaluate_poc_risk("high", human_approved=True).status == "allowed"
    assert evaluate_poc_risk("low").allowed is True
    assert evaluate_poc_risk("unknown").status == "rejected"


def test_planner_gate_uses_central_poc_policy() -> None:
    state = {"mental_model": {"nodes": {}}, "hypotheses": []}
    proposal = PlannerDecisionProposal(
        action_type=PlannerActionType.OBSERVE_TARGET,
        target_ref="engagement_target",
        expected_evidence=["scope_check"],
        estimated_cost=1,
        risk_level=PlannerRiskLevel.DESTRUCTIVE,
        rationale="must be rejected",
    )
    audit = evaluate_proposal(proposal, state)
    assert audit.status == PlannerDecisionStatus.REJECTED.value
    assert "policy:destructive_action" in audit.gates_failed


def test_planner_high_risk_is_needs_approval_only_when_other_gates_pass() -> None:
    state = {"mental_model": {"nodes": {}}, "hypotheses": []}
    proposal = PlannerDecisionProposal(
        action_type=PlannerActionType.OBSERVE_TARGET,
        target_ref="engagement_target",
        expected_evidence=["scope_check"],
        estimated_cost=1,
        risk_level=PlannerRiskLevel.HIGH,
        rationale="requires operator review",
    )
    audit = evaluate_proposal(proposal, state)
    assert audit.status == PlannerDecisionStatus.NEEDS_APPROVAL.value
    assert audit.gates_failed == ["risk:human_approval_required"]


def test_owner_foreign_contract_requires_both_access_paths() -> None:
    contract = EvidenceContract(
        all_of=[{"primitive": EvidencePrimitive.OWNER_FOREIGN_ACCESS.value}]
    )
    # GOED added a proof_posture requirement (causal_signal +
    # negative_control_complete + proof_bundle_sealed) on top of the
    # primitive-level check — see RECONCILIATION_REPORT.md.
    proof_posture = {
        "causal_signal": True,
        "negative_control_complete": True,
        "proof_bundle_sealed": True,
    }
    confirmed = evaluate_contract(
        contract,
        {
            "owner": {"accessible": True},
            "foreign": {"accessible": True},
            **proof_posture,
        },
    )
    clean = evaluate_contract(
        contract,
        {
            "owner": {"accessible": True},
            "foreign": {"accessible": False},
            **proof_posture,
        },
    )
    assert confirmed["satisfied"] is True
    assert clean["satisfied"] is False


def test_oob_contract_does_not_accept_in_band_response_only() -> None:
    contract = EvidenceContract(all_of=[{"primitive": EvidencePrimitive.OOB_CALLBACK.value}])
    result = evaluate_contract(contract, {"status_code": 200, "body": "callback"})
    assert result["satisfied"] is False

