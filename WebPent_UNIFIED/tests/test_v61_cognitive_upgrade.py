from types import SimpleNamespace

from webpent.models.hypothesis import Hypothesis, VulnClass
from webpent.shared.application_intent import infer_application_intent
from webpent.shared.evidence_contract import (
    EvidenceContract,
    EvidencePrimitive,
    EvidenceRequirement,
    evaluate_contract,
)
from webpent.shared.prioritization import compute_novelty_bonus, score_hypothesis
from webpent.shared.trust_matrix import build_trust_matrix, trust_adjustment


def test_evidence_contract_requires_all_primitives_and_fails_closed() -> None:
    contract = EvidenceContract(
        all_of=[
            EvidenceRequirement(primitive=EvidencePrimitive.DIFFERENTIAL_RESPONSE),
            EvidenceRequirement(primitive=EvidencePrimitive.OOB_CALLBACK),
        ],
        provenance=["heuristic"],
    )
    partial = evaluate_contract(
        contract,
        {
            "baseline": {"status_code": 200, "body_digest": "a"},
            "probe": {"status_code": 200, "body_digest": "b"},
        },
    )
    assert partial["satisfied"] is False
    assert {item["primitive"] for item in partial["results"]} == {
        "differential_response",
        "oob_callback",
    }

    complete = evaluate_contract(
        contract,
        {
            "baseline": {"status_code": 200, "body_digest": "a"},
            "probe": {"status_code": 200, "body_digest": "b"},
            "callback_received": True,
            # GOED added a proof_posture requirement (causal_signal +
            # negative_control_complete + proof_bundle_sealed) on top of
            # the per-primitive checks — see RECONCILIATION_REPORT.md.
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle_sealed": True,
        },
    )
    assert complete["satisfied"] is True


def test_application_intent_is_deterministic_and_policy_bounded() -> None:
    result = infer_application_intent(
        target_url="https://example.test",
        auth_signals=["multi-identity-context"],
        identities=[{}, {}],
        objects=[{"id": "redacted"}],
        workflows=[{"method": "POST"}],
        endpoint_details=[{"path": "/orders/{id}"}],
    )
    assert result["source"] == "deterministic_projection"
    assert "tenant_isolation" in result["policy_assumptions"]
    assert all("secret" not in str(value).lower() for value in result.values())


def test_trust_matrix_is_sanitized_and_small_samples_do_not_adjust() -> None:
    findings = [
        SimpleNamespace(
            vuln_class="sqli",
            tool_name="sqlmap",
            human_review_decision="accepted",
            confidence_level="Pending",
            hint_provenance=["memory_pattern"],
        ),
        SimpleNamespace(
            vuln_class="sqli",
            tool_name="sqlmap",
            human_review_decision="rejected",
            confidence_level="Pending",
            hint_provenance=["memory_pattern"],
        ),
        SimpleNamespace(
            vuln_class="sqli",
            tool_name="sqlmap",
            human_review_decision="accepted",
            confidence_level="Pending",
            hint_provenance=["memory_pattern"],
        ),
    ]
    matrix = build_trust_matrix(findings)
    entry = matrix["entries"]["sqli|sqlmap|memory_pattern"]
    assert entry["sample_count"] == 3
    assert entry["confidence"] == "calibrated"
    assert 0.05 <= entry["reliability"] <= 0.95
    assert trust_adjustment(matrix, findings[0]) >= 0.0
    assert "url" not in str(matrix).lower()


def test_novelty_bonus_is_bounded_and_score_remains_in_range() -> None:
    hypothesis = Hypothesis(
        target_url="https://example.test/orders/1",
        statement="An unknown response pattern may cross a workflow boundary.",
        vuln_class=VulnClass.UNKNOWN,
        hint_provenance=["policy_assumption"],
        novelty_score=1.0,
    )
    bonus = compute_novelty_bonus(hypothesis, {"pattern_hints": [], "trust_matrix": {}})
    assert 0.0 <= bonus <= 0.25
    score = score_hypothesis(hypothesis, {"hypotheses": [], "findings": []})
    assert 0.0 <= score <= 1.0
