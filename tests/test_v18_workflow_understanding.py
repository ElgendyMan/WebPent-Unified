from __future__ import annotations

from unittest.mock import patch

from webpent.agents.business_logic_fuzzer.agent import business_logic_fuzzer_node
from webpent.models.hypothesis import Hypothesis
from webpent.models.workflows import WorkflowObservation
from webpent.shared.workflow_understanding import (
    extract_workflow_observations,
    generate_business_logic_hypotheses,
    workflow_coverage_gaps,
)


def _crawled_data() -> dict:
    return {
        "forms": [
            {
                "action": "/checkout/confirm",
                "method": "POST",
                "fields": {"order_id": "order-42", "csrf_token": "secret-token"},
                "requires_auth": True,
                "state": "review",
                "next_state": "complete",
                "redirect": "/orders/summary",
            }
        ],
        "requests": [
            {
                "url": "/checkout/confirm",
                "method": "POST",
                "parameters": {"order_id": "order-42"},
                "identity_ref": "alice",
                "previous_step": "cart",
            }
        ],
    }


def test_workflow_extraction_is_redacted_and_evidence_referenced() -> None:
    observations = extract_workflow_observations(
        _crawled_data(),
        target_url="https://lab.example",
        scope_checker=lambda url: url.startswith("https://lab.example"),
    )

    assert observations
    item = observations[0]
    assert item.scope_decision == "allowed"
    assert item.destructive is True
    assert item.evidence_refs and item.evidence_refs[0].startswith("workflow:")
    serialized = item.model_dump_json()
    assert "order-42" not in serialized
    assert "secret-token" not in serialized
    assert "alice" not in serialized


def test_workflow_hypotheses_are_bounded_and_not_findings() -> None:
    observations = extract_workflow_observations(_crawled_data(), target_url="https://lab.example")
    specs = generate_business_logic_hypotheses(observations, target_url="https://lab.example")

    assert specs
    assert all(spec.maximum_attempts <= 1 for spec in specs)
    assert all(spec.request_budget <= 2 for spec in specs)
    assert all(spec.action_type in {"read_only_compare", "approval_required"} for spec in specs)
    assert all(not isinstance(spec, Hypothesis) for spec in specs)


def test_business_logic_confidence_uses_observable_workflow_signals() -> None:
    weak = WorkflowObservation(
        fingerprint="weak-observation",
        workflow_key="checkout",
        transition_key="review-to-submit",
        source_ref="workflow:weak",
        endpoint="https://lab.example/checkout",
        method="POST",
        signals=["form"],
        prerequisites=["authenticated_identity"],
        evidence_refs=["workflow:weak:evidence"],
        scope_decision="allowed",
    )
    strong = weak.model_copy(
        update={
            "fingerprint": "strong-observation",
            "signals": [
                "form",
                "method_sequence",
                "object_reference",
                "role_boundary",
                "workflow_intent",
            ],
            "identity_ref": "identity:hashed",
            "identity_context": ["role:hashed"],
            "authorization_boundary": "role_scoped",
            "object_refs": ["object:hashed"],
            "evidence_refs": ["workflow:strong:evidence", "workflow:strong:oracle"],
        }
    )

    weak_specs = generate_business_logic_hypotheses([weak], target_url="https://lab.example")
    strong_specs = generate_business_logic_hypotheses([strong], target_url="https://lab.example")

    assert weak_specs and strong_specs
    assert 0.0 <= weak_specs[0].confidence_score <= 1.0
    assert 0.0 <= strong_specs[0].confidence_score <= 1.0
    assert weak_specs[0].confidence_score != strong_specs[0].confidence_score


def test_workflow_coverage_reports_missing_metadata_without_finding() -> None:
    gaps = workflow_coverage_gaps({}, [])
    assert {item["gap"] for item in gaps} >= {
        "workflow_forms_missing",
        "workflow_sequence_missing",
    }


def test_legacy_business_logic_path_does_not_change_when_flag_is_off() -> None:
    state = {
        "target": {"url": "https://lab.example"},
        "findings": [],
        "crawled_data": {},
    }
    with patch(
        "webpent.config.settings.Settings.enable_workflow_understanding",
        False,
        create=True,
    ):
        result = business_logic_fuzzer_node(state)

    assert "hypotheses" not in result
    assert "workflow_observations" not in result
    assert "findings" not in result
    assert result["current_phase"] == "business_logic_fuzzing"
