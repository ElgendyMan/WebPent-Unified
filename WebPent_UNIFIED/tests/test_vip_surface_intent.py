"""Regression contracts for passive application-intent and identity enrichment."""

from webpent.shared.surface_security import analyze_security_surface
from webpent.shared.workflow_understanding import (
    extract_workflow_observations,
    generate_business_logic_hypotheses,
)


def _identity_workflow_data() -> dict:
    return {
        "endpoints": ["https://lab.example/orders/approve?account_id=42"],
        "forms": [
            {
                "action": "/orders/approve",
                "method": "POST",
                "requires_auth": True,
                "actor_role": "reviewer",
                "authorization_scope": "orders:approve",
                "account_id": "account-42",
                "operation": "approve order",
                "workflow": "order-review",
            }
        ],
        "workflow_observations": [
            {"fingerprint": "workflow-fingerprint-123456789", "workflow": "order-review"}
        ],
    }


def test_surface_summary_enriches_intent_without_plaintext_identity() -> None:
    data = _identity_workflow_data()
    summary = analyze_security_surface(data, "https://lab.example")
    serialized = str(summary)

    assert "transactional" in summary["application_intent"]
    assert "privileged_administration" in summary["application_intent"]
    assert summary["identity_context_refs"]
    assert summary["workflow_refs"]
    assert "reviewer" not in serialized
    assert "account-42" not in serialized


def test_workflow_identity_context_is_opaque_and_hypothesis_is_gated() -> None:
    data = _identity_workflow_data()
    observations = extract_workflow_observations(data, target_url="https://lab.example")
    assert observations
    item = observations[0]
    assert item.authorization_boundary == "role_scoped"
    assert "identity_context" in item.signals
    assert item.identity_ref is None or item.identity_ref.startswith("identity:")
    assert "reviewer" not in item.model_dump_json()

    specs = generate_business_logic_hypotheses(observations, target_url="https://lab.example")
    identity_specs = [spec for spec in specs if "identity_boundary" in spec.origin_detail]
    assert identity_specs
    assert all(spec.action_type == "approval_required" for spec in identity_specs)
    assert all(spec.request_budget == 0 for spec in identity_specs)
