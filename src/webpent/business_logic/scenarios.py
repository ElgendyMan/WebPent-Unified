"""Business-logic scenario catalog (additive to existing passive analyzers).

Mirrors the five-family contract in ``webpent.families.base`` so the
business_logic family participates in the same coverage/registry machinery.
"""
from __future__ import annotations

from webpent.families.base import EvidenceRequirement, FamilyId, ScenarioSpec

BUSINESS_LOGIC_SCENARIOS: tuple[ScenarioSpec, ...] = (
    ScenarioSpec(
        scenario_id="BIZ-001-price-manipulation",
        family=FamilyId.BUSINESS_LOGIC,
        name="Price / quantity manipulation at checkout",
        description=(
            "Unit price, quantity, or total is submitted client-side and "
            "trusted by the server without re-deriving from the catalog."
        ),
        preconditions=["checkout_endpoint", "price_in_request_body"],
        discriminator_experiment=(
            "Replay checkout with a tampered unit_price / negative quantity "
            "/ currency mismatch; verify the server re-derives totals."
        ),
        expected_signal="Order is accepted at the tampered (lower / negative) price.",
        negative_control="Untampered checkout completes at the catalog price.",
        evidence_requirements=[
            EvidenceRequirement(kind="tampered_checkout_replay", description="Replay with modified price fields"),
            EvidenceRequirement(kind="order_state_read", description="Final order total captured"),
        ],
        severity="high",
        references=["OWASP WSTG-BUSL-01", "CWE-841"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="BIZ-002-workflow-step-bypass",
        family=FamilyId.BUSINESS_LOGIC,
        name="Workflow / approval step bypass",
        description=(
            "A multi-step business workflow (order -> approve -> fulfill, "
            "draft -> review -> publish) accepts a direct transition to a "
            "later state without the intermediate approval."
        ),
        preconditions=["stateful_workflow", "state_field_in_request"],
        discriminator_experiment=(
            "Submit a resource directly in a terminal state (e.g. "
            "status=approved/published) skipping the review step."
        ),
        expected_signal="Resource enters terminal state without the required intermediate transition.",
        negative_control="Only valid transitions from the current state are accepted.",
        evidence_requirements=[
            EvidenceRequirement(kind="state_transition_replay", description="Direct terminal-state submission"),
            EvidenceRequirement(kind="post_state_read", description="Resource state after replay"),
        ],
        severity="high",
        references=["OWASP WSTG-BUSL-04", "CWE-841"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="BIZ-003-limit-quota-bypass",
        family=FamilyId.BUSINESS_LOGIC,
        name="Account / usage limit bypass via parallel accounts or fields",
        description=(
            "A free-tier limit (max items, trial days, max seats) is enforced "
            "per account or per a client-controlled field and can be evaded "
            "by splitting resources or tampering the counter."
        ),
        preconditions=["usage_limit_enforced", "counter_field_observable"],
        discriminator_experiment=(
            "Tamper the counter field / split the resource / reuse a trial "
            "identity; verify the limit is still enforced server-side."
        ),
        expected_signal="Usage exceeds the stated limit without payment / upgrade.",
        negative_control="Limit is enforced when the counter is untampered.",
        evidence_requirements=[
            EvidenceRequirement(kind="limit_replay", description="Attempts exceeding the limit"),
            EvidenceRequirement(kind="usage_state_read", description="Recorded usage after replay"),
        ],
        severity="medium",
        references=["CWE-770", "CWE-841"],
        safe_in_production=True,
    ),
    ScenarioSpec(
        scenario_id="BIZ-004-refund-return-abuse",
        family=FamilyId.BUSINESS_LOGIC,
        name="Refund / return / cancellation logic abuse",
        description=(
            "A refund or cancellation flow can be triggered after the "
            "benefit is consumed, or refunded twice by racing the flow."
        ),
        preconditions=["refund_or_cancel_flow", "digital_good_or_service"],
        discriminator_experiment=(
            "Consume the benefit then request refund; or issue two "
            "concurrent refund requests for the same order."
        ),
        expected_signal="Refund is issued after consumption / >1 refund for one order.",
        negative_control="Refund rejected after consumption / second refund rejected.",
        evidence_requirements=[
            EvidenceRequirement(kind="refund_replay", description="Refund request after consumption"),
            EvidenceRequirement(kind="balance_state_read", description="Account balance after refund"),
        ],
        severity="high",
        references=["CWE-841", "CWE-362"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="BIZ-005-inconsistent-authorization-matrix",
        family=FamilyId.BUSINESS_LOGIC,
        name="Inconsistent authorization across equivalent endpoints",
        description=(
            "The same business action is exposed via two equivalent routes "
            "(REST vs GraphQL vs RPC, or v1 vs v2); only one enforces the "
            "authorization check."
        ),
        preconditions=["multiple_api_surfaces", "equivalent_action_routes"],
        discriminator_experiment=(
            "Replay the same action on each equivalent route as an "
            "unauthorized actor; compare status codes."
        ),
        expected_signal="One route returns 2xx while another returns 403 for the same actor.",
        negative_control="All equivalent routes reject the unauthorized actor identically.",
        evidence_requirements=[
            EvidenceRequirement(kind="route_matrix_replay", description="Replay across equivalent routes"),
        ],
        severity="high",
        references=["CWE-863", "CWE-284"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="BIZ-006-numeric-boundary-abuse",
        family=FamilyId.BUSINESS_LOGIC,
        name="Numeric boundary abuse (integer overflow, negative, zero)",
        description=(
            "A numeric field (quantity, amount, page size, offset) accepts "
            "negative, zero, overflow, or fractional values that break "
            "business invariants (free order, unbounded pagination, DoS)."
        ),
        preconditions=["numeric_input_in_mutation"],
        discriminator_experiment=(
            "Submit boundary values (0, -1, MAX_INT, 0.01, NaN) and observe "
            "whether the invariant holds."
        ),
        expected_signal="A boundary value is accepted and violates the business invariant.",
        negative_control="Normal values behave correctly; boundary values are rejected.",
        evidence_requirements=[
            EvidenceRequirement(kind="boundary_replay", description="Boundary value submissions"),
            EvidenceRequirement(kind="post_state_read", description="Resulting state"),
        ],
        severity="medium",
        references=["CWE-190", "CWE-841"],
        safe_in_production=True,
    ),
)

__all__ = ["BUSINESS_LOGIC_SCENARIOS"]
