# tests/test_business_logic_workflows.py
"""Track 12 item 5 — business-logic workflow modeling with conservative
limits and human review (plans never execute themselves)."""

from __future__ import annotations

from webpent.production.business_logic_workflows import (
    FORBIDDEN_ACTION_KINDS,
    MAX_STEPS,
    WorkflowEnvironment,
    WorkflowModel,
    WorkflowStep,
    execution_allowed_for,
    plan_execution,
    record_approval,
)


def make_workflow(**overrides) -> WorkflowModel:
    steps = overrides.pop(
        "steps",
        [
            WorkflowStep("s1", "login", "/login", "authenticate as test user"),
            WorkflowStep("s2", "add_to_cart", "/cart", "add item"),
            WorkflowStep("s3", "apply_coupon", "/coupon", "apply coupon twice (race)"),
        ],
    )
    return WorkflowModel(
        name=overrides.pop("name", "coupon-race-lab"),
        client_id=overrides.pop("client_id", "c1"),
        scope_hash=overrides.pop("scope_hash", "scope-abc"),
        steps=steps,
        environment=overrides.pop("environment", WorkflowEnvironment.LAB),
        authorization_ref=overrides.pop("authorization_ref", ""),
        origin=overrides.pop("origin", "https://lab.example.com"),
        **overrides,
    )


class TestConservativeLimits:
    def test_lab_plan_valid_and_not_executable(self):
        packet = plan_execution(make_workflow())
        assert packet.ok_to_present is True
        assert packet.execution_allowed is False  # a plan stays a plan
        assert packet.review_checklist

    def test_step_ceiling_enforced(self):
        steps = [WorkflowStep(f"s{i}", "browse", "/p", "") for i in range(MAX_STEPS + 1)]
        packet = plan_execution(make_workflow(steps=steps))
        assert packet.ok_to_present is False
        assert any("too many steps" in v for v in packet.violations)

    def test_forbidden_action_kinds_rejected(self):
        for kind in list(FORBIDDEN_ACTION_KINDS)[:4]:
            wf = make_workflow(
                steps=[WorkflowStep("s1", kind, "/x", "destructive")]
            )
            packet = plan_execution(wf)
            assert packet.ok_to_present is False
            assert any("forbidden action kind" in v for v in packet.violations)

    def test_scope_binding_required(self):
        packet = plan_execution(make_workflow(scope_hash=""))
        assert packet.ok_to_present is False
        assert any("scope" in v for v in packet.violations)

    def test_authorized_environment_requires_reference(self):
        packet = plan_execution(
            make_workflow(environment=WorkflowEnvironment.AUTHORIZED, authorization_ref="")
        )
        assert packet.ok_to_present is False
        assert any("authorization reference" in v for v in packet.violations)

    def test_empty_steps_rejected(self):
        packet = plan_execution(make_workflow(steps=[]))
        assert packet.ok_to_present is False


class TestHumanApproval:
    def test_approval_unlocks_exact_digest_only(self):
        wf = make_workflow()
        packet = plan_execution(wf)
        ledger: dict = {}
        approved = record_approval(
            packet, reviewer="analyst-1", approved=True, approval_ledger=ledger
        )
        assert approved.execution_allowed is True
        assert execution_allowed_for(wf, ledger) is True

        # ANY change to the model → new digest → approval void.
        wf.steps.append(WorkflowStep("s4", "checkout", "/checkout", ""))
        assert execution_allowed_for(wf, ledger) is False

    def test_refusal_records_nothing(self):
        packet = plan_execution(make_workflow())
        ledger: dict = {}
        result = record_approval(
            packet, reviewer="analyst-1", approved=False, approval_ledger=ledger
        )
        assert result.execution_allowed is False
        assert ledger == {}

    def test_rejected_plan_never_presents(self):
        wf = make_workflow(steps=[WorkflowStep("s1", "data_deletion", "/purge", "")])
        packet = plan_execution(wf)
        assert packet.ok_to_present is False
        approved = record_approval(packet, reviewer="x", approved=True)
        assert approved.execution_allowed is False


class TestPlanDigest:
    def test_digest_stable_and_sensitive(self):
        wf = make_workflow()
        d1 = wf.plan_digest()
        d2 = make_workflow().plan_digest()
        assert d1 == d2  # deterministic
        wf2 = make_workflow(origin="https://other.example.com")
        assert wf2.plan_digest() != d1
