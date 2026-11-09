from webpent.models.workflows import WorkflowObservation
from webpent.shared.workflow_replay import build_workflow_replay_plan


def _observation(*, scope_decision: str = "allowed", destructive: bool = False):
    return WorkflowObservation(
        fingerprint="wf-fingerprint-001",
        workflow_key="checkout",
        transition_key="cart-to-paid",
        source_ref="obs:checkout",
        endpoint="https://app.test/orders",
        method="POST",
        from_state="cart",
        to_state="paid",
        signals=["workflow_intent", "identity_context"],
        identity_ref="identity:owner",
        identity_context=["owner"],
        authorization_boundary="same_identity",
        evidence_refs=["ev:response"],
        scope_decision=scope_decision,
        destructive=destructive,
    )


def test_replay_plan_is_ready_only_for_allowed_healthy_identity():
    plan = build_workflow_replay_plan(
        _observation(), identity_role="owner", session_health="healthy", secret_ref="vault:owner"
    )

    assert plan.status == "ready"
    assert plan.approval_required is True
    assert plan.executed is False
    assert plan.identity.session_health == "healthy"
    assert plan.identity.secret_ref == "vault:owner"
    assert plan.steps[0].approval_required is True
    assert plan.cleanup[0].status == "required"


def test_replay_plan_blocks_unknown_scope_or_unhealthy_session():
    unknown_scope = build_workflow_replay_plan(
        _observation(scope_decision="unknown"), identity_role="owner", session_health="healthy"
    )
    stale_session = build_workflow_replay_plan(
        _observation(), identity_role="owner", session_health="stale"
    )

    assert unknown_scope.status == "blocked"
    assert stale_session.status == "blocked"
    assert unknown_scope.executed is False
    assert stale_session.cleanup[0].status == "required"


def test_destructive_observation_never_removes_approval_or_cleanup_requirements():
    plan = build_workflow_replay_plan(
        _observation(destructive=True), identity_role="owner", session_health="healthy"
    )

    assert plan.status == "ready"
    assert plan.steps[0].non_destructive is False
    assert plan.steps[0].approval_required is True
    assert plan.cleanup
    assert plan.executed is False
