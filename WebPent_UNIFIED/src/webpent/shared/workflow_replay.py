"""Plan-only workflow replay with explicit scope, identity, and cleanup gates."""

from __future__ import annotations

import hashlib

from webpent.models.workflow_replay import (
    CleanupAction,
    ReplayIdentityContext,
    ReplayStep,
    WorkflowReplayPlan,
)
from webpent.models.workflows import WorkflowObservation


def _ref(prefix: str, value: str) -> str:
    return f"{prefix}:{hashlib.sha256(value.encode('utf-8', 'ignore')).hexdigest()[:16]}"


def _state_ref(state: str, workflow_fingerprint: str) -> str:
    return _ref("state", f"{workflow_fingerprint}:{state}")


def build_workflow_replay_plan(
    observation: WorkflowObservation,
    *,
    identity_role: str = "unknown",
    session_health: str = "unknown",
    secret_ref: str | None = None,
) -> WorkflowReplayPlan:
    """Create a bounded plan; this function never performs a replay."""
    identity = ReplayIdentityContext(
        context_id=observation.identity_ref or _ref("identity", identity_role),
        role=identity_role,
        session_health=session_health,
        secret_ref=secret_ref,
        capability_refs=observation.identity_context[:8],
        tenant_ref=observation.tenant_ref,
        object_refs=observation.object_refs[:20],
    )
    step = ReplayStep(
        step_id=_ref("replay-step", observation.fingerprint),
        endpoint_ref=observation.endpoint,
        method=observation.method,
        expected_state=observation.to_state,
        evidence_needed=["response_state", "identity_boundary", "cleanup_status"],
        non_destructive=not observation.destructive,
        approval_required=True,
        request_fingerprint=observation.fingerprint,
        pre_state={
            "state_ref": observation.from_state,
            "fingerprint": _state_ref(observation.from_state, observation.fingerprint),
            "status": "unknown",
            "evidence_refs": observation.evidence_refs[:12],
        },
        post_state={
            "state_ref": observation.to_state,
            "fingerprint": _state_ref(observation.to_state, observation.fingerprint),
            "status": "unknown",
            "evidence_refs": observation.evidence_refs[:12],
        },
    )
    cleanup = CleanupAction(
        action_id=_ref("cleanup", observation.fingerprint),
        description="Restore any temporary workflow state and retain cleanup evidence.",
    )
    ready = observation.scope_decision == "allowed" and session_health == "healthy"
    status = "ready" if ready else "blocked"
    return WorkflowReplayPlan(
        plan_id=_ref("replay-plan", observation.fingerprint),
        workflow_fingerprint=observation.fingerprint,
        identity=identity,
        tenant_ref=observation.tenant_ref,
        object_refs=observation.object_refs[:20],
        steps=[step],
        cleanup=[cleanup],
        scope_decision=observation.scope_decision,
        status=status,
        approval_required=True,
        max_requests=1,
        executed=False,
        cleanup_status="required",
        cleanup_evidence_refs=[],
    )


__all__ = ["build_workflow_replay_plan"]
