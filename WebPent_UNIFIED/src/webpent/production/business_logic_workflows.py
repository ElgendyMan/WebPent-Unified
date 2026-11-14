# src/webpent/production/business_logic_workflows.py
"""webpent.production.business_logic_workflows — Track 12, item 5.

Roadmap contract (المسار 12، البند 5 — تحليل منطق الأعمال):

    نمذجة تدفقات عمل متعددة الخطوات في بيئات اختبار أو ضمن تفويض صريح،
    بحدود تشغيل محافظة ومراجعة بشرية.

    ("Model multi-step business workflows in TEST environments or under
    explicit authorization, with CONSERVATIVE operational limits and
    HUMAN review.")

Design
------
This module models and VALIDATES multi-step workflow plans — it never
executes anything against a network by itself. Execution (when a human
approves) is delegated to the existing campaign machinery, which keeps
running through every scope gate.

* **Declarative model** — ``WorkflowModel`` = ordered ``WorkflowStep``s
  (identifier-level: action kind, target path template, description),
  bound to one client + one scope hash, and stamped with its
  environment: ``lab`` (a dedicated test environment) or
  ``authorized`` (explicit written authorization for THIS workflow).
* **Conservative limits (enforced, not advisory):** at most
  ``MAX_STEPS`` steps, single-step-at-a-time (no parallel execution of
  a business flow), a fixed FORBIDDEN action list
  (destructive/irreversible categories: payments, deletions, outbound
  email/SMS, password resets on real users, ...), and every step must
  belong to the workflow's own scope binding — one scope per workflow,
  no mixing.
* **Human review by construction:** ``plan_execution`` produces a
  review packet (plan + risks + explicit approval token) instead of
  running. Without a recorded human approval the plan stays a plan;
  ``execution_allowed`` is False until ``record_approval`` succeeds.
  Approval is per plan digest — any change to the model invalidates it.
* **Environment gate:** lab workflows are the default; an
  ``authorized`` workflow must carry the authorization reference, and
  the gate refuses anything else. There is no "production without
  authorization" path in the API.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "FORBIDDEN_ACTION_KINDS",
    "MAX_STEPS",
    "WorkflowEnvironment",
    "WorkflowModel",
    "WorkflowReviewPacket",
    "WorkflowStep",
    "plan_execution",
]

#: Conservative operational ceiling for a modeled business flow.
MAX_STEPS = 12

#: Action categories this platform will never model or execute against
#: a real system — destructive or irreversible business effects.
FORBIDDEN_ACTION_KINDS: frozenset[str] = frozenset(
    {
        "payment_or_charge",
        "data_deletion",
        "data_modification_persistent",
        "outbound_email_or_sms",
        "password_reset_or_account_lock",
        "privilege_grant",
        "third_party_api_call",
    }
)


class WorkflowEnvironment(str, Enum):
    """Where a modeled workflow is allowed to run."""

    LAB = "lab"                # dedicated test environment — the default
    AUTHORIZED = "authorized"  # explicit authorization for THIS flow


@dataclass
class WorkflowStep:
    """One identifier-level workflow step (no payloads)."""

    step_id: str
    action_kind: str        # e.g. "login", "add_to_cart", "apply_coupon"
    target_path: str        # path TEMPLATE within the authorized origin
    description: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "action_kind": self.action_kind,
            "target_path": self.target_path,
            "description": self.description,
        }


@dataclass
class WorkflowModel:
    """A multi-step business flow bound to one client + one scope."""

    name: str
    client_id: str
    scope_hash: str
    steps: list[WorkflowStep] = field(default_factory=list)
    environment: WorkflowEnvironment = WorkflowEnvironment.LAB
    authorization_ref: str = ""  # required when environment == AUTHORIZED
    origin: str = ""             # the single authorized origin, if any

    def plan_digest(self) -> str:
        """Stable digest of the plan — approvals bind to THIS digest."""
        payload = json.dumps(
            {
                "name": self.name,
                "client_id": self.client_id,
                "scope_hash": self.scope_hash,
                "environment": self.environment.value,
                "authorization_ref": self.authorization_ref,
                "origin": self.origin,
                "steps": [s.as_dict() for s in self.steps],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class WorkflowReviewPacket:
    """What the human reviewer sees (and what their approval binds to)."""

    ok_to_present: bool
    plan_digest: str
    workflow_name: str
    environment: str
    step_count: int
    violations: list[str] = field(default_factory=list)
    execution_allowed: bool = False
    review_checklist: list[str] = field(default_factory=list)
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok_to_present": self.ok_to_present,
            "plan_digest": self.plan_digest,
            "workflow_name": self.workflow_name,
            "environment": self.environment,
            "step_count": self.step_count,
            "violations": list(self.violations),
            "execution_allowed": self.execution_allowed,
            "review_checklist": list(self.review_checklist),
            "reason": self.reason,
        }


def plan_execution(workflow: WorkflowModel) -> WorkflowReviewPacket:
    """Validate a workflow against the conservative limits and produce
    the human-review packet. NEVER executes; ``execution_allowed`` is
    False until a human approval is recorded for this digest."""
    violations: list[str] = []

    if not workflow.name.strip():
        violations.append("workflow name is empty")
    if not workflow.scope_hash.strip():
        violations.append("workflow is not bound to a scope hash")
    if not workflow.steps:
        violations.append("workflow has no steps")
    if len(workflow.steps) > MAX_STEPS:
        violations.append(
            f"too many steps ({len(workflow.steps)} > conservative max {MAX_STEPS})"
        )
    for step in workflow.steps:
        if step.action_kind in FORBIDDEN_ACTION_KINDS:
            violations.append(
                f"step {step.step_id}: forbidden action kind "
                f"'{step.action_kind}' (destructive/irreversible)"
            )
    if (
        workflow.environment is WorkflowEnvironment.AUTHORIZED
        and not workflow.authorization_ref.strip()
    ):
        violations.append(
            "authorized environment requires an authorization reference"
        )

    digest = workflow.plan_digest()
    if violations:
        return WorkflowReviewPacket(
            ok_to_present=False,
            plan_digest=digest,
            workflow_name=workflow.name,
            environment=workflow.environment.value,
            step_count=len(workflow.steps),
            violations=violations,
            execution_allowed=False,
            reason="plan rejected by conservative limits — not presented for approval",
        )

    checklist = [
        "confirm every step target stays inside the authorized origin/scope",
        "confirm the environment matches the authorization actually held",
        "confirm no step can create an irreversible business effect",
        "confirm the flow will run one step at a time (no parallelism)",
        "set a wall-clock budget for the review window before approving",
    ]
    return WorkflowReviewPacket(
        ok_to_present=True,
        plan_digest=digest,
        workflow_name=workflow.name,
        environment=workflow.environment.value,
        step_count=len(workflow.steps),
        violations=[],
        execution_allowed=False,  # a plan stays a plan until record_approval
        review_checklist=checklist,
        reason="validated against conservative limits — awaiting human approval",
    )


def record_approval(
    packet: WorkflowReviewPacket,
    *,
    reviewer: str,
    approved: bool,
    approval_ledger: dict[str, dict[str, Any]] | None = None,
) -> WorkflowReviewPacket:
    """Record the human decision for a plan digest (pure + injectable
    ledger so callers can persist). Only the EXACT approved digest
    unlocks execution; any later model change yields a new digest and
    requires a new approval."""
    if approval_ledger is None:
        approval_ledger = {}
    if not packet.ok_to_present:
        return packet
    if approved and reviewer.strip():
        approval_ledger[packet.plan_digest] = {
            "reviewer": reviewer,
            "approved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        packet.execution_allowed = True
        packet.reason = f"human approval recorded ({reviewer})"
    else:
        packet.reason = "human approval refused or reviewer missing"
    return packet


def execution_allowed_for(workflow: WorkflowModel, approval_ledger: dict[str, Any]) -> bool:
    """Re-check the CURRENT digest against the approval ledger — the
    single authoritative gate used before any real execution handoff."""
    return bool(approval_ledger.get(workflow.plan_digest()))
