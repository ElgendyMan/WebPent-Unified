"""Pure, disposable stateful workflow fixtures for IRTA v2."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum


class WorkflowState(StrEnum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    APPROVED = "approved"
    PAID = "paid"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class WorkflowRecord:
    workflow_id: str
    owner_id: str
    requester_id: str
    amount: int
    state: WorkflowState = WorkflowState.DRAFT
    coupon_uses: int = 0


class DisposableWorkflowFixture:
    """In-memory workflow fixture; no HTTP, credentials, or external side effects."""

    def __init__(self, record: WorkflowRecord) -> None:
        if record.amount <= 0 or not record.workflow_id:
            raise ValueError("workflow requires a positive amount and id")
        self._record = record
        self._snapshot = record

    @property
    def record(self) -> WorkflowRecord:
        return self._record

    def snapshot(self) -> WorkflowRecord:
        self._snapshot = self._record
        return self._snapshot

    def restore(self) -> WorkflowRecord:
        self._record = self._snapshot
        return self._record

    def transition(self, actor_id: str, action: str) -> WorkflowRecord:
        transitions = {
            (WorkflowState.DRAFT, "submit"): WorkflowState.SUBMITTED,
            (WorkflowState.SUBMITTED, "approve"): WorkflowState.APPROVED,
            (WorkflowState.APPROVED, "pay"): WorkflowState.PAID,
            (WorkflowState.SUBMITTED, "cancel"): WorkflowState.CANCELLED,
        }
        if not actor_id or (self._record.state, action) not in transitions:
            raise ValueError("invalid workflow transition")
        if action == "approve" and actor_id != self._record.owner_id:
            raise PermissionError("only the owner may approve")
        if action == "pay" and actor_id != self._record.requester_id:
            raise PermissionError("only the requester may pay")
        self._record = replace(self._record, state=transitions[(self._record.state, action)])
        return self._record

    def apply_coupon(self, actor_id: str) -> WorkflowRecord:
        if (
            actor_id != self._record.requester_id
            or self._record.state is not WorkflowState.APPROVED
        ):
            raise PermissionError("coupon requires the approved requester workflow")
        if self._record.coupon_uses >= 1:
            raise ValueError("coupon invariant prevents reuse")
        self._record = replace(self._record, coupon_uses=1)
        return self._record
