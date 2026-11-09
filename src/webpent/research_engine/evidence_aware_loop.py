"""Bounded evidence-aware research state machine.

The loop chooses and evaluates admissibility only.  It never performs HTTP,
browser, mutation, payload generation, finding promotion, or proof sealing.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

# Additive Team-1 research-entity integration (Phase 4): optional agenda bridge
# hook. Lazy-imported to keep the default import graph and historical behavior
# byte-identical when the hook is unused. ``AgendaBridge`` never bypasses GOED's
# own ``ResearchState.admit_task`` gates (scope/dedup/budget).
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from webpent.research_engine.research_budget import BudgetUsage, ResearchBudget, evaluate_budget
from webpent.research_engine.research_state import ResearchState, ResearchTask

if TYPE_CHECKING:
    from webpent.research_engine.agenda_bridge import AgendaBridge


class LoopStatus(StrEnum):
    READY = "ready"
    BLOCKED = "blocked"
    EVIDENCE_READY = "evidence_ready"
    STOPPED = "stopped"


class EvidenceAwareResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    status: LoopStatus
    engagement_id: str
    target_id: str
    selected_task_id: str | None = None
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    missing_evidence: tuple[str, ...] = Field(default=(), max_length=32)
    stop_reason: str = Field(default="", max_length=240)
    execution_attempted: bool = False
    finding_promotion_allowed: bool = False
    proof_authority: bool = False


class EvidenceAwareAgentLoop:
    """Run safe planning/evidence transitions behind hard fail-closed gates."""

    def __init__(self, budget: ResearchBudget | None = None) -> None:
        self.budget = budget or ResearchBudget()

    def evaluate(
        self,
        *,
        engagement_id: str,
        target_id: str,
        tasks: Iterable[ResearchTask] = (),
        available_capabilities: Iterable[str] = (),
        evidence_refs: Iterable[str] = (),
        required_evidence: Iterable[str] = (),
        usage: BudgetUsage | None = None,
        scope_authorized: bool = False,
        authority_mode: str = "read_only_explanation",
        central_proof_verified: bool = False,
        agenda_bridge: AgendaBridge | None = None,
    ) -> EvidenceAwareResult:
        state = ResearchState(
            engagement_id=engagement_id,
            target_id=target_id,
            budget=self.budget,
            usage=usage or BudgetUsage(),
        )
        for task in tasks:
            state = state.admit_task(task)
        # Additive Phase-4 hook: when an agenda bridge is supplied, merge its
        # planned research tasks into the SAME canonical ResearchState via
        # GOED's own admit_task (scope/dedup/budget gates preserved), then
        # re-order deterministically by priority so the agenda has real
        # downstream effect on experiment selection. Default (None) keeps
        # historical admission order and behavior byte-identical.
        if agenda_bridge is not None:
            from webpent.research_engine.agenda_bridge import AgendaBridge as _AB

            if not isinstance(agenda_bridge, _AB):
                raise TypeError("agenda_bridge_must_be_AgendaBridge_or_None")
            state = agenda_bridge.admit_into_state(state).updated_state
            ordered = sorted(
                state.tasks,
                key=lambda t: (-float(t.priority), t.task_id),
            )
            state = state.model_copy(update={"tasks": tuple(ordered)})
        decision = evaluate_budget(self.budget, state.usage)
        if not scope_authorized:
            return self._result(
                state,
                status=LoopStatus.BLOCKED,
                stop_reason="scope_authorization_required",
            )
        if authority_mode not in {"read_only_explanation", "safe-smart", "smart-observe"}:
            return self._result(
                state,
                status=LoopStatus.BLOCKED,
                stop_reason="unsupported_authority_mode",
            )
        if not decision.allowed:
            return self._result(state, status=LoopStatus.STOPPED, stop_reason=decision.reason)
        capabilities = {str(item).strip() for item in available_capabilities if str(item).strip()}
        selected = next(
            (task for task in state.tasks if task.required_capability in capabilities),
            None,
        )
        if selected is None:
            return self._result(
                state,
                status=LoopStatus.BLOCKED,
                stop_reason="required_capability_unavailable",
            )
        clean_refs = tuple(
            dict.fromkeys(str(item).strip()[:240] for item in evidence_refs if str(item).strip())
        )[:32]
        required = tuple(
            dict.fromkeys(
                str(item).strip()[:240] for item in required_evidence if str(item).strip()
            )
        )[:32]
        missing = tuple(item for item in required if item not in clean_refs)
        if missing:
            return self._result(
                state,
                status=LoopStatus.READY,
                selected_task_id=selected.task_id,
                evidence_refs=clean_refs,
                missing_evidence=missing,
                stop_reason="evidence_gate_pending",
            )
        if not central_proof_verified:
            return self._result(
                state,
                status=LoopStatus.EVIDENCE_READY,
                selected_task_id=selected.task_id,
                evidence_refs=clean_refs,
                stop_reason="central_verification_required",
            )
        return self._result(
            state,
            status=LoopStatus.EVIDENCE_READY,
            selected_task_id=selected.task_id,
            evidence_refs=clean_refs,
            stop_reason="central_proof_present_but_promotion_remains_external_governance",
        )

    @staticmethod
    def _result(
        state: ResearchState,
        *,
        status: LoopStatus,
        selected_task_id: str | None = None,
        evidence_refs: tuple[str, ...] = (),
        missing_evidence: tuple[str, ...] = (),
        stop_reason: str,
    ) -> EvidenceAwareResult:
        return EvidenceAwareResult(
            status=status,
            engagement_id=state.engagement_id,
            target_id=state.target_id,
            selected_task_id=selected_task_id,
            evidence_refs=evidence_refs,
            missing_evidence=missing_evidence,
            stop_reason=stop_reason,
        )


__all__ = ["EvidenceAwareAgentLoop", "EvidenceAwareResult", "LoopStatus"]
