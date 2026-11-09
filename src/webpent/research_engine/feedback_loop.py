"""Bounded observation feedback and hypothesis lifecycle integration.

This module only updates auditable hypothesis state and advisory memory.  It
never executes an action, creates a finding, or treats an inference as proof.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.hypothesis import Hypothesis, HypothesisStatus
from webpent.research_engine.campaign_state import CampaignState
from webpent.research_engine.hypothesis_manager import HypothesisManager
from webpent.research_engine.research_state import ResearchTask
from webpent.shared.security_reasoning_memory import SecurityReasoningMemory

FeedbackOutcome = Literal["validated", "rejected", "blocked", "inconclusive"]


class ObservationFeedback(BaseModel):
    """Redacted feedback from one bounded experiment."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    hypothesis_id: str = Field(min_length=1, max_length=160)
    outcome: FeedbackOutcome | str = "inconclusive"
    causal_signal: bool = False
    negative_control_complete: bool = False
    central_proof: bool = False
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=20)
    rationale: str = Field(default="", max_length=1000)

    @field_validator("outcome", mode="before")
    @classmethod
    def _normalize_outcome(cls, value: Any) -> str:
        outcome = str(value or "inconclusive").strip().lower()
        allowed = {"validated", "rejected", "blocked", "inconclusive"}
        return outcome if outcome in allowed else "inconclusive"


class FeedbackResult(BaseModel):
    """Auditable feedback result; it carries no execution authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis: Hypothesis
    previous_status: str
    new_status: str
    accepted: bool
    outcome: str
    stop_reason: str
    evidence_refs: tuple[str, ...] = ()
    learning_memory_id: str | None = None
    advisory_only: bool = True


class ObservationFeedbackLoop:
    """Apply safe feedback, lifecycle transitions, and scoped learning."""

    def __init__(self, *, memory: SecurityReasoningMemory | None = None) -> None:
        self._manager = HypothesisManager()
        self._memory = memory

    @staticmethod
    def _refs(feedback: ObservationFeedback) -> tuple[str, ...]:
        return tuple(dict.fromkeys(feedback.evidence_refs))

    def apply(
        self,
        hypothesis: Hypothesis | dict[str, Any],
        feedback: ObservationFeedback,
    ) -> FeedbackResult:
        current = self._manager.transition(
            hypothesis,
            HypothesisStatus.INVESTIGATING,
            reason="feedback loop admitted hypothesis for bounded validation",
        ).hypothesis
        previous = str(current.status)
        outcome = str(feedback.outcome)
        refs = self._refs(feedback)

        # A validated outcome is never accepted by this facade unless the
        # central verifier has already supplied a proof-backed decision.
        if outcome == "validated" and not (
            feedback.causal_signal
            and feedback.negative_control_complete
            and feedback.central_proof
            and refs
        ):
            outcome = "inconclusive"
            reason = "validation withheld: causal, negative-control, and central proof are required"
        elif outcome == "rejected" and not feedback.negative_control_complete:
            outcome = "inconclusive"
            reason = "rejection withheld: independent negative control is incomplete"
        elif outcome == "blocked":
            reason = "experiment blocked by a bounded precondition or capability gate"
        elif outcome == "inconclusive":
            reason = "experiment was inconclusive; hypothesis remains open"
        else:
            reason = "proof-backed experiment outcome accepted by lifecycle contract"

        observation = {
            "outcome": outcome,
            "causal_signal": feedback.causal_signal,
            "negative_control_complete": feedback.negative_control_complete,
            "evidence_refs": list(refs),
        }
        transition = self._manager.record_observation(current, observation)
        memory_id: str | None = None
        if self._memory is not None:
            learning_outcome = {
                "validated": "supported",
                "rejected": "rejected",
                "blocked": "blocked",
                "inconclusive": "inconclusive",
            }[outcome]
            lesson = self._memory.learn_from_outcome(
                hypothesis_id=feedback.hypothesis_id,
                outcome=learning_outcome,
                rationale=feedback.rationale or reason,
                evidence_refs=refs,
            )
            memory_id = lesson.id if lesson is not None else None

        return FeedbackResult(
            hypothesis=transition.hypothesis,
            previous_status=previous,
            new_status=transition.new_status,
            accepted=transition.accepted,
            outcome=outcome,
            stop_reason=reason if not transition.accepted else transition.reason,
            evidence_refs=refs,
            learning_memory_id=memory_id,
        )

    def apply_to_campaign(
        self,
        campaign_state: CampaignState,
        task_id: str,
        hypothesis: Hypothesis | dict[str, Any],
        feedback: ObservationFeedback,
        *,
        discovered_assets: tuple[str, ...] = (),
        evidence_summary: Mapping[str, str] | None = None,
        task_status: Literal["completed", "failed", "blocked"] | None = None,
    ) -> tuple[FeedbackResult, CampaignState]:
        """Project explicit feedback into bounded campaign bookkeeping.

        This method stores references and redacted summaries only. It does not
        execute a task, create a finding, or promote a hypothesis by itself.
        """
        result = self.apply(hypothesis, feedback)
        resolved_status = result.new_status in {
            HypothesisStatus.RESOLVED_TRUE.value,
            HypothesisStatus.RESOLVED_FALSE.value,
            HypothesisStatus.LEARNED.value,
            HypothesisStatus.ABANDONED.value,
        }
        active = [
            item for item in campaign_state.active_hypotheses if item != feedback.hypothesis_id
        ]
        if not resolved_status:
            active.append(feedback.hypothesis_id[:160])
        assets = list(campaign_state.discovered_assets)
        for asset in discovered_assets:
            clean_asset = str(asset).strip()[:240]
            if clean_asset and clean_asset not in assets:
                assets.append(clean_asset)
        status = task_status or ("blocked" if result.outcome == "blocked" else "completed")
        next_state = campaign_state.mark_task(task_id, status)
        summary = dict(next_state.evidence_summary)
        summary[f"feedback:{feedback.hypothesis_id[:100]}"] = result.outcome[:80]
        if result.evidence_refs:
            summary[f"evidence:{feedback.hypothesis_id[:100]}"] = ",".join(result.evidence_refs)[
                :400
            ]
        if evidence_summary:
            summary.update(
                {str(key)[:120]: str(value)[:400] for key, value in evidence_summary.items()}
            )
        next_state = next_state.evolve(
            event_id=f"feedback:{feedback.hypothesis_id[:120]}",
            active_hypotheses=tuple(dict.fromkeys(active)),
            discovered_assets=tuple(dict.fromkeys(assets)),
            evidence_summary=summary,
        )
        return result, next_state

    def apply_task_feedback(
        self,
        task: ResearchTask,
        hypothesis: Hypothesis | dict[str, Any],
        feedback: ObservationFeedback,
    ) -> FeedbackResult:
        """Convenience method that requires a task capability before feedback."""
        required = getattr(task, "required_capability", "")
        if not str(required).strip():
            blocked = feedback.model_copy(
                update={"outcome": "blocked", "rationale": "task capability missing"}
            )
            return self.apply(hypothesis, blocked)
        return self.apply(hypothesis, feedback)


__all__ = ["FeedbackOutcome", "FeedbackResult", "ObservationFeedback", "ObservationFeedbackLoop"]
