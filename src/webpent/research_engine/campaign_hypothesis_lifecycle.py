"""Campaign-local lifecycle projection over the canonical hypothesis engine.

The campaign labels in this module are a projection only.  The canonical
``HypothesisStatus`` state machine remains unchanged, and this facade never
creates findings, grants execution authority, or overrides a central oracle.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.hypothesis import Hypothesis, HypothesisStatus
from webpent.research.hypothesis_engine import HypothesisEngine
from webpent.research_engine.hypothesis_manager import HypothesisManager

CampaignLifecycleLabel = Literal["CREATED", "SUPPORTED", "VALIDATED", "REJECTED", "BLOCKED"]


class LifecycleProjectionResult(BaseModel):
    """Auditable projection result with no finding or execution authority."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    hypothesis: Hypothesis
    requested_label: CampaignLifecycleLabel
    canonical_status: str
    accepted: bool
    reasons: tuple[str, ...] = Field(default=(), max_length=16)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=20)
    advisory_only: bool = True
    finding_created: bool = False


class CampaignHypothesisLifecycle:
    """Map campaign labels to safe canonical hypothesis transitions."""

    def __init__(self, *, manager: HypothesisManager | None = None) -> None:
        self._manager = manager or HypothesisManager()

    @staticmethod
    def _status(hypothesis: Hypothesis) -> str:
        status = hypothesis.status
        return status.value if isinstance(status, HypothesisStatus) else str(status)

    @staticmethod
    def _refs(evidence_refs: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(str(ref)[:240] for ref in evidence_refs if str(ref).strip()))

    @staticmethod
    def _result(
        hypothesis: Hypothesis,
        label: CampaignLifecycleLabel,
        *,
        accepted: bool,
        reasons: tuple[str, ...] = (),
        evidence_refs: tuple[str, ...] = (),
    ) -> LifecycleProjectionResult:
        return LifecycleProjectionResult(
            hypothesis=hypothesis,
            requested_label=label,
            canonical_status=(
                hypothesis.status.value
                if isinstance(hypothesis.status, HypothesisStatus)
                else str(hypothesis.status)
            ),
            accepted=accepted,
            reasons=reasons,
            evidence_refs=evidence_refs,
        )

    def project(
        self,
        hypothesis: Hypothesis | dict[str, Any],
        label: CampaignLifecycleLabel,
        *,
        causal_signal: bool = False,
        negative_control_complete: bool = False,
        central_proof: bool = False,
        evidence_refs: tuple[str, ...] | list[str] = (),
        reason: str = "",
    ) -> LifecycleProjectionResult:
        """Apply a campaign label without changing global promotion semantics."""
        current = HypothesisEngine.coerce(hypothesis)
        refs = self._refs(evidence_refs)

        if label == "CREATED":
            return self._result(current, label, accepted=True, evidence_refs=refs)

        if label in {"SUPPORTED", "BLOCKED"}:
            if self._status(current) == HypothesisStatus.UNEXPLORED.value:
                transition = self._manager.transition(
                    current,
                    HypothesisStatus.INVESTIGATING,
                    reason=reason or f"campaign hypothesis {label.lower()} projection",
                    evidence_refs=refs,
                )
                if transition.accepted:
                    current = transition.hypothesis
            if label == "BLOCKED":
                return self._result(
                    current,
                    label,
                    accepted=self._status(current) == HypothesisStatus.INVESTIGATING.value,
                    reasons=("blocked_task_or_campaign_gate",),
                    evidence_refs=refs,
                )
            return self._result(
                current,
                label,
                accepted=self._status(current) == HypothesisStatus.INVESTIGATING.value,
                reasons=("supporting_evidence_is_not_proof",),
                evidence_refs=refs,
            )

        if label == "VALIDATED":
            missing: list[str] = []
            if not causal_signal:
                missing.append("causal_signal")
            if not negative_control_complete:
                missing.append("negative_control_complete")
            if not central_proof:
                missing.append("central_proof")
            if not refs:
                missing.append("evidence_refs")
            if missing:
                return self._result(
                    current,
                    label,
                    accepted=False,
                    reasons=("validation_gate_missing:" + ",".join(missing),),
                    evidence_refs=refs,
                )
            if self._status(current) == HypothesisStatus.UNEXPLORED.value:
                admitted = self._manager.transition(
                    current,
                    HypothesisStatus.INVESTIGATING,
                    reason="validated campaign hypothesis admitted for proof evaluation",
                    evidence_refs=refs,
                )
                if not admitted.accepted:
                    return self._result(
                        current,
                        label,
                        accepted=False,
                        reasons=(admitted.reason,),
                        evidence_refs=refs,
                    )
                current = admitted.hypothesis
            transition = self._manager.record_observation(
                current,
                {
                    "outcome": "validated",
                    "causal_signal": True,
                    "negative_control_complete": True,
                    "evidence_refs": list(refs),
                },
            )
            return self._result(
                transition.hypothesis,
                label,
                accepted=transition.accepted,
                reasons=(transition.reason,),
                evidence_refs=refs,
            )

        if label == "REJECTED":
            if not negative_control_complete:
                return self._result(
                    current,
                    label,
                    accepted=False,
                    reasons=("rejection_gate_missing:negative_control_complete",),
                    evidence_refs=refs,
                )
            if not refs:
                return self._result(
                    current,
                    label,
                    accepted=False,
                    reasons=("rejection_gate_missing:evidence_refs",),
                )
            if self._status(current) == HypothesisStatus.UNEXPLORED.value:
                admitted = self._manager.transition(
                    current,
                    HypothesisStatus.INVESTIGATING,
                    reason="rejected campaign hypothesis admitted for control evaluation",
                )
                if not admitted.accepted:
                    return self._result(current, label, accepted=False, reasons=(admitted.reason,))
                current = admitted.hypothesis
            transition = self._manager.record_observation(
                current,
                {
                    "outcome": "rejected",
                    "causal_signal": False,
                    "negative_control_complete": True,
                    "evidence_refs": list(refs),
                },
            )
            return self._result(
                transition.hypothesis,
                label,
                accepted=transition.accepted,
                reasons=(transition.reason,),
                evidence_refs=refs,
            )

        raise ValueError("unsupported_campaign_lifecycle_label")


__all__ = [
    "CampaignHypothesisLifecycle",
    "CampaignLifecycleLabel",
    "LifecycleProjectionResult",
]
