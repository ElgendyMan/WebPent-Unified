"""Passive state-transition projection for business-logic analysis."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from webpent.intelligence.state_model import StateModel, StateSnapshot, StateTransition
from webpent.models.workflows import WorkflowObservation


class TransitionCandidate(BaseModel):
    """A possible illegal transition requiring a separately authorized replay."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    target_id: str = Field(..., min_length=1, max_length=200)
    engagement_id: str = Field(..., min_length=1, max_length=200)
    source_state: str = Field(..., min_length=1, max_length=120)
    target_state: str = Field(..., min_length=1, max_length=120)
    operation: str = Field(..., min_length=1, max_length=160)
    reason: str = Field(..., min_length=1, max_length=300)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    required_validation: list[str] = Field(
        default_factory=lambda: [
            "target_backed_state_observation",
            "independent_negative_control",
            "central_sealed_replayable_proof_bundle",
        ],
        max_length=8,
    )
    promotion_status: str = "candidate_only"


def _state_id(value: str) -> str:
    return value.strip().lower().replace(" ", "_")[:160] or "unknown"


class StateTransitionAnalyzer:
    """Build a known-state model and compare it to an explicit allow-list."""

    def build_model(
        self,
        observations: Iterable[WorkflowObservation],
        *,
        target_id: str,
        engagement_id: str,
    ) -> StateModel:
        model = StateModel(
            target_id=target_id.strip()[:200],
            engagement_id=engagement_id.strip()[:200],
        )
        for observation in observations:
            source = _state_id(observation.from_state)
            target = _state_id(observation.to_state)
            model.add_state(
                StateSnapshot(
                    state_id=source,
                    label=observation.from_state,
                    evidence_refs=observation.evidence_refs,
                )
            )
            model.add_state(
                StateSnapshot(
                    state_id=target,
                    label=observation.to_state,
                    evidence_refs=observation.evidence_refs,
                )
            )
            model.add_transition(
                StateTransition(
                    source_state_id=source,
                    target_state_id=target,
                    operation=f"{observation.method}:{observation.endpoint}",
                    observed=True,
                    evidence_refs=observation.evidence_refs,
                )
            )
        return model

    def find_candidates(
        self,
        observations: Iterable[WorkflowObservation],
        *,
        target_id: str,
        engagement_id: str,
        allowed_transitions: set[tuple[str, str]] | None = None,
    ) -> list[TransitionCandidate]:
        target_id = target_id.strip()
        engagement_id = engagement_id.strip()
        if not target_id or not engagement_id:
            raise ValueError("target_and_engagement_context_required")
        rows = list(observations)
        self.build_model(rows, target_id=target_id, engagement_id=engagement_id)
        allowed = {
            (_state_id(source), _state_id(target))
            for source, target in (allowed_transitions or set())
        }
        candidates: list[TransitionCandidate] = []
        seen: set[tuple[str, str, str]] = set()
        for observation in rows:
            source = _state_id(observation.from_state)
            target = _state_id(observation.to_state)
            key = (source, target, observation.method)
            if key in seen or (source, target) in allowed:
                continue
            if source == "unknown" or target == "unknown":
                continue
            seen.add(key)
            candidates.append(
                TransitionCandidate(
                    target_id=target_id,
                    engagement_id=engagement_id,
                    source_state=source,
                    target_state=target,
                    operation=f"{observation.method}:{observation.endpoint}",
                    reason=(
                        "transition is observed but absent from supplied "
                        "allowed-transition model"
                    ),
                    evidence_refs=observation.evidence_refs,
                )
            )
        return candidates[:128]


__all__ = ["StateTransitionAnalyzer", "TransitionCandidate"]
