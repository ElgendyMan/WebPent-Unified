"""Passive specialist proposal generation.

Specialists provide bounded candidates for the existing research loop. They do
not execute actions, authorize transport, or promote findings.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.research import CandidateAction
from webpent.research_engine.research_state import ResearchTask


class SpecialistProposal(BaseModel):
    """A proposal pair that remains outside execution and confirmation paths."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    specialist: str = Field(min_length=2, max_length=64)
    candidate_action: CandidateAction
    research_task: ResearchTask
    proposal_only: bool = True
    execution_authority: str = "ActionAuthority_required"


def _action_id(specialist: str, target_id: str, objective: str) -> str:
    digest = hashlib.sha256(f"{specialist}|{target_id}|{objective}".encode()).hexdigest()[:16]
    return f"specialist:{specialist}:{digest}"


def propose_specialist_tasks(
    *,
    specialist: str,
    engagement_id: str,
    target_id: str,
    target_ref: str,
    objectives: Iterable[str],
    action_class: str,
    required_capabilities: Iterable[str] = (),
) -> tuple[SpecialistProposal, ...]:
    """Create deterministic, bounded, redaction-safe specialist proposals."""
    specialist = str(specialist).strip()[:64]
    engagement_id = str(engagement_id).strip()[:160]
    target_id = str(target_id).strip()[:160]
    target_ref = str(target_ref).strip()[:500]
    action_class = str(action_class).strip()[:64]
    capabilities = tuple(
        dict.fromkeys(
            str(item).strip()[:80] for item in required_capabilities if str(item).strip()
        )
    )[:12]
    if not specialist or not engagement_id or not target_id or not action_class:
        raise ValueError("specialist_scope_and_class_required")
    proposals: list[SpecialistProposal] = []
    for objective in objectives:
        clean_objective = str(objective).strip()[:500]
        if not clean_objective:
            continue
        action_id = _action_id(specialist, target_id, clean_objective)
        candidate = CandidateAction(
            action_id=action_id,
            action_class=action_class,
            objective=clean_objective,
            target_ref=target_ref,
            required_capabilities=list(capabilities),
            policy_tags=["proposal_only", "central_authority_required"],
            capability="http_read",
            requires_approval=True,
            idempotency_key=action_id,
            justification=f"{specialist} planning proposal; validation evidence required",
            metadata={"specialist": specialist, "engagement_id": engagement_id},
        )
        task = ResearchTask(
            task_id=f"{action_id}:research",
            engagement_id=engagement_id,
            target_id=target_id,
            objective=clean_objective,
            reason=f"specialist:{specialist}",
            priority=0.6,
            required_evidence=(
                "target_backed_causal_signal",
                "independent_negative_control",
                "central_sealed_replayable_proof_bundle",
            ),
            operation="plan",
        )
        proposals.append(
            SpecialistProposal(
                specialist=specialist,
                candidate_action=candidate,
                research_task=task,
            )
        )
    return tuple(proposals[:32])


def propose_api_surface_tasks(**kwargs: object) -> tuple[SpecialistProposal, ...]:
    """Passive API/discovery specialist facade."""
    return propose_specialist_tasks(
        action_class="api_surface_review", specialist="api_surface", **kwargs
    )


def propose_access_control_tasks(**kwargs: object) -> tuple[SpecialistProposal, ...]:
    """Passive authorization specialist facade."""
    return propose_specialist_tasks(
        action_class="access_control_review", specialist="access_control", **kwargs
    )


def propose_business_logic_tasks(**kwargs: object) -> tuple[SpecialistProposal, ...]:
    """Passive workflow/invariant specialist facade."""
    return propose_specialist_tasks(
        action_class="business_logic_review", specialist="business_logic", **kwargs
    )


__all__ = [
    "SpecialistProposal",
    "propose_access_control_tasks",
    "propose_api_surface_tasks",
    "propose_business_logic_tasks",
    "propose_specialist_tasks",
]
