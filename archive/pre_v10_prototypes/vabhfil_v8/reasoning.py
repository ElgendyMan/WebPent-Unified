"""Senior-researcher reasoning chain over recorded models."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import ExpertSecurityInvestigationV8, V8Status
from .utils import evidence_refs, get_value, stable_id, strings, unique_sorted


@dataclass(frozen=True, slots=True)
class ExpertSecurityReasoningModelV8:
    max_investigations: int = 8

    def investigate(
        self,
        *,
        engagement_id: str,
        target_id: str,
        mental_model: object | None = None,
        assumptions: tuple[str, ...] = (),
        evidence_refs_input: tuple[str, ...] = (),
    ) -> tuple[ExpertSecurityInvestigationV8, ...]:
        model_assumptions = strings(
            get_value(mental_model, "security_assumptions", "important_assumptions")
        )
        all_assumptions = unique_sorted((*assumptions, *model_assumptions))
        if not all_assumptions:
            all_assumptions = ("security-relevant behavior is not yet sufficiently recorded",)
        trust = strings(get_value(mental_model, "trust_relationships", "authorization_boundaries"))
        workflows = strings(
            get_value(mental_model, "sensitive_workflows", "user_journeys", "business_logic")
        )
        boundary = trust[0] if trust else "trust boundary is not established in recorded state"
        workflow = (
            workflows[0]
            if workflows
            else "workflow semantics are not established in recorded state"
        )
        refs = tuple(sorted(set(evidence_refs_input) | set(evidence_refs(mental_model))))
        investigations: list[ExpertSecurityInvestigationV8] = []
        for assumption in all_assumptions[: self.max_investigations]:
            investigations.append(
                ExpertSecurityInvestigationV8(
                    investigation_id=stable_id(
                        "investigation", engagement_id, target_id, assumption
                    ),
                    security_question=(
                        f"Which recorded behavior depends on the assumption: {assumption}?"
                    ),
                    assumption=assumption,
                    potential_weakness=(
                        "a missing authorization, ownership, state, or workflow control could "
                        "make the assumption unsafe"
                    ),
                    evidence_needed=(
                        "explicit intended-behavior evidence",
                        "attacker-capability boundary",
                        "candidate/control observation pair",
                        "causal oracle and independent reproduction",
                    ),
                    validation_approach=(
                        f"map the assumption to boundary: {boundary}",
                        f"trace the recorded workflow: {workflow}",
                        "compare candidate and negative control under identical safe preconditions",
                        "stop unless sealed replayable evidence is available",
                    ),
                    attacker_capability=(
                        "use only capabilities explicitly represented in recorded state"
                    ),
                    trust_boundary=boundary,
                    business_impact=(
                        "impact remains unproven until the causal oracle distinguishes outcomes"
                    ),
                    confidence=0.35 if not refs else 0.5,
                    source_refs=refs,
                    status=V8Status.ADVISORY,
                )
            )
        return tuple(investigations)


__all__ = ["ExpertSecurityReasoningModelV8"]
