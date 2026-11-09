"""Security invariant reasoning over the existing ASROS world model."""

from __future__ import annotations

from collections.abc import Iterable

from webpent.asros.world_model import SecurityWorldModel

from .contracts import InvariantReasoning, InvariantResult


class InvariantReasoningSystemV6:
    """Assess falsifiable invariants without turning assessments into findings."""

    VERSION = "abhie-invariant-reasoning-v6"

    def assess(self, *, world_model: SecurityWorldModel) -> tuple[InvariantReasoning, ...]:
        if not isinstance(world_model, SecurityWorldModel):
            raise TypeError("security_world_model_required")
        results: list[InvariantReasoning] = []
        for invariant in sorted(world_model.invariants, key=lambda item: item.invariant_id):
            assessment = world_model.invariant_assessment(invariant.invariant_id)
            result = InvariantResult(assessment.result)
            evidence_refs = tuple(assessment.evidence_refs)
            confidence = (
                0.7
                if result in (InvariantResult.SUPPORTED, InvariantResult.DISPUTED) and evidence_refs
                else 0.2
            )
            if result == InvariantResult.BLOCKED:
                confidence = 0.0
            results.append(
                InvariantReasoning(
                    invariant_id=invariant.invariant_id,
                    statement=invariant.statement,
                    result=result,
                    source_evidence=evidence_refs or tuple(invariant.lineage.evidence_refs),
                    confidence=confidence,
                    affected_objects=(invariant.subject, invariant.protected_resource),
                    validation_strategy=(
                        "compare expected and observed behaviour",
                        "require candidate/control observations",
                        "require central causal oracle and replayable proof",
                    ),
                    rationale=assessment.rationale,
                )
            )
        return tuple(results)

    def assess_ids(
        self,
        *,
        world_model: SecurityWorldModel,
        invariant_ids: Iterable[str],
    ) -> tuple[InvariantReasoning, ...]:
        wanted = {str(item).strip() for item in invariant_ids if str(item).strip()}
        return tuple(
            item for item in self.assess(world_model=world_model) if item.invariant_id in wanted
        )


__all__ = ["InvariantReasoningSystemV6"]
