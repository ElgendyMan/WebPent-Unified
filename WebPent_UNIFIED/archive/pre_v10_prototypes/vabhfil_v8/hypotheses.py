"""Evolving hypotheses with evidence discipline and no confirmation authority."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import HypothesisDisposition, SecurityHypothesisV8
from .utils import evidence_refs, get_value, stable_id


@dataclass(frozen=True, slots=True)
class AutonomousHypothesisEvolutionV8:
    def create(self, investigations: tuple[object, ...]) -> tuple[SecurityHypothesisV8, ...]:
        result: list[SecurityHypothesisV8] = []
        for item in investigations:
            assumption = str(get_value(item, "assumption", default="unresolved assumption"))
            weakness = str(get_value(item, "potential_weakness", default="potential control gap"))
            refs = evidence_refs(item)
            result.append(
                SecurityHypothesisV8(
                    hypothesis_id=stable_id("hypothesis", assumption, weakness),
                    statement=f"The control assumption '{assumption}' may be unsafe: {weakness}.",
                    supporting_evidence=refs,
                    conflicting_evidence=(),
                    confidence_history=(0.25 if not refs else 0.45,),
                    next_validation_action=(
                        "obtain candidate/control observations and apply the causal oracle"
                    ),
                    disposition=HypothesisDisposition.HYPOTHESIS,
                    source_refs=refs,
                )
            )
        return tuple(result)

    def compare(
        self,
        hypotheses: tuple[SecurityHypothesisV8, ...],
        *,
        conflicting_evidence: dict[str, tuple[str, ...]] | None = None,
    ) -> tuple[SecurityHypothesisV8, ...]:
        conflicts = conflicting_evidence or {}
        compared: list[SecurityHypothesisV8] = []
        for hypothesis in hypotheses:
            new_conflicts = tuple(
                sorted(
                    set(hypothesis.conflicting_evidence)
                    | set(conflicts.get(hypothesis.hypothesis_id, ()))
                )
            )
            if new_conflicts:
                confidence = max(0.0, hypothesis.confidence - 0.2)
                disposition = (
                    HypothesisDisposition.REJECTED
                    if confidence < 0.25
                    else HypothesisDisposition.INCONCLUSIVE
                )
            else:
                confidence = hypothesis.confidence
                disposition = hypothesis.disposition
            compared.append(
                SecurityHypothesisV8(
                    hypothesis_id=hypothesis.hypothesis_id,
                    statement=hypothesis.statement,
                    supporting_evidence=hypothesis.supporting_evidence,
                    conflicting_evidence=new_conflicts,
                    confidence_history=(*hypothesis.confidence_history, confidence),
                    next_validation_action=hypothesis.next_validation_action,
                    disposition=disposition,
                    merged_into=hypothesis.merged_into,
                    source_refs=hypothesis.source_refs,
                )
            )
        return tuple(compared)

    def merge_related(
        self, hypotheses: tuple[SecurityHypothesisV8, ...]
    ) -> tuple[SecurityHypothesisV8, ...]:
        merged: list[SecurityHypothesisV8] = []
        seen: dict[str, SecurityHypothesisV8] = {}
        for hypothesis in hypotheses:
            key = hypothesis.statement.split(":", 1)[0].lower()
            if key not in seen:
                seen[key] = hypothesis
                merged.append(hypothesis)
                continue
            parent = seen[key]
            merged[-1] = SecurityHypothesisV8(
                hypothesis_id=parent.hypothesis_id,
                statement=parent.statement,
                supporting_evidence=tuple(
                    sorted(set(parent.supporting_evidence) | set(hypothesis.supporting_evidence))
                ),
                conflicting_evidence=tuple(
                    sorted(set(parent.conflicting_evidence) | set(hypothesis.conflicting_evidence))
                ),
                confidence_history=parent.confidence_history,
                next_validation_action=parent.next_validation_action,
                disposition=HypothesisDisposition.MERGED,
                merged_into=parent.hypothesis_id,
                source_refs=tuple(sorted(set(parent.source_refs) | set(hypothesis.source_refs))),
            )
        return tuple(merged)

    def reject_weak(
        self, hypotheses: tuple[SecurityHypothesisV8, ...]
    ) -> tuple[SecurityHypothesisV8, ...]:
        return tuple(
            SecurityHypothesisV8(
                hypothesis_id=item.hypothesis_id,
                statement=item.statement,
                supporting_evidence=item.supporting_evidence,
                conflicting_evidence=item.conflicting_evidence,
                confidence_history=item.confidence_history,
                next_validation_action=item.next_validation_action,
                disposition=(
                    HypothesisDisposition.REJECTED
                    if not item.supporting_evidence and item.conflicting_evidence
                    else item.disposition
                ),
                merged_into=item.merged_into,
                source_refs=item.source_refs,
            )
            for item in hypotheses
        )


__all__ = ["AutonomousHypothesisEvolutionV8"]
