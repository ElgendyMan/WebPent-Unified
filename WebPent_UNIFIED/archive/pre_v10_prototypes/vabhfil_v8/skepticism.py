"""False-positive defense: challenge possible findings before any promotion."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import HypothesisDisposition, ResearchConfidenceReportV8
from .utils import stable_id, unique_sorted


@dataclass(frozen=True, slots=True)
class ExpertFalsePositiveDefenseV8:
    def assess(
        self,
        *,
        subject_id: str,
        intended_behavior_possible: bool = True,
        attacker_capability_realistic: bool = False,
        impact_proven: bool = False,
        alternative_explanations: tuple[str, ...] = (),
        reproducible_by_another_researcher: bool = False,
        evidence_refs: tuple[str, ...] = (),
    ) -> ResearchConfidenceReportV8:
        missing: list[str] = []
        if intended_behavior_possible:
            missing.append("intended behavior has not been ruled out")
        if not attacker_capability_realistic:
            missing.append("realistic attacker capability is not established")
        if not impact_proven:
            missing.append("impact is not causally proven")
        if alternative_explanations:
            missing.append("alternative explanations remain")
        if not reproducible_by_another_researcher:
            missing.append("independent reproduction is absent")
        complete = not missing
        return ResearchConfidenceReportV8(
            report_id=stable_id("confidence", subject_id, evidence_refs, missing),
            subject_id=subject_id,
            intended_behavior_possible=intended_behavior_possible,
            attacker_capability_realistic=attacker_capability_realistic,
            impact_proven=impact_proven,
            alternative_explanations=unique_sorted(alternative_explanations),
            reproducible_by_another_researcher=reproducible_by_another_researcher,
            missing_evidence=unique_sorted(missing),
            confidence=0.85 if complete else max(0.05, 0.85 - 0.12 * len(missing)),
            disposition=HypothesisDisposition.RETAINED
            if complete
            else HypothesisDisposition.INCONCLUSIVE,
            oracle_overridden=False,
            confirmation_created=False,
        )


__all__ = ["ExpertFalsePositiveDefenseV8"]
