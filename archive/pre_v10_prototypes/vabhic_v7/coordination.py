"""Specialist coordination and false-positive skepticism for VABHIC v7."""

from __future__ import annotations

from hashlib import sha256

from .contracts import (
    CoordinationReport,
    Disposition,
    SecurityMentalModel,
    SkepticismAssessment,
    SpecialistContribution,
    V7Status,
)


class MultiAgentResearchCoordinatorV7:
    SPECIALTIES = ("recon", "authorization", "business_logic", "evidence", "validation")

    def coordinate(
        self, *, model: SecurityMentalModel, candidate_ids: tuple[str, ...] = ()
    ) -> CoordinationReport:
        contributions = tuple(
            SpecialistContribution(
                specialist_id=f"specialist:{specialty}",
                specialty=specialty,
                question=(
                    model.unresolved_questions[index % len(model.unresolved_questions)]
                    if model.unresolved_questions
                    else "Which evidence is still missing for this research boundary?"
                ),
                reasoning=(
                    f"review the model from the {specialty} perspective",
                    "cite existing evidence only",
                    "separate hypothesis from confirmation",
                ),
                evidence_refs=model.evidence_refs,
            )
            for index, specialty in enumerate(self.SPECIALTIES)
        )
        questions = tuple(dict.fromkeys(item.question for item in contributions))
        conflicts = (
            tuple("specialists must not infer causality from reachability alone" for _ in [0])
            if candidate_ids
            else ()
        )
        return CoordinationReport(
            coordination_id="coordination:"
            + sha256(f"{model.model_id}|{candidate_ids}".encode()).hexdigest()[:16],
            contributions=contributions,
            shared_questions=questions,
            resolved_conflicts=(),
            unresolved_conflicts=conflicts,
            communication_evidence=model.evidence_refs,
            status=V7Status.ADVISORY,
        )


class FalsePositiveSkepticismV7:
    def assess(
        self,
        *,
        candidate_id: str,
        possible_impact: str,
        evidence_refs: tuple[str, ...],
        causal_oracle_present: bool = False,
        proof_replay_verified: bool = False,
        attacker_capability_realistic: bool = False,
    ) -> SkepticismAssessment:
        challenges: list[str] = []
        alternatives = (
            "intended behavior or a missing business requirement",
            "an observation or display difference without security impact",
            "an environment or fixture mismatch",
        )
        if not causal_oracle_present:
            challenges.append("causal oracle is absent")
        if not evidence_refs:
            challenges.append("no evidence references are available")
        if not possible_impact:
            challenges.append("impact is not described")
        if not proof_replay_verified:
            challenges.append("sealed proof replay is not verified")
        if not attacker_capability_realistic:
            challenges.append("attacker capability is not established")
        demonstrated = bool(possible_impact and causal_oracle_present and proof_replay_verified)
        reproducible = bool(evidence_refs and proof_replay_verified)
        confidence = (
            0.85 if demonstrated and attacker_capability_realistic else 0.25 if challenges else 0.55
        )
        return SkepticismAssessment(
            assessment_id="skepticism:" + sha256(candidate_id.encode()).hexdigest()[:16],
            subject_id=candidate_id,
            intended_behavior_possible=True,
            alternative_explanations=alternatives,
            attacker_capability_realistic=attacker_capability_realistic,
            impact_demonstrated=demonstrated,
            evidence_reproducible=reproducible,
            challenges=tuple(challenges),
            confidence=confidence,
            disposition=Disposition.BLOCKED if challenges else Disposition.ADVISORY,
        )


__all__ = ["FalsePositiveSkepticismV7", "MultiAgentResearchCoordinatorV7"]
