"""Attack narratives and bounded research-budget allocation."""

from __future__ import annotations

from hashlib import sha256

from .contracts import AttackNarrative, BudgetAllocation, DiscoveryCandidateV2


class AutonomousAttackNarrativeBuilderV7:
    def build(self, candidates: tuple[DiscoveryCandidateV2, ...]) -> tuple[AttackNarrative, ...]:
        return tuple(
            AttackNarrative(
                narrative_id="narrative:"
                + sha256(candidate.candidate_id.encode()).hexdigest()[:16],
                attacker_goal=(
                    "reach or influence the protected asset across an unintended boundary"
                ),
                required_conditions=(
                    "attacker capability is realistic",
                    "the relevant identity/state boundary exists",
                    "a safe precondition is available",
                ),
                weakness_hypothesis=candidate.security_assumption,
                possible_impact=candidate.possible_impact,
                evidence_needed=candidate.validation_path,
                dependencies=(candidate.candidate_id, *candidate.source_refs),
                confidence=candidate.confidence,
            )
            for candidate in candidates
        )


class ResearchBudgetIntelligenceV7:
    """Rank effort by value while penalizing repeated low-information paths."""

    def allocate(
        self,
        *,
        candidates: tuple[DiscoveryCandidateV2, ...],
        narratives: tuple[AttackNarrative, ...] = (),
        attempted_ids: tuple[str, ...] = (),
        budget: float = 8.0,
    ) -> tuple[BudgetAllocation, ...]:
        if budget < 0:
            raise ValueError("research_budget_must_be_non_negative")
        attempted = set(attempted_ids)
        remaining = float(budget)
        rows: list[BudgetAllocation] = []
        for candidate in sorted(candidates, key=lambda item: (-item.confidence, item.candidate_id)):
            duplicate = 1.0 if candidate.candidate_id in attempted else 0.0
            likelihood = candidate.confidence
            impact = 0.65 if candidate.possible_impact else 0.0
            uncertainty = 1.0 - candidate.confidence
            evidence_value = min(1.0, len(candidate.validation_path) / 4)
            exploration_cost = min(1.0, 0.35 + 0.1 * len(candidate.validation_path))
            utility = max(
                0.0,
                min(
                    1.0,
                    0.30 * likelihood
                    + 0.25 * impact
                    + 0.25 * uncertainty
                    + 0.20 * evidence_value
                    - 0.35 * duplicate,
                ),
            )
            selected = remaining >= exploration_cost and utility > 0.15
            if selected:
                remaining -= exploration_cost
            rows.append(
                BudgetAllocation(
                    allocation_id="allocation:"
                    + sha256(candidate.candidate_id.encode()).hexdigest()[:16],
                    subject_id=candidate.candidate_id,
                    likelihood=likelihood,
                    impact=impact,
                    uncertainty=uncertainty,
                    evidence_value=evidence_value,
                    exploration_cost=exploration_cost,
                    utility=utility,
                    rationale=(
                        "value combines likelihood, impact, uncertainty, evidence "
                        "value, cost, and duplicate-path penalty"
                    ),
                    duplicate_penalty=duplicate,
                    selected=selected,
                )
            )
        return tuple(rows)


__all__ = ["AutonomousAttackNarrativeBuilderV7", "ResearchBudgetIntelligenceV7"]
