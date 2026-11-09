"""VABHIC v7 composition root: advisory research intelligence only."""

from __future__ import annotations

from dataclasses import dataclass

from .commander import AutonomousResearchCommanderV7
from .contracts import VABHICV7Result
from .coordination import FalsePositiveSkepticismV7, MultiAgentResearchCoordinatorV7
from .discovery import UnknownVulnerabilityDiscoveryV2
from .mental_model import SecurityMentalModelBuilderV7
from .narrative_budget import AutonomousAttackNarrativeBuilderV7, ResearchBudgetIntelligenceV7


@dataclass(frozen=True, slots=True)
class VABHICV7Core:
    commander: AutonomousResearchCommanderV7 = AutonomousResearchCommanderV7()
    model_builder: SecurityMentalModelBuilderV7 = SecurityMentalModelBuilderV7()
    discovery: UnknownVulnerabilityDiscoveryV2 = UnknownVulnerabilityDiscoveryV2()
    narratives: AutonomousAttackNarrativeBuilderV7 = AutonomousAttackNarrativeBuilderV7()
    budget: ResearchBudgetIntelligenceV7 = ResearchBudgetIntelligenceV7()
    coordinator: MultiAgentResearchCoordinatorV7 = MultiAgentResearchCoordinatorV7()
    skepticism: FalsePositiveSkepticismV7 = FalsePositiveSkepticismV7()

    VERSION = "vabhic-v7"

    def run(
        self,
        *,
        engagement_id: str,
        target_id: str,
        world_model: object | None = None,
        attack_graph: object | None = None,
        invariants: object | None = None,
        memory: object | None = None,
        coverage: object | None = None,
        previous_results: object | None = None,
        evidence_refs: tuple[str, ...] = (),
        attempted_ids: tuple[str, ...] = (),
    ) -> VABHICV7Result:
        plan = self.commander.plan(
            engagement_id=engagement_id,
            target_id=target_id,
            world_model=world_model,
            attack_graph=attack_graph,
            invariants=invariants,
            memory=memory,
            coverage=coverage,
            previous_results=previous_results,
        )
        model = self.model_builder.build(
            engagement_id=engagement_id,
            target_id=target_id,
            world_model=world_model,
            attack_graph=attack_graph,
            knowledge=memory,
            evidence_refs=evidence_refs,
        )
        candidates = self.discovery.discover(
            model=model, attack_graph=attack_graph, recorded_results=previous_results
        )
        narratives = self.narratives.build(candidates)
        allocations = self.budget.allocate(
            candidates=candidates,
            narratives=narratives,
            attempted_ids=attempted_ids,
            budget=self.commander.budget,
        )
        coordination = self.coordinator.coordinate(
            model=model, candidate_ids=tuple(candidate.candidate_id for candidate in candidates)
        )
        skepticism = tuple(
            self.skepticism.assess(
                candidate_id=candidate.candidate_id,
                possible_impact=candidate.possible_impact,
                evidence_refs=candidate.source_refs,
                causal_oracle_present=False,
                proof_replay_verified=False,
                attacker_capability_realistic=False,
            )
            for candidate in candidates
        )
        return VABHICV7Result(
            engagement_id=engagement_id,
            target_id=target_id,
            command_plan=plan,
            mental_model=model,
            candidates=candidates,
            narratives=narratives,
            allocations=allocations,
            coordination=coordination,
            skepticism=skepticism,
        )


__all__ = ["VABHICV7Core"]
