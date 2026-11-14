"""Composition root for the ABHIE v6 intelligence layer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from webpent.abhip.contracts import TargetIntelligenceGraph
from webpent.asros.world_model import SecurityWorldModel

from .agent_core import ResearchAgentCoreV6
from .architect import ArchitectReviewV6
from .chains import AttackChainIntelligenceV6
from .contracts import (
    AgentResearchState,
    ArchitectReviewReport,
    AttackChainHypothesis,
    CreativeDirection,
    DifferentialSignalV6,
    DiscoveryCandidate,
    InvariantReasoning,
    ResearchDecision,
)
from .creativity import ResearchCreativityEngineV6
from .differential import DifferentialAnalysisV6
from .discovery import DeepDiscoveryEngineV6
from .invariants import InvariantReasoningSystemV6


@dataclass(frozen=True, slots=True)
class ABHIEV6Result:
    state: AgentResearchState
    decisions: tuple[ResearchDecision, ...]
    candidates: tuple[DiscoveryCandidate, ...]
    invariants: tuple[InvariantReasoning, ...]
    chains: tuple[AttackChainHypothesis, ...]
    creative_directions: tuple[CreativeDirection, ...]
    differentials: tuple[DifferentialSignalV6, ...]
    architect_review: ArchitectReviewReport
    requests_sent: int = 0
    mutations_performed: bool = False
    finding_created: bool = False

    def __post_init__(self) -> None:
        if self.requests_sent != 0 or self.mutations_performed or self.finding_created:
            raise ValueError("abhie_v6_result_cannot_execute_or_create_finding")


class ABHIEV6Core:
    """Run the v6 research intelligence lifecycle without routing actions."""

    VERSION = "abhie-v6"

    def __init__(self) -> None:
        self.agent = ResearchAgentCoreV6()
        self.discovery = DeepDiscoveryEngineV6()
        self.invariants = InvariantReasoningSystemV6()
        self.chains = AttackChainIntelligenceV6()
        self.creativity = ResearchCreativityEngineV6()
        self.differential = DifferentialAnalysisV6()
        self.architect = ArchitectReviewV6()

    def run(
        self,
        *,
        graph: TargetIntelligenceGraph,
        world_model: SecurityWorldModel | None = None,
        evidence_state: Mapping[str, object] | None = None,
        coverage_state: Mapping[str, object] | None = None,
        left_context: Mapping[str, object] | None = None,
        right_context: Mapping[str, object] | None = None,
        evidence_refs: Sequence[str] = (),
    ) -> ABHIEV6Result:
        decisions = self.agent.plan(
            graph=graph,
            evidence_state=evidence_state,
            coverage_state=coverage_state,
        )
        candidates = self.discovery.discover(graph=graph)
        invariant_results = self.invariants.assess(world_model=world_model) if world_model else ()
        chains = self.chains.generate(
            graph=graph,
            candidates=candidates,
            invariants=invariant_results,
        )
        creative = tuple(
            direction
            for candidate in candidates
            for direction in self.creativity.explore(
                candidate=candidate,
                evidence_refs=evidence_refs,
            )
        )
        differentials = ()
        if left_context is not None and right_context is not None:
            differentials = self.differential.compare(
                comparison_id=f"{graph.target_id}:v6",
                left=left_context,
                right=right_context,
                evidence_refs=evidence_refs,
            )
        hypothesis = (
            {
                "id": candidates[0].candidate_id,
                "reason": candidates[0].violated_assumption,
                "affected_asset": candidates[0].affected_assets[0],
                "evidence_refs": candidates[0].source_refs or tuple(evidence_refs),
                "attack_plan": candidates[0].validation_plan,
            }
            if candidates
            else {"id": "v6-no-candidate"}
        )
        review = self.architect.review(
            engagement_id=graph.engagement_id,
            target_id=graph.target_id,
            subject_id=hypothesis["id"],
            hypothesis=hypothesis,
            argument_chain=chains[0] if chains else None,
            evidence_refs=evidence_refs or tuple(hypothesis["evidence_refs"]),
            observation_count=0,
        )
        state = AgentResearchState(
            engagement_id=graph.engagement_id,
            target_id=graph.target_id,
            decisions=decisions,
            candidates=candidates,
            invariant_reasoning=invariant_results,
            chains=chains,
            creative_directions=creative,
            differentials=differentials,
            stop_reason="advisory lifecycle complete; execution not requested",
        )
        return ABHIEV6Result(
            state=state,
            decisions=decisions,
            candidates=candidates,
            invariants=invariant_results,
            chains=chains,
            creative_directions=creative,
            differentials=differentials,
            architect_review=review,
        )


__all__ = ["ABHIEV6Core", "ABHIEV6Result"]
