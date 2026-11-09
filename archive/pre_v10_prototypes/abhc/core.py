"""Composition root for the bounded ABHC v3 research core."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .boundaries import SecurityBoundaryReasoner
from .chains import PotentialAttackChainReasoner
from .contracts import ABHCOutput, CoverageState, WeakSignal
from .director import AutonomousResearchDirector
from .experiments import BoundedExperimentPlanner
from .exploration import AdaptiveSurfaceExplorer
from .hypotheses import HypothesisEvolutionEngine
from .quality import FindingQualityEngine


class ABHCCore:
    """Run one bounded advisory research pass over recorded/modelled inputs."""

    def __init__(self, *, budget: float = 5.0) -> None:
        self.director = AutonomousResearchDirector(budget=budget)
        self.explorer = AdaptiveSurfaceExplorer()
        self.hypotheses = HypothesisEvolutionEngine()
        self.boundaries = SecurityBoundaryReasoner()
        self.experiments = BoundedExperimentPlanner()
        self.quality = FindingQualityEngine()
        self.chains = PotentialAttackChainReasoner()

    def research(
        self,
        *,
        world_model: object | None = None,
        attack_graph: object | None = None,
        knowledge_graph: object | None = None,
        memory: object | None = None,
        prior_coverage: CoverageState | Mapping[str, object] | None = None,
        weak_signals: Sequence[WeakSignal] = (),
        available_capabilities: Sequence[str] = (),
    ) -> ABHCOutput:
        missions = self.director.decide(
            world_model=world_model,
            attack_graph=attack_graph,
            knowledge_graph=knowledge_graph,
            memory=memory,
            coverage=prior_coverage,
        )
        surfaces = self.explorer.explore(
            attack_graph=attack_graph,
            world_model=world_model,
            prior_coverage=prior_coverage,
        )
        assumption_map = {
            surface.surface_id: self._assumption(surface.category) for surface in surfaces.surfaces
        }
        hypotheses = self.hypotheses.create_from_surfaces(surfaces, assumptions=assumption_map)
        boundary_map = self.boundaries.map_boundaries(
            attack_graph=attack_graph,
            world_model=world_model,
            hypotheses=hypotheses,
        )
        experiments = self.experiments.plan(
            hypotheses,
            boundary_map,
            available_capabilities=available_capabilities,
            budget=self.director.budget,
        )
        chains = self.chains.reason(
            hypotheses=hypotheses,
            boundaries=boundary_map.boundaries,
            weak_signals=weak_signals,
        )
        quality_reports = self.quality.batch_assess(hypotheses)
        from .review import AutonomousResearchReview

        review = AutonomousResearchReview().review(
            missions=missions,
            hypotheses=hypotheses,
            boundaries=boundary_map.boundaries,
            experiments=experiments,
            chains=chains,
            quality_reports=quality_reports,
        )
        return ABHCOutput(
            missions=missions,
            surfaces=surfaces,
            hypotheses=hypotheses,
            boundaries=boundary_map,
            experiments=experiments,
            chains=chains,
            quality_reports=quality_reports,
            review=review,
        )

    @staticmethod
    def _assumption(category: str) -> str:
        category = category.lower()
        if category in {"identity", "permission", "privilege", "role"}:
            return "identity and privilege boundaries are enforced"
        if category in {"workflow", "state"}:
            return "workflow state transitions are authorized"
        if category in {"resource", "object", "ownership"}:
            return "ownership and tenant boundaries are enforced"
        return "the modeled security invariant is enforced"


__all__ = ["ABHCCore"]
