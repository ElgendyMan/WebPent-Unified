"""Bounded in-process ABHIE v4 composition."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from .boundaries import SecurityBoundaryMapper
from .chains import AttackChainIntelligence
from .competition import ExpertHypothesisEngine
from .contracts import (
    BrainObservation,
    EvidenceAssessment,
    EvidenceState,
    ResearchBrainState,
    ResearchQualityScore,
)
from .discovery import UnknownVulnerabilityDiscoveryEngine
from .reflection import ReflectionMemory
from .review import SeniorResearchReviewer
from .strategy import ExpertStrategySelector


class ABHIECoreV4:
    """Runs one deterministic advisory research pass over recorded inputs."""

    def __init__(self) -> None:
        self.discovery = UnknownVulnerabilityDiscoveryEngine()
        self.boundaries = SecurityBoundaryMapper()
        self.competition = ExpertHypothesisEngine()
        self.strategy = ExpertStrategySelector()
        self.reflection = ReflectionMemory()
        self.chains = AttackChainIntelligence()
        self.reviewer = SeniorResearchReviewer()

    def run(
        self,
        *,
        brain: ResearchBrainState,
        observations: Iterable[BrainObservation] = (),
    ) -> dict[str, object]:
        observations = tuple(observations)
        updated_brain = replace(
            brain,
            known=tuple(sorted(brain.known + observations, key=lambda item: item.observation_id)),
            unknowns=tuple(sorted(set(brain.unknowns).union(self._unknowns(observations)))),
        )
        directions = self.discovery.discover(updated_brain)
        assumptions = updated_brain.risky_assumptions
        boundary_graph = self.boundaries.map(
            target_ref=brain.target_ref,
            **self._boundary_inputs(updated_brain),
        )
        competition = self.competition.prioritize(
            self.competition.generate(
                observation_id=observations[0].observation_id if observations else "recorded-pass",
                assumptions=assumptions,
                crossings=boundary_graph.crossings,
                assets=tuple(item.asset for item in observations),
            )
        )
        winner = next(
            (
                item
                for item in competition.candidates
                if item.hypothesis_id == competition.winner_id
            ),
            None,
        )
        strategy = self.strategy.select(hypothesis_id=winner.hypothesis_id if winner else "none")
        chains = self.chains.build(competition.candidates)
        evidence = EvidenceAssessment(
            causal=EvidenceState.MISSING,
            negative_control=EvidenceState.MISSING,
            proof_bundle=EvidenceState.MISSING,
            replay=EvidenceState.MISSING,
            completeness=0.0,
            contradictions=(),
        )
        review = (
            self.reviewer.review(
                target_ref=brain.target_ref,
                hypothesis=winner,
                evidence=evidence,
                real_boundary=bool(boundary_graph.crossings),
                failed_assumption=bool(assumptions),
                impact_demonstrated=False,
            )
            if winner
            else None
        )
        quality = ResearchQualityScore(
            discovery_quality=self._ratio(len(directions), len(observations)),
            reasoning_quality=self._ratio(len(competition.candidates), 3),
            evidence_quality=0.0,
            efficiency=1.0,
            coverage_improvement=self._ratio(len(boundary_graph.nodes), max(1, len(observations))),
        )
        return {
            "brain": updated_brain,
            "assumptions": assumptions,
            "discovery_directions": directions,
            "boundary_graph": boundary_graph,
            "competition": competition,
            "strategy": strategy,
            "chains": chains,
            "evidence": evidence,
            "review": review,
            "quality": quality,
            "executed": False,
            "requests": 0,
            "finding_created": False,
        }

    @staticmethod
    def _boundary_inputs(
        brain: ResearchBrainState,
    ) -> dict[str, tuple[dict[str, str], ...]]:
        grouped: dict[str, list[dict[str, str]]] = {
            "users": [],
            "roles": [],
            "resources": [],
            "actions": [],
            "workflows": [],
            "trust_levels": [],
            "states": [],
        }
        domain_map = {
            "user": "users",
            "identity": "users",
            "principal": "users",
            "role": "roles",
            "resource": "resources",
            "asset": "resources",
            "endpoint": "resources",
            "route": "resources",
            "action": "actions",
            "workflow": "workflows",
            "trust": "trust_levels",
            "state": "states",
        }
        for item in brain.known:
            key = domain_map.get(item.domain.lower())
            if key:
                grouped[key].append(
                    {
                        "id": item.asset,
                        "label": item.statement,
                        "trust_level": item.domain,
                    }
                )
        if not grouped["resources"]:
            grouped["resources"] = [{"id": item.asset, "label": item.asset} for item in brain.known]
        return {key: tuple(values) for key, values in grouped.items()}

    @staticmethod
    def _unknowns(observations: tuple[BrainObservation, ...]) -> tuple[str, ...]:
        return tuple(
            sorted(
                f"{item.domain}:{item.asset}:causal-boundary-unverified"
                for item in observations
                if not item.evidence_refs
            )
        )

    @staticmethod
    def _ratio(numerator: int, denominator: int) -> float:
        return round(min(1.0, numerator / denominator), 6) if denominator else 0.0
