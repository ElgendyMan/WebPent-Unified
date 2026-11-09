"""Unknown weakness exploration without vulnerability claims."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .contracts import BrainObservation, ResearchBrainState


@dataclass(frozen=True, slots=True)
class DiscoveryDirection:
    direction_id: str
    category: str
    reasoning_chain: tuple[str, ...]
    affected_assets: tuple[str, ...]
    violated_assumption: str
    expected_impact: str
    validation_strategy: tuple[str, ...]
    confidence: float


class UnknownVulnerabilityDiscoveryEngine:
    CATEGORIES = (
        "unexpected_trust_relationship",
        "missing_authorization_boundary",
        "incorrect_workflow_assumption",
        "inconsistent_state_transition",
        "data_ownership_mistake",
    )

    def discover(
        self,
        state: ResearchBrainState,
        observations: Iterable[BrainObservation] = (),
    ) -> tuple[DiscoveryDirection, ...]:
        items = tuple(observations) or state.known
        assets = tuple(sorted({item.asset for item in items}))
        if not assets:
            assets = ("unmapped-asset",)
        assumption_text = tuple(item.statement for item in state.risky_assumptions)
        directions: list[DiscoveryDirection] = []
        templates = (
            (
                "trust",
                "An observed relationship may grant more trust than its source context warrants.",
                "unauthorized trust propagation",
            ),
            (
                "authorization",
                "A sensitive action may lack an explicit identity or role boundary.",
                "cross-boundary action reachability",
            ),
            (
                "workflow",
                "A workflow transition may rely on client or sequence assumptions.",
                "invalid business state transition",
            ),
            (
                "state",
                "A state transition may not preserve the invariant across adjacent states.",
                "inconsistent security state",
            ),
            (
                "ownership",
                "An object reference may not be bound to the requesting owner.",
                "cross-owner data exposure or action",
            ),
        )
        for index, (category, statement, impact) in enumerate(templates):
            source = (
                assumption_text[index % len(assumption_text)]
                if assumption_text
                else "missing explicit security invariant"
            )
            evidence = tuple(item.observation_id for item in items if item.domain)
            directions.append(
                DiscoveryDirection(
                    direction_id=f"unknown-{index}-{category}",
                    category=self.CATEGORIES[index],
                    reasoning_chain=(
                        f"observed assets: {', '.join(assets[:4])}",
                        statement,
                        f"candidate violated assumption: {source}",
                    ),
                    affected_assets=assets[:8],
                    violated_assumption=source,
                    expected_impact=impact,
                    validation_strategy=(
                        "compare authorized candidate and independent negative control",
                        "require causal oracle and sealed replayable evidence",
                        f"use recorded evidence only: {', '.join(evidence[:4]) or 'none'}",
                    ),
                    confidence=0.35 if not evidence else 0.5,
                )
            )
        return tuple(directions)


class DiscoveryEngine(UnknownVulnerabilityDiscoveryEngine):
    """Compatibility alias for concise integrations."""


UnknownDiscoveryEngine = UnknownVulnerabilityDiscoveryEngine
