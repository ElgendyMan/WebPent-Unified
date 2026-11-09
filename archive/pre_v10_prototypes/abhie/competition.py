"""Competing security hypotheses with explicit alternatives."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from .contracts import (
    BoundaryCrossing,
    Hypothesis,
    HypothesisCompetition,
    Lifecycle,
    SecurityAssumption,
)


class ExpertHypothesisEngine:
    def generate(
        self,
        *,
        observation_id: str,
        assumptions: Iterable[SecurityAssumption] = (),
        crossings: Iterable[BoundaryCrossing] = (),
        assets: Iterable[str] = (),
    ) -> HypothesisCompetition:
        assumptions = tuple(assumptions)
        crossings = tuple(crossings)
        assets = tuple(sorted({str(item) for item in assets})) or ("unknown-asset",)
        source = assumptions[0] if assumptions else None
        crossing = crossings[0] if crossings else None
        base_refs = tuple(source.source_refs) if source else ()
        boundary_text = (
            f"{crossing.source_node} may reach {crossing.destination_node}"
            if crossing
            else "a security boundary is insufficiently specified"
        )
        candidates = (
            Hypothesis(
                hypothesis_id=f"{observation_id}-authorization",
                statement=f"Authorization boundary may be weaker than intended: {boundary_text}.",
                why_it_matters=(
                    "A cross-principal or cross-role path could change "
                    "the security outcome."
                ),
                supporting_evidence=base_refs,
                missing_evidence=("causal candidate observation", "independent negative control"),
                alternative_explanations=(
                    "the path may be intentionally public",
                    "the observation may reflect routing only",
                ),
                validation_plan=(
                    "compare authorized candidate/control behavior",
                    "apply central causal oracle",
                    "seal and replay evidence",
                ),
                affected_assets=assets,
                assumption_id=source.assumption_id if source else None,
                confidence=0.55 if source and crossing else 0.3,
            ),
            Hypothesis(
                hypothesis_id=f"{observation_id}-workflow",
                statement="A workflow or state assumption may permit an invalid transition.",
                why_it_matters="Business state and security state may diverge at a boundary.",
                supporting_evidence=base_refs,
                missing_evidence=("state transition observation", "causal oracle"),
                alternative_explanations=(
                    "the transition may be an intended recovery path",
                    "the state may be stale",
                ),
                validation_plan=(
                    "map adjacent states",
                    "compare expected and observed transition",
                    "require replayable proof",
                ),
                affected_assets=assets,
                assumption_id=source.assumption_id if source else None,
                confidence=0.48 if source else 0.25,
            ),
            Hypothesis(
                hypothesis_id=f"{observation_id}-benign",
                statement=(
                    "The signal may be benign reachability or an intentional "
                    "trust relationship."
                ),
                why_it_matters=(
                    "Avoiding false positives requires testing a non-vulnerability "
                    "explanation."
                ),
                supporting_evidence=base_refs,
                missing_evidence=("documented intended behavior",),
                alternative_explanations=(),
                validation_plan=("perform read-only comparison against a negative control",),
                affected_assets=assets,
                assumption_id=source.assumption_id if source else None,
                confidence=0.42,
            ),
        )
        ranked = tuple(sorted(candidates, key=lambda item: (-item.confidence, item.hypothesis_id)))
        winner = ranked[0] if ranked else None
        rationale = (
            "competition includes an explicit benign alternative",
            "confidence is advisory until causal and negative-control evidence exists",
            "selected by deterministic confidence ordering: "
            f"{winner.hypothesis_id if winner else 'none'}",
        )
        return HypothesisCompetition(
            observation_id=observation_id,
            candidates=ranked,
            winner_id=winner.hypothesis_id if winner else None,
            rationale=rationale,
        )

    def prioritize(self, competition: HypothesisCompetition) -> HypothesisCompetition:
        updated = tuple(
            replace(
                item,
                lifecycle=Lifecycle.PRIORITIZED
                if item.hypothesis_id == competition.winner_id
                else item.lifecycle,
            )
            for item in competition.candidates
        )
        return replace(competition, candidates=updated)
