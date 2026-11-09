"""Controlled alternative research directions for ABHIE v6."""

from __future__ import annotations

from collections.abc import Sequence

from .contracts import CreativeDirection, DiscoveryCandidate


class ResearchCreativityEngineV6:
    """Generate bounded alternative explanations instead of premature conclusions."""

    VERSION = "abhie-creativity-v6"

    def explore(
        self,
        *,
        candidate: DiscoveryCandidate,
        evidence_refs: Sequence[str] = (),
    ) -> tuple[CreativeDirection, ...]:
        if not isinstance(candidate, DiscoveryCandidate):
            raise TypeError("discovery_candidate_required")
        refs = tuple(sorted({str(ref).strip() for ref in evidence_refs if str(ref).strip()}))
        if not refs:
            refs = candidate.source_refs
        directions = (
            (
                "benign-explanation",
                "The behavior may be expected under an undocumented role or workflow state.",
                "role and workflow documentation",
                "Check allowed conditions before treating the signal as a deviation.",
            ),
            (
                "stale-model-explanation",
                "The recorded model may be stale or incomplete rather than the control being weak.",
                "knowledge freshness and source lineage",
                "Refresh only through an approved evidence path and compare hashes.",
            ),
            (
                "boundary-explanation",
                (
                    "A trust-boundary relationship may explain the difference without "
                    "a security failure."
                ),
                "trust boundaries and indirect relationships",
                "Map both sides of the boundary and require an independent control.",
            ),
        )
        return tuple(
            CreativeDirection(
                direction_id=f"{candidate.candidate_id}:{direction_id}",
                question="What else could explain this behavior?",
                alternative_explanation=explanation,
                related_area=area,
                evidence_refs=refs,
                rank=index,
                rationale=rationale,
            )
            for index, (direction_id, explanation, area, rationale) in enumerate(
                directions, start=1
            )
        )


__all__ = ["ResearchCreativityEngineV6"]
