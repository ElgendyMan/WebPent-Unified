"""Evolving vulnerability hypotheses for ABHC v3."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from hashlib import sha256

from .contracts import EvolvingHypothesis, HypothesisStatus, SurfaceExplorationReport


class HypothesisEvolutionEngine:
    """Turn modeled surfaces and assumptions into auditable hypotheses."""

    def create_from_surfaces(
        self,
        report: SurfaceExplorationReport,
        *,
        assumptions: Mapping[str, str] | None = None,
        limit: int = 32,
    ) -> tuple[EvolvingHypothesis, ...]:
        if limit < 1:
            raise ValueError("hypothesis_limit_must_be_positive")
        assumptions = assumptions or {}
        result: list[EvolvingHypothesis] = []
        for surface in report.surfaces[:limit]:
            assumption = assumptions.get(surface.surface_id)
            if not assumption:
                assumption = self._default_assumption(surface.category)
            statement = (
                f"The modeled boundary around {surface.label} may not enforce "
                f"the intended {assumption}."
            )
            digest = sha256(f"{surface.surface_id}|{assumption}".encode()).hexdigest()[:16]
            result.append(
                EvolvingHypothesis(
                    hypothesis_id=f"hypothesis:{digest}",
                    statement=statement,
                    security_assumption=assumption,
                    target_area=surface.surface_id,
                    confidence=round(0.35 + 0.40 * surface.potential, 6),
                    evidence_refs=surface.evidence_refs,
                    required_validation=(
                        "canonical candidate observation",
                        "independent negative control",
                        "causal oracle",
                        "sealed replayable proof",
                    ),
                )
            )
        return tuple(result)

    def evolve(
        self,
        hypothesis: EvolvingHypothesis,
        *,
        evidence_refs: Iterable[str] = (),
        confidence: float | None = None,
        begin_validation: bool = False,
        rejection_reason: str = "",
    ) -> EvolvingHypothesis:
        current = hypothesis
        refs = tuple(evidence_refs)
        if rejection_reason:
            return current.reject(rejection_reason)
        if current.status is HypothesisStatus.NEW:
            current = current.start_investigation()
        if refs:
            current = current.attach_evidence(refs, confidence)
        elif confidence is not None:
            current = current.attach_evidence((), confidence)
        if begin_validation:
            current = current.begin_validation()
        return current

    @staticmethod
    def _default_assumption(category: str) -> str:
        normalized = category.lower()
        if normalized in {"identity", "privilege", "permission"}:
            return "identity and privilege boundaries are enforced consistently"
        if normalized in {"workflow", "state"}:
            return "workflow state transitions require the intended authorization"
        if normalized in {"resource", "object"}:
            return "object ownership and tenant scope are enforced"
        return "sensitive operations enforce an explicit security invariant"


__all__ = ["HypothesisEvolutionEngine"]
