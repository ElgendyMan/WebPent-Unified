"""Deep assumption-violation discovery for ABHIE v6."""

from __future__ import annotations

from collections.abc import Iterable

from webpent.abhip.contracts import TargetIntelligenceGraph

from .contracts import DiscoveryCandidate, V6Status


class DeepDiscoveryEngineV6:
    """Turn graph gaps and weak relations into evidence-linked hypotheses."""

    VERSION = "abhie-deep-discovery-v6"

    def discover(
        self,
        *,
        graph: TargetIntelligenceGraph,
        additional_assumptions: Iterable[str] = (),
    ) -> tuple[DiscoveryCandidate, ...]:
        if not isinstance(graph, TargetIntelligenceGraph):
            raise TypeError("target_intelligence_graph_required")
        assumptions = tuple(
            sorted({str(item).strip() for item in additional_assumptions if str(item).strip()})
        )
        gaps = tuple(
            sorted({str(item).strip() for item in graph.coverage_gaps if str(item).strip()})
        )
        if not gaps:
            gaps = ("ownership consistency", "privilege consistency", "workflow authorization")
        candidates: list[DiscoveryCandidate] = []
        assets = tuple(node.node_id for node in graph.nodes[:8]) or ("unmapped_asset",)
        evidence_refs = tuple(
            ref for node in graph.nodes for ref in node.evidence_refs if str(ref).strip()
        )
        for index, gap in enumerate(gaps):
            assumption = assumptions[index] if index < len(assumptions) else gap
            candidates.append(
                DiscoveryCandidate(
                    candidate_id=f"v6-candidate-{index + 1:03d}",
                    violated_assumption=f"Security must preserve {assumption}",
                    affected_assets=assets,
                    reasoning_chain=(
                        f"graph gap: {gap}",
                        "compare expected security invariant with recorded behavior",
                        "require candidate/control evidence before any verdict",
                    ),
                    evidence_requirements=(
                        "source or observation reference",
                        "candidate and independent negative control",
                        "central causal oracle",
                        "sealed and replayable ProofBundle",
                    ),
                    validation_plan=(
                        "remain offline until approved bounded execution exists",
                        "compare identity/role/state/action dimensions",
                        "stop on missing precondition or evidence",
                    ),
                    source_refs=tuple(sorted(set(evidence_refs))),
                    confidence=max(0.2, min(0.8, 0.45 + 0.05 * len(evidence_refs))),
                    status=V6Status.ADVISORY,
                )
            )
        return tuple(candidates)


__all__ = ["DeepDiscoveryEngineV6"]
