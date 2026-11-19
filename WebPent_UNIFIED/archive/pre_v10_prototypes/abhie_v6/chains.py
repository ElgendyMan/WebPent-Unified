"""Complex attack-chain hypotheses for ABHIE v6."""

from __future__ import annotations

from collections.abc import Sequence

from webpent.abhip.contracts import TargetIntelligenceGraph

from .contracts import AttackChainHypothesis, DiscoveryCandidate, InvariantReasoning, V6Status


class AttackChainIntelligenceV6:
    """Join weak recorded signals into explainable, non-confirmed chains."""

    VERSION = "abhie-attack-chain-v6"

    def generate(
        self,
        *,
        graph: TargetIntelligenceGraph,
        candidates: Sequence[DiscoveryCandidate] = (),
        invariants: Sequence[InvariantReasoning] = (),
    ) -> tuple[AttackChainHypothesis, ...]:
        if not isinstance(graph, TargetIntelligenceGraph):
            raise TypeError("target_intelligence_graph_required")
        candidate_items = tuple(candidates)
        invariant_items = tuple(invariants)
        if not candidate_items and not invariant_items:
            return ()
        evidence_refs = tuple(
            sorted({ref for node in graph.nodes for ref in node.evidence_refs if str(ref).strip()})
        )
        chains: list[AttackChainHypothesis] = []
        for index, candidate in enumerate(candidate_items):
            related = next(
                (
                    item
                    for item in invariant_items
                    if set(item.affected_objects) & set(candidate.affected_assets)
                ),
                None,
            )
            dependency_ids = (candidate.candidate_id,) + (
                (related.invariant_id,) if related else ()
            )
            chains.append(
                AttackChainHypothesis(
                    chain_id=f"v6-chain-{index + 1:03d}",
                    explanation=(
                        "A weak graph signal may combine with an assumption violation and "
                        "produce impact; the sequence is a hypothesis until causal testing."
                    ),
                    steps=(
                        "weak signal recorded",
                        "context and relationship mapped",
                        "security assumption compared",
                        "impact path bounded for review",
                    ),
                    dependencies=dependency_ids,
                    evidence_requirements=(
                        "evidence for each dependency",
                        "candidate/control comparison",
                        "central causal oracle",
                        "sealed and replayable ProofBundle",
                    ),
                    validation_path=(
                        "remain advisory when scope or preconditions are absent",
                        "validate each dependency independently",
                        "stop on any missing evidence",
                    ),
                    impact_hypothesis=f"Potential impact on {candidate.affected_assets[0]}",
                    confidence=min(0.8, candidate.confidence + (0.1 if related else 0.0)),
                    status=V6Status.ADVISORY,
                )
            )
        if not chains and evidence_refs:
            chains.append(
                AttackChainHypothesis(
                    chain_id="v6-chain-signal-review",
                    explanation=(
                        "Recorded evidence exists but no candidate dependency has been established."
                    ),
                    steps=("weak signal recorded", "dependency discovery required"),
                    dependencies=("recorded_evidence",),
                    evidence_requirements=("map a falsifiable assumption", "central causal oracle"),
                    validation_path=("do not execute without approved bounded scope",),
                    impact_hypothesis="unknown until dependencies are established",
                    confidence=0.2,
                )
            )
        return tuple(chains)


__all__ = ["AttackChainIntelligenceV6"]
