"""Advisory attack-chain reasoning with explicit evidence dependencies."""

from __future__ import annotations

from collections.abc import Iterable
from itertools import combinations

from .contracts import AttackChainHypothesis, Disposition, Hypothesis


class AttackChainIntelligence:
    def build(self, hypotheses: Iterable[Hypothesis]) -> tuple[AttackChainHypothesis, ...]:
        items = tuple(sorted(hypotheses, key=lambda item: item.hypothesis_id))
        chains: list[AttackChainHypothesis] = []
        for left, right in combinations(items, 2):
            shared = tuple(sorted(set(left.affected_assets).intersection(right.affected_assets)))
            if not shared or not left.supporting_evidence or not right.supporting_evidence:
                continue
            chain_id = f"chain-{left.hypothesis_id}-{right.hypothesis_id}"
            chains.append(
                AttackChainHypothesis(
                    chain_id=chain_id,
                    steps=(left.hypothesis_id, right.hypothesis_id),
                    reasoning=(
                        "hypotheses share an affected asset",
                        "the relationship is a research hypothesis, not a confirmed exploit path",
                    ),
                    confidence=min(left.confidence, right.confidence) * 0.75,
                    validation_requirements=(
                        "validate each step independently",
                        "require causal oracle and independent negative control",
                        "require sealed and replayable evidence",
                    ),
                    evidence_dependencies=tuple(
                        sorted(set(left.supporting_evidence + right.supporting_evidence))
                    ),
                    disposition=Disposition.ADVISORY,
                )
            )
        return tuple(chains)
