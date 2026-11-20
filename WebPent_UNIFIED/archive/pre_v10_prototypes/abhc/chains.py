"""Hypothesis-only attack-chain reasoning for ABHC v3."""

from __future__ import annotations

from collections.abc import Sequence
from hashlib import sha256

from .contracts import BoundaryCandidate, EvolvingHypothesis, PotentialAttackChain, WeakSignal


class PotentialAttackChainReasoner:
    """Join weak signals to modeled boundaries without claiming exploitation."""

    def reason(
        self,
        *,
        hypotheses: Sequence[EvolvingHypothesis] = (),
        boundaries: Sequence[BoundaryCandidate] = (),
        weak_signals: Sequence[WeakSignal] = (),
        max_chains: int = 32,
    ) -> tuple[PotentialAttackChain, ...]:
        result: list[PotentialAttackChain] = []
        for hypothesis in hypotheses:
            related_boundaries = [
                boundary
                for boundary in boundaries
                if boundary.source_node == hypothesis.target_area
                or boundary.target_node == hypothesis.target_area
                or any(ref in hypothesis.evidence_refs for ref in boundary.evidence_refs)
            ]
            related_signals = [
                signal
                for signal in weak_signals
                if any(ref in hypothesis.evidence_refs for ref in signal.evidence_refs)
                or signal.signal_id == hypothesis.target_area
            ]
            for boundary in related_boundaries[:4]:
                signals = related_signals[:4]
                if not signals:
                    continue
                path = (
                    hypothesis.target_area,
                    boundary.boundary_type,
                    boundary.target_node,
                )
                digest = sha256("|".join(path).encode()).hexdigest()[:16]
                result.append(
                    PotentialAttackChain(
                        chain_id=f"chain:{digest}",
                        reasoning_path=path,
                        weak_signal_refs=tuple(signal.signal_id for signal in signals),
                        evidence_refs=tuple(
                            dict.fromkeys((*hypothesis.evidence_refs, *boundary.evidence_refs))
                        ),
                        required_validation=(
                            "independent negative control",
                            "causal oracle",
                            "sealed proof bundle",
                            "replay verification",
                        ),
                        confidence=round(
                            min(
                                hypothesis.confidence,
                                boundary.confidence,
                                max(signal.strength for signal in signals),
                            ),
                            6,
                        ),
                    )
                )
        unique = {chain.chain_id: chain for chain in result}
        return tuple(sorted(unique.values(), key=lambda item: (-item.confidence, item.chain_id)))[
            :max_chains
        ]


__all__ = ["PotentialAttackChainReasoner"]
