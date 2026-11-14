"""Evidence intelligence; passive, redacted, and fail-closed."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import EvidenceDisposition, EvidenceRecordV9


@dataclass(frozen=True, slots=True)
class EvidenceIntelligenceV9:
    """Builds evidence records from supplied observations; never collects them."""

    def assess(
        self,
        *,
        subject_id: str,
        observation_refs: tuple[str, ...] = (),
        causal_oracle: str = "",
        proof_bundle_ref: str = "",
        seal_verified: bool = False,
        replay_verified: bool = False,
        explanation: str = "",
    ) -> EvidenceRecordV9:
        complete = bool(
            observation_refs
            and causal_oracle
            and proof_bundle_ref
            and seal_verified
            and replay_verified
        )
        disposition = EvidenceDisposition.CONFIRMED if complete else EvidenceDisposition.BLOCKED
        if not complete:
            explanation = explanation or "evidence requirements incomplete; no finding is permitted"
        return EvidenceRecordV9(
            evidence_id=f"evidence-{subject_id}",
            subject_id=subject_id,
            observation_refs=observation_refs,
            causal_oracle=causal_oracle,
            reproducibility_requirements=(
                "candidate/control observations",
                "sealed ProofBundle",
                "replay",
            ),
            proof_bundle_ref=proof_bundle_ref,
            seal_verified=seal_verified,
            replay_verified=replay_verified,
            explanation=explanation,
            disposition=disposition,
        )

    @staticmethod
    def verify_replay(record: EvidenceRecordV9, replay_digest: str | None) -> bool:
        return bool(
            replay_digest
            and record.disposition is EvidenceDisposition.CONFIRMED
            and record.seal_verified
            and record.replay_verified
        )


__all__ = ["EvidenceIntelligenceV9"]
