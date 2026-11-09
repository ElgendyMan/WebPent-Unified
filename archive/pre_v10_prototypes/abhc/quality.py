"""Finding-quality assessment for ABHC v3."""

from __future__ import annotations

from collections.abc import Sequence

from .contracts import (
    AdvisoryDisposition,
    EvolvingHypothesis,
    FindingConfidenceReport,
    OracleEvidence,
)


class FindingQualityEngine:
    """Assess evidence quality without creating findings or promotion decisions."""

    def assess(
        self,
        hypothesis: EvolvingHypothesis,
        *,
        oracle: OracleEvidence | None = None,
        alternative_explanations_considered: bool = False,
        evidence_reproducible: bool = False,
    ) -> FindingConfidenceReport:
        oracle = oracle or hypothesis.oracle_evidence
        complete = bool(oracle and oracle.sufficient)
        rationale: list[str] = []
        if not hypothesis.evidence_refs:
            rationale.append("no_actual_evidence_refs")
        if not complete:
            rationale.append("causal_control_proof_replay_incomplete")
        if not alternative_explanations_considered:
            rationale.append("alternative_explanations_not_closed")
        if not evidence_reproducible:
            rationale.append("evidence_replayability_not_demonstrated")
        disposition = (
            AdvisoryDisposition.ADVISORY_CANDIDATE
            if complete and alternative_explanations_considered and evidence_reproducible
            else AdvisoryDisposition.INSUFFICIENT_EVIDENCE
        )
        if not hypothesis.evidence_refs:
            disposition = AdvisoryDisposition.BLOCKED
        return FindingConfidenceReport(
            hypothesis_id=hypothesis.hypothesis_id,
            vulnerability_exists=True if complete else None,
            impact_demonstrated=True if complete else None,
            alternative_explanations_considered=alternative_explanations_considered,
            evidence_reproducible=evidence_reproducible,
            confidence_justified=complete
            and alternative_explanations_considered
            and evidence_reproducible,
            disposition=disposition,
            rationale=tuple(
                rationale or ("evidence_quality_requirements_met_for_advisory_review",)
            ),
        )

    def batch_assess(
        self, hypotheses: Sequence[EvolvingHypothesis]
    ) -> tuple[FindingConfidenceReport, ...]:
        return tuple(self.assess(hypothesis) for hypothesis in hypotheses)


__all__ = ["FindingQualityEngine"]
