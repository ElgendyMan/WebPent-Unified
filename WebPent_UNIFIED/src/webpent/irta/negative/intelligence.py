"""Negative intelligence for suppressing unsupported findings."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CleanDisposition(StrEnum):
    CLEAN = "clean"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class CleanReasonBundle:
    case_id: str
    disposition: CleanDisposition
    reasons: tuple[str, ...]
    checked_controls: tuple[str, ...]
    evidence_digest: str = ""

    def validate(self) -> None:
        if not self.case_id or not self.reasons:
            raise ValueError("clean evidence requires case identity and explicit reasons")
        if self.disposition is CleanDisposition.CLEAN and not self.checked_controls:
            raise ValueError("clean disposition requires independent controls")
        if self.disposition is not CleanDisposition.CLEAN and self.evidence_digest:
            raise ValueError("non-clean evidence must not be presented as confirmed proof")


class FalsePositiveSuppressionEngine:
    """Return conservative dispositions from causal-evidence completeness."""

    def evaluate(
        self,
        case_id: str,
        *,
        candidate_observed: bool,
        control_observed: bool,
        causal_oracle_passed: bool,
        proof_replayable: bool,
    ) -> CleanReasonBundle:
        if not case_id:
            raise ValueError("case id is required")
        if candidate_observed and control_observed and causal_oracle_passed and proof_replayable:
            bundle = CleanReasonBundle(
                case_id,
                CleanDisposition.INCONCLUSIVE,
                ("positive causal evidence is present; this is not a clean result",),
                ("candidate", "negative_control"),
            )
        elif not candidate_observed or not control_observed:
            bundle = CleanReasonBundle(
                case_id,
                CleanDisposition.BLOCKED,
                ("candidate/control observation pair is incomplete",),
                (),
            )
        else:
            bundle = CleanReasonBundle(
                case_id,
                CleanDisposition.INCONCLUSIVE,
                ("causal oracle or replayable proof is incomplete",),
                ("candidate", "negative_control"),
            )
        bundle.validate()
        return bundle
