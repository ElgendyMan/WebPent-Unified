"""Learning A/B evidence contract (additive, not frozen).

Schema for the before/after/evidence metrics that prove the learning loop
reduces hypothesis count for the same confirmed findings. Pure dataclasses,
no authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["CampaignMetrics", "ABEvidence", "LearningLoopEvidence"]


@dataclass(frozen=True)
class CampaignMetrics:
    campaign: str
    hypotheses_generated: int
    hypotheses_tested: int
    confirmed_findings: int
    confirmed_bug_ids: tuple[str, ...] = ()
    notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "campaign": str(self.campaign)[:32],
            "hypotheses": int(self.hypotheses_generated),
            "tested": int(self.hypotheses_tested),
            "confirmed": int(self.confirmed_findings),
            "confirmed_bug_ids": list(self.confirmed_bug_ids),
            "notes": str(self.notes)[:240],
        }


@dataclass(frozen=True)
class ABEvidence:
    before: CampaignMetrics
    after: CampaignMetrics
    hypotheses_reduction: int
    same_findings: bool
    verdict: str  # "learning_proven" | "inconclusive" | "learning_not_observed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "before": self.before.as_dict(),
            "after": self.after.as_dict(),
            "hypotheses_reduction": int(self.hypotheses_reduction),
            "same_findings": bool(self.same_findings),
            "verdict": str(self.verdict)[:64],
        }


@dataclass(frozen=True)
class LearningLoopEvidence:
    target: str
    evidence: ABEvidence
    lesson_consultant_used: bool
    generated_at: str = ""
    honesty_label: str = "SYNTHETIC_PROOF_ONLY_no_live_target_no_real_llm"

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": str(self.target)[:256],
            "evidence": self.evidence.as_dict(),
            "lesson_consultant_used": bool(self.lesson_consultant_used),
            "generated_at": str(self.generated_at)[:64],
            "honesty_label": self.honesty_label,
        }
