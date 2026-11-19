"""U-FORGE-2 — The Quality Gate.

Applies the spec's QUALITY_RULES. Evaluation order is documented and
safety-first: auto_reject conditions are tested BEFORE auto_accept so
a deprecated or malware payload can never pass on trust alone
(FORGE-L-2 QUALITY_OVER_QUANTITY, L-9 published arithmetic).

Rules (spec, verbatim thresholds):
- auto_accept: trust >= 0.85 AND (has_cve OR has_writeup) AND NOT
  high-risk
- review_required: 0.6 <= trust < 0.85, OR complexity == expert, OR
  none of the accept/reject conditions fire
- auto_reject: trust < 0.6, OR high-risk without documented impact,
  OR deprecated, OR known malware
"""
from __future__ import annotations

from dataclasses import dataclass

from webpent.forge.schemas import QualitySignal

TRUST_ACCEPT_FLOOR = 0.85
TRUST_REVIEW_FLOOR = 0.6


@dataclass(frozen=True)
class QualityDecision:
    decision: str       # "auto_accept" | "review_required" | "auto_reject"
    reason: str


class QualityGate:
    """Batches and auto-accepts payloads by the published rules."""

    def evaluate(self, signal: QualitySignal) -> QualityDecision:
        if signal.is_known_malware:
            return QualityDecision(
                "auto_reject", "known malware — never enters the corpus")
        if signal.is_deprecated:
            return QualityDecision(
                "auto_reject", "payload deprecated by its source")
        if (signal.is_high_risk and not signal.has_documented_impact):
            return QualityDecision(
                "auto_reject",
                "high-risk payload without documented impact (L-8)")
        if signal.source_trust < TRUST_REVIEW_FLOOR:
            return QualityDecision(
                "auto_reject",
                f"source trust {signal.source_trust:.2f} below the "
                f"{TRUST_REVIEW_FLOOR:.2f} floor")
        if signal.complexity == "expert":
            return QualityDecision(
                "review_required",
                "expert-complexity payloads always get human review")
        if (signal.source_trust >= TRUST_ACCEPT_FLOOR
                and (signal.has_cve or signal.has_writeup)
                and not signal.is_high_risk):
            return QualityDecision(
                "auto_accept",
                "trusted source with CVE or writeup, not high-risk")
        return QualityDecision(
            "review_required",
            f"trust {signal.source_trust:.2f} in the review band "
            f"[{TRUST_REVIEW_FLOOR:.2f}, {TRUST_ACCEPT_FLOOR:.2f})")
