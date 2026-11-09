"""Judgment Council — U-JC-5: the Judge.

The verdict engine. Deterministic phases (JC-L-2):

    1. Scoring:   AdvocateScore = sum(weighted evidence)
                                 x (1 - max challenge severity)
    2. Synthesis: clear winner (top/runner-up >= clear_winner_ratio),
                  coalesce (runner-up close), escalate (tie)
    3. Confidence: AgreementLevel x (1 - max challenge severity)
                   AgreementLevel = top_score / sum_of_all_scores
    4. Verdict:   action + full reasoning + dissent + tier + escalation

Every advocate's view appears in the reasoning (JC-L-3) and every minority
voice lands in the dissent list (JC-L-5).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from webpent.jc.contracts import (
    CouncilSession,
    DissentingView,
    Verdict,
    clamp01,
    utc,
)
from webpent.jc.verdict import VerdictRules, load_verdict_rules
from webpent.jc.weigher import EvidenceWeigher

SCORE_PRECISION = 12


class Judge:
    """Weighs the arguments against the challenges and rules."""

    def __init__(
        self, *, rules_path: Any = None, rules: VerdictRules | None = None
    ) -> None:
        self.rules = rules if rules is not None else load_verdict_rules(rules_path)

    # ------------------------------------------------------------- scores
    def score_advocates(
        self, session: CouncilSession, weigher: EvidenceWeigher
    ) -> dict[str, dict]:
        """Score each advocate from weighted evidence and challenges."""
        max_severity: dict[str, float] = {}
        for challenge in session.challenges:
            target = challenge.target_advocate_id
            max_severity[target] = max(
                max_severity.get(target, 0.0), challenge.challenge_severity
            )
        summary: dict[str, dict] = {}
        for order, arg in enumerate(session.arguments):
            weighted = weigher.weigh_all(arg.evidence)
            raw = sum(w.weight for w in weighted)
            severity = max_severity.get(arg.advocate_id, 0.0)
            score = raw * (1.0 - severity)
            summary[arg.advocate_id] = {
                "claim": arg.claim,
                "raw_evidence_weight": round(raw, 4),
                "challenge_severity": round(severity, 4),
                "score": round(score, SCORE_PRECISION),
                "confidence": arg.confidence,
                "argue_order": order,
                "evidence_count": len(arg.evidence),
            }
        return summary

    # --------------------------------------------------------------- rule
    def rule(
        self,
        session: CouncilSession,
        *,
        now: datetime | None = None,
        weigher: EvidenceWeigher | None = None,
    ) -> Verdict:
        """Produce the verdict for one session (deterministic)."""
        stamp = utc(now) if now is not None else utc(session.started_at)
        weigher = weigher or EvidenceWeigher(now=stamp)
        summary = self.score_advocates(session, weigher)
        rules = self.rules

        if not summary:
            return Verdict(
                action="none",
                reasoning="no advocate argued; nothing to synthesize",
                confidence=0.0,
                confidence_tier="low",
                dissent=[],
                escalate=True,
                escalation_reason="no arguments submitted",
                advocates_summary={},
                session_id=session.session_id,
                timestamp=stamp,
            )

        scores = {aid: data["score"] for aid, data in summary.items()}
        top_aid = max(sorted(scores), key=lambda a: scores[a])
        ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
        top_score = ranked[0][1]
        second_score = ranked[1][1] if len(ranked) > 1 else 0.0
        total = sum(scores.values())
        max_severity = max(
            (data["challenge_severity"] for data in summary.values()), default=0.0
        )

        reasons: list[str] = []
        escalate = False
        is_tie = (
            len(ranked) > 1 and abs(top_score - second_score) <= rules.tie_epsilon
        )
        if is_tie:
            escalate = True
            reasons.append(
                f"tie between {ranked[0][0]} and {ranked[1][0]} "
                f"(scores {top_score:.4f})"
            )

        ratio = (top_score / second_score) if second_score > 0 else float("inf")
        if is_tie:
            mode = "escalate"
        elif ratio >= rules.clear_winner_ratio:
            mode = "clear_winner"
        else:
            mode = "coalesce"

        if top_score <= 0:
            escalate = True
            mode = "escalate"
            reasons.append("no advocate produced a positive score")

        action = summary[top_aid]["claim"]
        agreement = (top_score / total) if total > 0 else 0.0
        reasoning_parts = [
            f"mode={mode}; winner={top_aid} with score {top_score:.4f} "
            f"(agreement {agreement:.2f} of {total:.4f} total)"
        ]
        for aid, data in summary.items():
            reasoning_parts.append(
                f"{aid}: claim='{data['claim']}' score={data['score']:.4f} "
                f"(evidence weight {data['raw_evidence_weight']:.4f}, "
                f"challenge severity {data['challenge_severity']:.2f}, "
                f"self-confidence {data['confidence']:.2f})"
            )
        if mode == "coalesce" and len(ranked) > 1:
            runner = ranked[1][0]
            alt_text = "; ".join(
                alt for arg in session.arguments if arg.advocate_id == runner
                for alt in arg.alternatives
            )[:200]
            reasoning_parts.append(
                f"coalesced with runner-up {runner}"
                + (f" adopting alternatives: {alt_text}" if alt_text else "")
            )

        confidence = 0.0
        if total > 0 and top_score > 0:
            confidence = clamp01(agreement * (1.0 - max_severity))
        tier = rules.tier(confidence)
        if rules.should_escalate(confidence):
            escalate = True
            reasons.append(
                f"confidence {confidence:.2f} below medium threshold "
                f"{rules.medium:.2f}"
            )

        dissent = [
            DissentingView(
                advocate_id=aid,
                claim=data["claim"],
                reasoning=(
                    f"scored {data['score']:.4f} against winner "
                    f"{top_aid} ({top_score:.4f}); view preserved (JC-L-5)"
                ),
                confidence=data["confidence"],
            )
            for aid, data in sorted(summary.items())
            if aid != top_aid and data["claim"] != action
        ]

        return Verdict(
            action=action,
            reasoning="\n".join(reasoning_parts)[:4000],
            confidence=confidence,
            confidence_tier=tier,
            dissent=dissent,
            escalate=escalate,
            escalation_reason="; ".join(reasons) if reasons else None,
            advocates_summary=summary,
            session_id=session.session_id,
            timestamp=stamp,
        )


__all__ = ["Judge"]
