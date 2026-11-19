"""Judgment Council — U-JC-10: the Reasoning Explainer.

Three transparency levels (JC-L-3, L-4), all deterministic and derived
only from the verdict/session data already in memory:

    one-liner  a single sentence: what was decided and how confident
    summary    action, confidence, escalation, dissent count, winners
    full       every argument, every challenge, every dissent, weights

Both markdown and json renderers are provided; both consume the same
level-3 data so the two formats can never disagree.
"""

from __future__ import annotations

from typing import Any

from webpent.jc.contracts import CouncilSession, Verdict

LEVELS = ("one-liner", "summary", "full")


class Explainer:
    """Renders a verdict at three transparency levels."""

    def explain(
        self,
        verdict: Verdict,
        session: CouncilSession | None = None,
        *,
        level: str = "summary",
    ) -> dict[str, Any]:
        """Return the explanation dict for one of the three levels."""
        if level not in LEVELS:
            raise ValueError(f"unknown level {level!r}; use one of {LEVELS}")
        data = self._base(verdict)
        if level == "one-liner":
            return data
        if level == "summary":
            return self._summary(verdict, data)
        return self._full(verdict, session, data)

    # ------------------------------------------------------------- levels
    def _base(self, verdict: Verdict) -> dict[str, Any]:
        top = self._winner_id(verdict)
        return {
            "advisory": True,
            "session_id": verdict.session_id,
            "action": verdict.action,
            "confidence": round(verdict.confidence, 4),
            "confidence_tier": verdict.confidence_tier,
            "escalate": verdict.escalate,
            "escalation_reason": verdict.escalation_reason,
            "level": "one-liner",
            "one_liner": (
                f"council says '{verdict.action}' with {verdict.confidence:.2f} "
                f"confidence ({verdict.confidence_tier})"
                + (" — escalate to the operator" if verdict.escalate else "")
            ),
            "winner": top,
        }

    def _summary(self, verdict: Verdict, data: dict[str, Any]) -> dict[str, Any]:
        data["level"] = "summary"
        data["n_arguments"] = len(verdict.advocates_summary)
        data["n_dissent"] = len(verdict.dissent)
        data["advocates"] = [
            {
                "advocate_id": aid,
                "claim": d.get("claim", ""),
                "score": d.get("score", 0.0),
                "challenge_severity": d.get("challenge_severity", 0.0),
            }
            for aid, d in sorted(verdict.advocates_summary.items())
        ]
        data["dissent_ids"] = [d.advocate_id for d in verdict.dissent]
        data["reasoning"] = verdict.reasoning
        return data

    def _full(
        self,
        verdict: Verdict,
        session: CouncilSession | None,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        data = self._summary(verdict, data)
        data["level"] = "full"
        # reasoning is already set by _summary()
        data["dissent"] = [d.as_dict() for d in verdict.dissent]
        data["advocates"] = [
            dict(entry) for entry in data.get("advocates", [])
        ]
        for entry in data["advocates"]:
            aid = entry["advocate_id"]
            summary_entry = verdict.advocates_summary.get(aid, {})
            entry["confidence"] = summary_entry.get("confidence", 0.0)
            entry["argue_order"] = summary_entry.get("argue_order", 0)
            entry["evidence_count"] = summary_entry.get("evidence_count", 0)
            entry["raw_evidence_weight"] = summary_entry.get(
                "raw_evidence_weight", 0.0
            )
        if session is not None:
            data["question"] = session.question
            data["arguments"] = [a.as_dict() for a in session.arguments]
            data["challenges"] = [c.as_dict() for c in session.challenges]
        else:
            data["question"] = None
            data["arguments"] = []
            data["challenges"] = []
        return data

    # -------------------------------------------------------- renderers
    def to_markdown(self, verdict: Verdict, session: CouncilSession | None = None,
                    *, level: str = "full") -> str:
        """Markdown rendering of the same explanation (deterministic)."""
        data = self.explain(verdict, session, level=level)
        lines = [
            f"# Council verdict ({data['session_id']})",
            "",
            data["one_liner"].replace("—", "-"),
            "",
            f"- action: `{data['action']}`",
            f"- confidence: {data['confidence']:.4f} ({data['confidence_tier']})",
            f"- escalate: {str(data['escalate']).lower()}",
        ]
        if data.get("escalation_reason"):
            lines.append(f"- escalation reason: {data['escalation_reason']}")
        lines.append("")
        if data.get("question"):
            lines.append(f"**Question:** {data['question']}")
            lines.append("")
        lines.append("## Advocates")
        for entry in data.get("advocates", []):
            lines.append(
                f"- {entry['advocate_id']}: '{entry['claim']}' "
                f"(score {entry.get('score', 0.0):.4f}, "
                f"severity {entry.get('challenge_severity', 0.0):.2f})"
            )
        if data.get("dissent"):
            lines.append("")
            lines.append("## Dissent (preserved, JC-L-5)")
            for d in data["dissent"]:
                lines.append(f"- {d['advocate_id']}: '{d['claim']}' — {d['reasoning']}")
        if data.get("challenges"):
            lines.append("")
            lines.append("## Skeptic challenges")
            for c in data["challenges"]:
                flags = ", ".join(c.get("bias_flags", [])) or "none"
                lines.append(
                    f"- vs {c['target_advocate_id']}: {c['counter_claim']} "
                    f"[flags: {flags}] (severity {c['challenge_severity']:.2f})"
                )
        lines.append("")
        lines.append("## Reasoning")
        lines.append("```")
        lines.append(data.get("reasoning", ""))
        lines.append("```")
        lines.append("")
        lines.append("_Advisory only (JC-L-1): this report decides nothing._")
        return "\n".join(lines)

    def to_json(self, verdict: Verdict, session: CouncilSession | None = None,
                *, level: str = "full") -> dict[str, Any]:
        """JSON rendering (same data as markdown, L-4)."""
        return self.explain(verdict, session, level=level)

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _winner_id(verdict: Verdict) -> str | None:
        best_id: str | None = None
        best_score = float("-inf")
        for aid, d in sorted(verdict.advocates_summary.items()):
            score = float(d.get("score", 0.0))
            if score > best_score:
                best_score = score
                best_id = aid
        return best_id


__all__ = ["LEVELS", "Explainer"]
