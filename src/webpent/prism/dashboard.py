"""THE PRISM — U-PRISM-13, the Learning Dashboard (v89).

One deterministic text view of what Prism learned and improved: ranked
signals, extracted patterns with confidence, applied prior adjustments,
before/after metrics, avoided rabbit holes and the evidence-tier
distribution. Every render opens with the advisory preamble
(PRISM-L-2) and closes with the law line (PRISM-L-12: preamble before
any ✅).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from webpent.prism import PREAMBLE_LINE
from webpent.prism.metrics import PrismMetrics
from webpent.prism.patterns import Pattern
from webpent.prism.priors import PriorAdjustment

SECTIONS = ("signals", "patterns", "priors", "metrics", "rabbit-holes",
            "evidence")


def render_dashboard(
    metrics: PrismMetrics | None = None,
    patterns: Sequence[Pattern] = (),
    adjustments: Sequence[PriorAdjustment] = (),
    tier_distribution: Mapping[str, int] | None = None,
    ranked_signals: Sequence[tuple[str, float]] = (),
    rabbit_holes_avoided: int = 0,
) -> str:
    lines: list[str] = [PREAMBLE_LINE, ""]
    lines.append("== signals (ranked by value) ==")
    if ranked_signals:
        for signal_id, weight in ranked_signals:
            lines.append(f"  {signal_id}: weight={weight:.3f}")
    else:
        lines.append("  (no signals ranked yet)")
    lines.append("")
    lines.append("== patterns (extracted, with confidence) ==")
    if patterns:
        for pattern in patterns:
            lines.append(
                f"  {pattern.pattern_id} {pattern.pattern_type}="
                f"{pattern.key}: samples={pattern.samples} "
                f"rate={pattern.success_rate:.2f} "
                f"confidence={pattern.confidence:.2f}"
            )
    else:
        lines.append("  (no patterns above min_samples yet)")
    lines.append("")
    lines.append("== priors (adjustments applied) ==")
    if adjustments:
        for adj in adjustments:
            lines.append(
                f"  {adj.pattern_id} {adj.pattern_type}={adj.key}: "
                f"{adj.delta:+.3f} -> {adj.adjusted:.3f} ({adj.reason})"
            )
    else:
        lines.append("  (no prior adjustments applied)")
    lines.append("")
    lines.append("== metrics (before -> after) ==")
    if metrics is not None:
        lines.append(
            f"  acceptance: {metrics.acceptance_before:.2f} -> "
            f"{metrics.acceptance_after:.2f} "
            f"({metrics.improvement_pct:+.1f}%)"
        )
        lines.append(
            f"  avg evidence score: "
            f"{metrics.avg_evidence_score_before:.3f} -> "
            f"{metrics.avg_evidence_score_after:.3f}"
        )
        lines.append(
            f"  time per finding: "
            f"{metrics.avg_time_per_finding_before:.2f}h -> "
            f"{metrics.avg_time_per_finding_after:.2f}h"
        )
    else:
        lines.append("  (no metrics yet — PRISM-L-10: metrics or it "
                     "didn't happen)")
    lines.append("")
    lines.append("== rabbit holes ==")
    lines.append(f"  avoided: {max(rabbit_holes_avoided, 0)}")
    lines.append("")
    lines.append("== evidence (distribution by tier) ==")
    if tier_distribution:
        for tier in sorted(tier_distribution):
            lines.append(f"  {tier}: {tier_distribution[tier]}")
    else:
        lines.append("  (no evidence scored yet)")
    lines.append("")
    lines.append("PRISM advisory: ranks, flags and suggests only — it "
                 "never blocks or executes a decision (PRISM-L-2).")
    return "\n".join(lines)


def export_dashboard(path: Path, **kwargs: Any) -> str:
    text = render_dashboard(**kwargs)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return text


__all__ = ["SECTIONS", "export_dashboard", "render_dashboard"]
