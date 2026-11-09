"""THE ORACLE — U-ORACLE-12, the Operator Dashboard (v88).

One passive view over the whole Oracle pipeline: evidence in, graph out,
predictions and proposals ranked, validation status honest. Renders from
a DashboardSnapshot so the CLI stays stateless. Advisory only (ORACLE-L-10):
the dashboard reports what the evidence supports; it never acts and it
never opens a socket.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PREAMBLE_LINE = (
    "advisory: the oracle dashboard reports; it never acts and never "
    "touches the target. Every number here is from recorded evidence."
)

SECTION_ORDER = (
    "Pipeline", "Evidence", "Graph", "Predictions", "Impact", "Validation",
)

STAGE_KEYS = (
    "report", "stack", "signals", "graph", "predictions", "proposals",
    "traces", "views", "estimates",
)


@dataclass
class OracleDashboardSnapshot:
    """Everything the dashboard needs for one render."""

    target_id: str = ""
    generated_at: str = ""
    stages: dict[str, bool] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    coverage: dict[str, str] = field(default_factory=dict)
    zero_touch: dict[str, Any] = field(default_factory=dict)
    top_impact: dict[str, Any] | None = None
    validation: dict[str, Any] = field(default_factory=dict)
    laws: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "generated_at": self.generated_at,
            "stages": dict(self.stages),
            "counts": dict(self.counts),
            "sources": list(self.sources),
            "coverage": dict(self.coverage),
            "zero_touch": dict(self.zero_touch),
            "top_impact": self.top_impact,
            "validation": dict(self.validation),
            "laws": dict(self.laws),
            "advisory": True,
        }


def render(snapshot: OracleDashboardSnapshot) -> str:
    """Render all six sections as plain text (section headers fixed)."""
    lines: list[str] = [PREAMBLE_LINE, ""]

    lines.append("== Pipeline ==")
    lines.append(f"  target: {snapshot.target_id or '(none)'}")
    for stage in STAGE_KEYS:
        mark = "done" if snapshot.stages.get(stage) else "-"
        lines.append(f"  {stage}: {mark}")
    lines.append("")

    lines.append("== Evidence ==")
    lines.append(
        f"  findings: {snapshot.counts.get('findings', 0)}  "
        f"sources: {', '.join(snapshot.sources) or '(none)'}"
    )
    for source_id, state in sorted(snapshot.coverage.items()):
        lines.append(f"  {source_id}: {state}")
    lines.append("")

    lines.append("== Graph ==")
    lines.append(
        f"  nodes: {snapshot.counts.get('nodes', 0)}  "
        f"edges: {snapshot.counts.get('edges', 0)}  "
        f"signals: {snapshot.counts.get('signals', 0)}"
    )
    lines.append("")

    lines.append("== Predictions ==")
    lines.append(
        f"  predictions: {snapshot.counts.get('predictions', 0)}  "
        f"proposals: {snapshot.counts.get('proposals', 0)}  "
        f"simulations: {snapshot.counts.get('traces', 0)}  "
        f"perspectives: {snapshot.counts.get('perspectives', 0)}"
    )
    lines.append("")

    lines.append("== Impact ==")
    if snapshot.top_impact:
        top = snapshot.top_impact
        lines.append(
            f"  top: {top.get('proposal_id')}  "
            f"category={top.get('impact_category')}  "
            f"adjusted_payout={top.get('adjusted_payout')}"
        )
    else:
        lines.append("  (no impact estimates recorded)")
    lines.append("")

    lines.append("== Validation ==")
    if snapshot.validation:
        lines.append(
            f"  resolved: {snapshot.validation.get('resolved', 0)}  "
            f"claim: {snapshot.validation.get('claim')}"
        )
    else:
        lines.append("  (no ledger recorded)")
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "OracleDashboardSnapshot", "PREAMBLE_LINE", "SECTION_ORDER",
    "STAGE_KEYS", "render",
]
