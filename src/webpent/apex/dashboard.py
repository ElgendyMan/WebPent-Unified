"""The Apex Predator — U-APEX-11, the Operator Dashboard (v87).

One view over everything: chains in flight or done, tool usage, speed
metrics (measured, never claimed — APEX-L-8), fused findings, and
resources. Renders from a DashboardSnapshot so the CLI stays stateless.
Advisory only (APEX-L-9): the dashboard reports, it does not act.
"""

from __future__ import annotations

from dataclasses import dataclass, field

PREAMBLE_LINE = (
    "advisory: the dashboard reports; it never acts. Every number here is "
    "from recorded runs."
)

SECTION_ORDER = ("Chains", "Tool usage", "Speed", "Findings", "Resources")


@dataclass
class DashboardSnapshot:
    """Everything the dashboard needs for one render."""

    chains: list[dict] = field(default_factory=list)
    tool_usage: list[dict] = field(default_factory=list)
    speed: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    resources: dict = field(default_factory=dict)


def render(snapshot: DashboardSnapshot) -> str:
    """Render all five sections as plain text (section headers fixed)."""
    lines: list[str] = [PREAMBLE_LINE, ""]

    lines.append("== Chains ==")
    if snapshot.chains:
        for chain in snapshot.chains:
            lines.append(
                f"  - {chain['chain_id']}  {chain['hypothesis_type']}  "
                f"target={chain.get('target', '-')}  "
                f"steps={chain.get('steps', '?')}  "
                f"completed={chain.get('completed', 0)}  "
                f"failed={chain.get('failed', 0)}  "
                f"skipped={chain.get('skipped', 0)}"
            )
    else:
        lines.append("  (no recorded chains)")
    lines.append("")

    lines.append("== Tool usage ==")
    if snapshot.tool_usage:
        for row in snapshot.tool_usage:
            lines.append(
                f"  {row['tool_id']}: {row['runs']} run(s), "
                f"last result exit {row['last_exit_code']}"
            )
    else:
        lines.append("  (no tool runs recorded)")
    lines.append("")

    lines.append("== Speed ==")
    speed = snapshot.speed
    lines.append(
        f"  chains_run={speed.get('chains_run', 0)}  "
        f"measured_speedup_max={speed.get('measured_speedup_max', '-')}  "
        f"total_duration_seconds={speed.get('total_duration_seconds', '-')}"
    )
    lines.append("")

    lines.append("== Findings ==")
    if snapshot.findings:
        for finding in snapshot.findings:
            lines.append(
                f"  {finding['finding_id']}  {finding['vuln_class']} at "
                f"{finding['endpoint']}  severity={finding['severity']}  "
                f"confidence={finding.get('confidence', 0):.2f}  "
                f"consensus={finding.get('consensus', 0):.2f}"
            )
    else:
        lines.append("  (no fused findings)")
    lines.append("")

    lines.append("== Resources ==")
    resources = snapshot.resources
    lines.append(f"  sandbox_mode={resources.get('sandbox_mode', 'local')}")
    lines.append(f"  docker_daemon={resources.get('docker_daemon', '-')}")
    lines.append(
        f"  audit_lines={resources.get('audit_lines', 0)}  "
        f"cache_entries={resources.get('cache_entries', 0)}"
    )
    return "\n".join(lines)
