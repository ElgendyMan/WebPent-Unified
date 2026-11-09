# src/webpent/reporting/engagement_report.py
"""webpent.reporting.engagement_report

Deliverable engagement report: Markdown and self-contained HTML rendered
from a hunt report payload that already exists.

ADVISORY-ONLY and machine-derived: the renderer is a pure function over
the ``to_report_json()`` payload. It never computes a new claim about the
target, never adds a finding, and never upgrades a severity. Sections
absent from the payload are skipped rather than invented; every
``non_claim`` in the payload is carried through verbatim so a reader
cannot mistake advisory guidance for a re-run result.

Redaction contract: the payload is already redaction-safe upstream and is
passed through as-is; the renderer adds no request or response data of
its own and emits no external resources (no CDN scripts, stylesheets, or
fonts), so the HTML file can be handed to a target owner without phoning
home to anyone.
"""

from __future__ import annotations

import html
from typing import Any

_MD_NON_CLAIM = (
    "machine-derived report over this hunt's own records; not a guarantee "
    "of completeness and not a claim about anything that was not hunted"
)

_FORMATS = ("markdown", "html")


def _cell(value: object) -> str:
    text = str(value) if value is not None else ""
    return text.replace("|", "\\|").replace("\n", " ")


def _esc(value: object) -> str:
    return html.escape(str(value) if value is not None else "")


def _md_executive(summary: dict[str, Any]) -> list[str]:
    lines = ["## Executive summary", ""]
    exposure = summary.get("exposure")
    if exposure:
        lines += [str(exposure), ""]
    by_severity = summary.get("counts_by_severity")
    if isinstance(by_severity, dict) and by_severity:
        lines += ["| Severity | Count |", "| --- | --- |"]
        for severity, count in by_severity.items():
            lines.append(f"| {_cell(severity)} | {count} |")
        lines.append("")
    non_claim = summary.get("non_claim")
    if non_claim:
        lines += [f"> {non_claim}", ""]
    return lines


def _md_dashboard(dashboard: dict[str, Any]) -> list[str]:
    rows = dashboard.get("rows")
    if not isinstance(rows, list) or not rows:
        return []
    lines = [
        "## Priority dashboard",
        "",
        "| Finding | Class | Severity | Effort | Priority |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        if not isinstance(row, dict):
            continue
        lines.append(
            "| {finding} | {vuln} | {severity} | {effort} | {priority} |".format(
                finding=_cell(row.get("finding_id")),
                vuln=_cell(row.get("vuln_class")),
                severity=_cell(row.get("severity")),
                effort=_cell(row.get("effort")),
                priority=_cell(row.get("priority")),
            )
        )
    skipped = dashboard.get("skipped_unclassified")
    if isinstance(skipped, int) and skipped:
        lines += ["", f"Skipped unclassified findings: {skipped}."]
    lines.append("")
    return lines


def _md_findings(payload: dict[str, Any]) -> list[str]:
    findings = payload.get("findings")
    if not isinstance(findings, list) or not findings:
        return []
    lines = [
        "## Findings",
        "",
        "| ID | Title | Severity | Class |",
        "| --- | --- | --- | --- |",
    ]
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        lines.append(
            "| {fid} | {title} | {severity} | {vuln} |".format(
                fid=_cell(finding.get("finding_id")),
                title=_cell(finding.get("title") or "Untitled finding"),
                severity=_cell(finding.get("severity") or "unknown"),
                vuln=_cell(finding.get("vuln_class") or "unknown"),
            )
        )
    lines += [
        "",
        "> Only identifiers, titles, severity and class are listed here; "
        "request and response data stay in the machine-readable JSON report.",
        "",
    ]
    return lines


def _md_remediation(remediation: dict[str, Any]) -> list[str]:
    lines = ["## Remediation guidance", ""]
    non_claim = remediation.get("non_claim")
    if non_claim:
        lines += [f"> {non_claim}", ""]
    return lines


def build_markdown(payload: dict[str, Any]) -> str:
    iteration = payload.get("iteration")
    max_iterations = payload.get("max_iterations")
    lines = [
        "# WebPent engagement report",
        "",
        f"- Engagement: {_cell(payload.get('engagement_id'))}",
        f"- Target: {_cell(payload.get('target_url'))}",
        f"- Phase: {_cell(payload.get('phase'))}  |  Outcome: "
        f"{_cell(payload.get('outcome') or 'n/a')}",
        f"- Iterations: {_cell(iteration if iteration is not None else 'n/a')}"
        f" of {_cell(max_iterations if max_iterations is not None else 'n/a')}",
        "",
    ]
    counts = payload.get("counts")
    if isinstance(counts, dict):
        lines += [
            f"- {_cell(key)}: {value}"
            for key, value in sorted(counts.items())
            if isinstance(value, int)
        ] + [""]
    summary = payload.get("remediation", {}).get("executive_summary") \
        if isinstance(payload.get("remediation"), dict) else None
    if isinstance(summary, dict):
        lines += _md_executive(summary)
    dashboard = payload.get("remediation", {}).get("priority_dashboard") \
        if isinstance(payload.get("remediation"), dict) else None
    if isinstance(dashboard, dict):
        lines += _md_dashboard(dashboard)
    lines += _md_findings(payload)
    remediation = payload.get("remediation")
    if isinstance(remediation, dict):
        lines += _md_remediation(remediation)
    lines += ["---", f"> {_MD_NON_CLAIM}", ""]
    return "\n".join(lines)


_CSS = """
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;
padding:0 1rem;color:#1a1a1a;background:#fafafa}
h1{border-bottom:2px solid #333}h2{margin-top:2rem}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}
th{background:#eee}
blockquote{border-left:4px solid #b90;padding:.4rem 1rem;color:#555;
background:#fffbea}
code{background:#eee;padding:.1rem .3rem}
"""


def build_html(payload: dict[str, Any]) -> str:
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>WebPent engagement report</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>WebPent engagement report</h1>",
        "<table>",
        f"<tr><th>Engagement</th><td>{_esc(payload.get('engagement_id'))}</td></tr>",
        f"<tr><th>Target</th><td>{_esc(payload.get('target_url'))}</td></tr>",
        f"<tr><th>Outcome</th><td>{_esc(payload.get('outcome') or 'n/a')}</td></tr>",
        "</table>",
    ]
    counts = payload.get("counts")
    if isinstance(counts, dict):
        parts.append("<h2>Counts</h2><table>")
        for key, value in sorted(counts.items()):
            if isinstance(value, int):
                parts.append(f"<tr><th>{_esc(key)}</th><td>{value}</td></tr>")
        parts.append("</table>")
    raw_remediation = payload.get("remediation")
    remediation = raw_remediation if isinstance(raw_remediation, dict) else None
    summary = remediation.get("executive_summary") if remediation else None
    if isinstance(summary, dict):
        parts.append("<h2>Executive summary</h2>")
        if summary.get("exposure"):
            parts.append(f"<p>{_esc(summary['exposure'])}</p>")
        by_severity = summary.get("counts_by_severity")
        if isinstance(by_severity, dict) and by_severity:
            parts.append("<table><tr><th>Severity</th><th>Count</th></tr>")
            for severity, count in by_severity.items():
                parts.append(
                    f"<tr><td>{_esc(severity)}</td><td>{count}</td></tr>"
                )
            parts.append("</table>")
        if summary.get("non_claim"):
            parts.append(f"<blockquote>{_esc(summary['non_claim'])}</blockquote>")
    dashboard = remediation.get("priority_dashboard") if remediation else None
    dashboard_rows = dashboard.get("rows") if isinstance(dashboard, dict) else None
    if isinstance(dashboard_rows, list) and dashboard_rows:
        parts.append(
            "<h2>Priority dashboard</h2><table><tr><th>Finding</th><th>Class</th>"
            "<th>Severity</th><th>Effort</th><th>Priority</th></tr>"
        )
        for row in dashboard_rows:
            if not isinstance(row, dict):
                continue
            parts.append(
                "<tr><td>{f}</td><td>{c}</td><td>{s}</td><td>{e}</td><td>{p}</td></tr>".format(
                    f=_esc(row.get("finding_id")),
                    c=_esc(row.get("vuln_class")),
                    s=_esc(row.get("severity")),
                    e=_esc(row.get("effort")),
                    p=_esc(row.get("priority") if row.get("priority") is not None else ""),
                )
            )
        parts.append("</table>")
        skipped = dashboard.get("skipped_unclassified")
        if isinstance(skipped, int) and skipped:
            parts.append(
                f"<p>Skipped unclassified findings: "
                f"{dashboard['skipped_unclassified']}.</p>"
            )
    findings = payload.get("findings")
    if isinstance(findings, list) and findings:
        parts.append(
            "<h2>Findings</h2><table><tr><th>ID</th><th>Title</th>"
            "<th>Severity</th><th>Class</th></tr>"
        )
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            parts.append(
                "<tr><td>{f}</td><td>{t}</td><td>{s}</td><td>{c}</td></tr>".format(
                    f=_esc(finding.get("finding_id")),
                    t=_esc(finding.get("title") or "Untitled finding"),
                    s=_esc(finding.get("severity") or "unknown"),
                    c=_esc(finding.get("vuln_class") or "unknown"),
                )
            )
        parts.append("</table>")
        parts.append(
            "<blockquote>Only identifiers, titles, severity and class are "
            "listed here; request and response data stay in the "
            "machine-readable JSON report.</blockquote>"
        )
    if remediation and remediation.get("non_claim"):
        parts.append(
            f"<h2>Remediation guidance</h2>"
            f"<blockquote>{_esc(remediation['non_claim'])}</blockquote>"
        )
    parts.append(f"<hr><blockquote>{_esc(_MD_NON_CLAIM)}</blockquote>")
    parts.append("</body></html>")
    return "".join(parts)


def build_engagement_report(payload: dict[str, Any], fmt: str = "markdown") -> dict[str, Any]:
    """Render a hunt report payload into a deliverable document."""
    if fmt not in _FORMATS:
        raise ValueError(f"unsupported report format {fmt!r}; expected one of {_FORMATS}")
    content = build_markdown(payload) if fmt == "markdown" else build_html(payload)
    return {
        "content": content,
        "fmt": fmt,
        "non_claim": _MD_NON_CLAIM,
    }


__all__ = ["build_engagement_report", "build_html", "build_markdown"]
