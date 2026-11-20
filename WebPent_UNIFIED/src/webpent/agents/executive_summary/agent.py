# src/webpent/agents/executive_summary/agent.py
"""webpent.agents.executive_summary.agent

V5 Sprint 11 — AI Executive Summary Node.

A LangGraph node that runs immediately before the reporter. It ingests
ALL findings, calculates an overall Risk Score (Critical/High/Medium/Low),
and prompts the LLM to draft a two-paragraph C-Suite-level executive
summary with a business impact statement.

The summary and risk score are saved in the graph state
(``state["executive_summary"]`` and ``state["risk_score"]``) so the
reporter node can embed them in the final report.

Integration:
    Inserted between NODE_CROSS_REASONING and NODE_REPORTER.
    reporter_node reads state["executive_summary"] and
    state["risk_score"] when composing the report.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from webpent.models.findings import Finding, Severity
from webpent.shared.llm import (
    TaskType,
    get_safety_system_instruction,
    safe_prompt_format,
    try_get_llm,
)
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a Senior Security Consultant writing a C-Suite-level "
    "Executive Summary for a penetration test engagement. The audience "
    "is executives (CEO, CISO, CFO) — not engineers. Use clear, "
    "business-focused language. Avoid technical jargon; where "
    "technical terms are unavoidable, briefly explain their business "
    "impact.\n\n"
    "Write EXACTLY two paragraphs:\n"
    "  Paragraph 1: Overall security posture and the most critical "
    "risks, expressed in terms of business impact (data breach, "
    "regulatory fines, reputational damage, service disruption).\n"
    "  Paragraph 2: Recommended remediation priorities and a brief "
    "note on residual risk after remediation.\n\n"
    "Do not use markdown headers, bullet points, or code blocks. "
    "Plain text only.\n\n"
    "V10 P0-4 EVIDENCE INTEGRITY: 'Tool-Confirmed' findings represent "
    "proven exploit posture — you may describe them as verified "
    "vulnerabilities. ALL OTHER confidence levels (AI-Assessed, Needs "
    "Human Review, Pending, Not Scanned, Clean) are UNCONFIRMED — you "
    "MUST describe them as 'candidate', 'potential', 'requires "
    "verification', or 'hypothesis', NEVER as proven vulnerabilities. "
    "When confirmed_count is 0, the overall posture is 'unconfirmed' "
    "— do NOT claim High or Critical exploit risk from unconfirmed "
    "rows alone."
)

_HUMAN_TEMPLATE = (
    "Target URL: {url}\n"
    "Total findings: {count}\n"
    "Risk score: {risk_score}\n"
    "Severity breakdown: {severity_breakdown}\n"
    "Tool-Confirmed findings: {confirmed_count}\n"
    "Top findings (by severity):\n{top_findings}\n\n"
    "Draft a two-paragraph C-Suite executive summary with business "
    "impact statement."
)

# Risk score thresholds based on severity counts.
# The highest severity with >=1 finding determines the overall risk.
_RISK_PRIORITY = [
    (Severity.CRITICAL.value, "Critical"),
    (Severity.HIGH.value, "High"),
    (Severity.MEDIUM.value, "Medium"),
    (Severity.LOW.value, "Low"),
]

# V10 P0-4 (RCA follow-up): confidence levels that count as "confirmed"
# for risk-score purposes. Only Tool-Confirmed findings represent proven
# exploit posture. AI-Assessed / Needs Human Review / Pending / Not
# Scanned / Clean are unconfirmed — they must NOT drive a High/Critical
# executive risk score. See _calculate_risk_score below.
_CONFIRMED_CONFIDENCE_LEVELS = frozenset({"Tool-Confirmed"})


def _calculate_risk_score(findings: list[Finding]) -> str:
    """Calculate the overall risk score from the findings list.

    V5 Sprint 11: The risk score is determined by the highest-severity
    finding. If there are no findings, the risk is "Low" (no issues
    detected). If there is at least one Critical finding, the risk is
    "Critical", and so on.

    V10 P0-4 (RCA follow-up): the risk score is now driven ONLY by
    Tool-Confirmed findings. Unconfirmed findings (AI-Assessed, Needs
    Human Review, Pending, Not Scanned, Clean, recon-only) do NOT
    count toward the executive risk posture. When confirmed_count == 0,
    the risk is capped at "Low" with an explicit "Unconfirmed — zero
    tool confirmations" label, regardless of how many high-severity
    hypotheses or AI-Assessed findings exist. This makes it impossible
    to publish "High" executive risk driven only by unconfirmed
    recon/hypothesis rows.

    Args:
        findings: The list of all findings from the engagement.

    Returns:
        One of "Critical", "High", "Medium", "Low", or
        "Unconfirmed — zero tool confirmations".
    """
    if not findings:
        return "Low"

    # V10 P0-4: filter to confirmed findings only for risk scoring.
    confirmed_findings = [
        f for f in findings
        if getattr(f, "confidence_level", "") in _CONFIRMED_CONFIDENCE_LEVELS
    ]
    if not confirmed_findings:
        # Zero tool confirmations — cap at "Low" with explicit label.
        return "Unconfirmed — zero tool confirmations"

    severities = {str(f.severity).lower() for f in confirmed_findings}
    for sev_value, risk_label in _RISK_PRIORITY:
        if sev_value in severities:
            return risk_label
    return "Low"


def _severity_breakdown(findings: list[Finding]) -> str:
    """Return a human-readable severity breakdown string."""
    counts: dict[str, int] = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
        Severity.INFO.value: 0,
    }
    for f in findings:
        sev = str(f.severity).lower()
        if sev in counts:
            counts[sev] += 1
    parts = [f"{count} {sev.title()}" for sev, count in counts.items() if count > 0]
    return ", ".join(parts) if parts else "none"


def _top_findings_summary(findings: list[Finding], limit: int = 5) -> str:
    """Return a summary of the top findings by severity."""
    if not findings:
        return "(no findings)"

    severity_rank = {
        Severity.CRITICAL.value: 4,
        Severity.HIGH.value: 3,
        Severity.MEDIUM.value: 2,
        Severity.LOW.value: 1,
        Severity.INFO.value: 0,
    }
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_rank.get(str(f.severity).lower(), 0),
        reverse=True,
    )
    lines: list[str] = []
    for f in sorted_findings[:limit]:
        lines.append(
            f"  - [{str(f.severity).upper()}] {f.title} "
            f"({f.vuln_class}, {f.confidence_level}) — {f.url}"
        )
    return "\n".join(lines)


def _generate_executive_summary(
    target_url: str,
    findings: list[Finding],
    risk_score: str,
    llm: Any,
) -> str:
    """Prompt the LLM to generate the two-paragraph executive summary.

    Returns the LLM's text response, or a fallback summary if the LLM
    fails.
    """
    # V10 P0-4: confirmed_count must count Tool-Confirmed findings
    # (confidence_level), NOT the deprecated `confidence` enum field
    # which is set to CONFIRMED by sqlmap/dalfox but also by
    # Playwright dialog detection — the authoritative signal is
    # confidence_level == "Tool-Confirmed".
    confirmed_count = sum(
        1 for f in findings
        if getattr(f, "confidence_level", "") == "Tool-Confirmed"
    )

    human_prompt = safe_prompt_format(
        _HUMAN_TEMPLATE,
        url=target_url,
        count=len(findings),
        risk_score=risk_score,
        severity_breakdown=_severity_breakdown(findings),
        confirmed_count=confirmed_count,
        top_findings=_top_findings_summary(findings),
    )

    if llm is not None:
        try:
            response = llm.invoke(
                [
                    SystemMessage(content=get_safety_system_instruction()),
                    SystemMessage(content=_SYSTEM_PROMPT),
                    HumanMessage(content=human_prompt),
                ]
            )
            summary: str = (
                response.content
                if isinstance(response.content, str)
                else str(response.content)
            )
            return summary.strip()
        except Exception as exc:  # noqa: BLE001 — LLM failure must not abort the graph
            logger.warning(
                "Executive summary LLM failed: %s — using fallback summary", exc
            )
    else:
        logger.info("Executive summary LLM disabled/unavailable; using deterministic fallback")

    # V10 P0-4: fallback language must respect confirmed_count.
    # When confirmed_count == 0, the posture is "unconfirmed" — do
    # NOT claim High/Critical exploit risk from unconfirmed rows.
    if confirmed_count == 0:
        return (
            f"Automated penetration testing of {target_url} identified "
            f"{len(findings)} candidate finding(s). None have been "
            f"tool-confirmed — the overall risk posture is UNCONFIRMED "
            f"and requires verification before drawing exploit-risk "
            f"conclusions. The candidate findings should be triaged "
            f"manually to determine which warrant deeper validation.\n\n"
            f"Remediation should not be prioritised on unconfirmed "
            f"rows alone. A follow-up engagement with the target's "
            f"authentication context (or with OOB callback enabled) "
            f"is recommended to convert candidates into confirmed "
            f"findings and establish a verified risk baseline."
        )
    return (
        f"Automated penetration testing of {target_url} identified "
        f"{len(findings)} security finding(s) "
        f"({confirmed_count} tool-confirmed) with an overall risk "
        f"score of {risk_score}. The most critical confirmed issues "
        f"should be remediated immediately to prevent potential data "
        f"breach, regulatory penalties, or service disruption.\n\n"
        f"Remediation should prioritise the {risk_score.lower()}-"
        f"severity confirmed findings identified in this report. "
        f"Residual risk after remediation should be reassessed in a "
        f"follow-up engagement to verify effective closure of all "
        f"identified vulnerabilities."
    )


def executive_summary_node(state: PentestState) -> dict:
    """LangGraph node that generates the AI executive summary + risk score.

    V5 Sprint 11: Runs before the reporter node. Reads all findings from
    state, calculates the overall risk score, prompts the LLM for a
    two-paragraph C-Suite summary, and saves both in the graph state.
    """
    target = state["target"]
    findings: list[Finding] = list(state.get("findings") or [])

    risk_score = _calculate_risk_score(findings)
    logger.info(
        "Executive summary node: %d findings, risk score = %s",
        len(findings), risk_score,
    )

    llm = try_get_llm(TaskType.ANALYSIS)
    summary = _generate_executive_summary(
        target.url, findings, risk_score, llm
    )

    return {
        "executive_summary": summary,
        "risk_score": risk_score,
        "messages": [
            AIMessage(
                content=(
                    f"Executive summary generated (risk={risk_score}, "
                    f"{len(findings)} findings)."
                )
            )
        ],
        "current_phase": "executive_summary",
    }
