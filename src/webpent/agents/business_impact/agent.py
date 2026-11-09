# src/webpent/agents/business_impact/agent.py
"""webpent.agents.business_impact.agent

LangGraph node that generates business-impact statements for confirmed
findings.

The business-impact agent iterates over all findings whose confidence
is ``CONFIRMED`` and asks the LLM to produce a 1–2 sentence statement
describing the real-world business consequences of the vulnerability
(e.g. data breach, regulatory fines, reputational damage, service
disruption). The statement is stored in the finding's
``business_impact`` field via ``model_copy``.

Resilience:
    LLM invocation is wrapped per-finding in ``try/except``. A failure
    on one finding does not abort impact analysis for the others.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from webpent.models.findings import Finding
from webpent.shared.llm import (
    TaskType,
    get_safety_system_instruction,
    safe_prompt_format,
    try_get_llm,
)
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a business risk analyst. Given a security vulnerability, "
    "produce a concise 1-2 sentence business impact statement AND a "
    "brief one-sentence justification for your assessment. "
    "Focus on real-world consequences: data breaches, regulatory "
    "penalties (GDPR, HIPAA), financial loss, reputational damage, "
    "service disruption, or compliance violations. "
    "Format: <impact statement> || <justification>\n"
    "Do not use markdown."
)

_HUMAN_TEMPLATE = (
    "Vulnerability title: {title}\n"
    "Severity: {severity}\n"
    "CVSS score: {cvss}\n"
    "URL: {url}\n"
    "Description: {description}\n\n"
    "What is the business impact of this vulnerability?"
)


def _assess_finding(finding: Finding, llm: Any) -> Finding:
    """Generate a business-impact statement for a single confirmed finding.

    Returns the original finding unchanged on any failure; returns a
    mutated copy with ``business_impact`` set on success.
    """
    if llm is None:
        # Business-impact prose is optional in deterministic offline mode.
        # Preserve the evidence-backed finding without inventing impact text.
        return finding

    human_prompt = safe_prompt_format(
        _HUMAN_TEMPLATE,
        title=finding.title,
        severity=finding.severity,
        cvss=finding.cvss_score or "(not scored)",
        url=finding.url,
        description=finding.description,
    )

    try:
        response = llm.invoke(
            [
                SystemMessage(content=get_safety_system_instruction()),
                SystemMessage(content=_SYSTEM_PROMPT),
                HumanMessage(content=human_prompt),
            ]
        )
        impact: str = (
            response.content
            if isinstance(response.content, str)
            else str(response.content)
        )
    except Exception as exc:  # noqa: BLE001 — all fallbacks exhausted
        logger.error(
            "LLM failed for business impact of finding %s: %s",
            finding.id,
            exc,
        )
        return finding

    # Clean up the response (strip whitespace, markdown fences).
    impact = impact.strip()
    if impact.startswith("```"):
        lines = impact.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        impact = "\n".join(lines).strip()

    # V5 Audit Trail: Split impact and reasoning on "||" separator.
    reasoning = ""
    if "||" in impact:
        parts = impact.split("||", 1)
        impact = parts[0].strip()
        reasoning = parts[1].strip()
    else:
        reasoning = "No separate justification provided by LLM."

    if not impact:
        logger.warning(
            "Empty business impact for finding %s — leaving unset",
            finding.id,
        )
        return finding

    logger.info(
        "Business impact generated for finding %s (%s)",
        finding.id,
        finding.title,
    )

    # V5: Store both the impact statement and the reasoning.
    existing_reasoning = getattr(finding, "reasoning", "") or ""
    combined_reasoning = (
        f"{existing_reasoning}\nBusiness Impact: {reasoning}"
        if existing_reasoning
        else f"Business Impact: {reasoning}"
    )

    return finding.model_copy(
        update={
            "business_impact": impact,
            "reasoning": combined_reasoning,
        }
    )


def business_impact_node(state: PentestState) -> dict:
    """LangGraph node implementing the business-impact analysis phase.

    V4.5 Sprint 3: Assesses ALL findings, not just confirmed ones.
    Every finding regardless of ``vuln_class`` or ``confidence``
    receives a business impact statement. For UNKNOWN classes, the
    LLM is guided by the original ``severity`` from the scanning tool.

    Args:
        state: Current graph state. Must contain ``findings``.

    Returns:
        A partial state update with two keys:
          * ``findings`` — the full findings list with business impact.
          * ``messages`` — a single :class:`AIMessage` summarising the
            phase outcome.
    """
    findings: list[Finding] = list(state.get("findings") or [])

    logger.info(
        "Business impact analysis starting: %d total finding(s)", len(findings)
    )

    findings_by_id: dict[UUID, Finding] = {f.id: f for f in findings}

    llm = try_get_llm(TaskType.ANALYSIS)

    assessed_count = 0

    for finding in findings:
        # V4.5 Sprint 3: Assess ALL findings, not just confirmed ones.
        updated = _assess_finding(finding, llm)
        if updated.business_impact is not None:
            assessed_count += 1
            findings_by_id[finding.id] = updated

    updated_findings: list[Finding] = [
        findings_by_id[f.id] for f in findings if f.id in findings_by_id
    ]

    summary = (
        f"Business impact analysis completed. Assessed {assessed_count} of "
        f"{len(findings)} total finding(s)."
    )
    logger.info(summary)

    return {
        "findings": updated_findings,
        "messages": [AIMessage(content=summary)],
    }
