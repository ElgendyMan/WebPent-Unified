# src/webpent/agents/cross_reasoning/agent.py
"""webpent.agents.cross_reasoning.agent

LangGraph node that identifies potential attack chains by reasoning
across all findings.

The cross-reasoning agent looks at the full findings list and asks the
LLM to identify combinations of vulnerabilities that, when chained
together, produce a more severe impact than any individual finding.
For example:

  * XSS + CSRF → session hijacking and account takeover
  * IDOR + SSRF → internal service exploitation via parameter
    manipulation
  * Open redirect + credential harvesting → phishing-driven ATO

Each identified chain is appended to ``state["hypotheses"]`` via the
:func:`merge_lists` reducer.

V7 Cognitive Upgrade — Phase 1 (atomic type migration):
    This node previously emitted ``list[str]`` (bare attack-chain
    descriptions) into ``state["hypotheses"]``. After Phase 1's
    atomic migration of ``state["hypotheses"]`` from ``list[str]`` to
    ``list[Hypothesis]``, this node now wraps each chain description
    in a :class:`Hypothesis` object with ``origin=CROSS_REASONS``,
    ``vuln_class=UNKNOWN`` (a chain doesn't fit a single class), and a
    neutral ``confidence_score`` (0.3 — the chain is LLM-proposed, not
    tool-confirmed, so it starts at the same base as a heuristic match).
    The LLM's narrative text is preserved in ``statement``; the
    ``origin_detail`` field records that this came from cross-reasoning
    narrative synthesis. This keeps the type migration atomic — no
    window where the field holds a mixed-type list.

Resilience:
    LLM invocation and JSON parsing are wrapped in ``try/except``. On
    any failure the node returns an empty hypotheses list so the graph
    continues cleanly.
"""

from __future__ import annotations

import json
import logging

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from webpent.models.findings import EXPLOITABLE_CLASSES, Finding, VulnClass
from webpent.models.hypothesis import Hypothesis, HypothesisOrigin
from webpent.shared.confidence import compute_initial_hypothesis_confidence
from webpent.shared.llm import (
    TaskType,
    get_safety_system_instruction,
    safe_prompt_format,
    try_get_llm,
)
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are an expert penetration tester specialising in attack-chain "
    "analysis. Given a list of vulnerabilities, identify potential "
    "attack chains — combinations of two or more findings that, when "
    "exploited together, produce a more severe impact than any "
    "individual finding (e.g. XSS + CSRF = account takeover). "
    "Return a JSON list of strings, where each string describes one "
    "attack chain in a single sentence. If no chains are possible, "
    "return an empty list."
)

_HUMAN_TEMPLATE = (
    "Target URL: {url}\n"
    "Total findings: {count}\n\n"
    "Findings:\n{findings}\n\n"
    "Identify potential attack chains and return a JSON list of strings."
)

# Maximum number of findings to include in the LLM prompt.
_MAX_FINDINGS_FOR_LLM = 25

# Cap on per-finding summary length.
_MAX_FINDING_SUMMARY_CHARS = 150

# Severity ranking for sorting (most severe first).
_SEVERITY_RANKS: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _format_findings(findings: list[Finding]) -> str:
    """Format findings into a compact list for the LLM prompt."""
    if not findings:
        return "(no findings)"

    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_RANKS.get(str(f.severity), 99),
    )

    lines: list[str] = []
    for i, finding in enumerate(sorted_findings[:_MAX_FINDINGS_FOR_LLM], start=1):
        summary = f"  {i}. [{finding.severity}] {finding.title} (confidence: {finding.confidence})"
        if len(summary) > _MAX_FINDING_SUMMARY_CHARS:
            summary = summary[: _MAX_FINDING_SUMMARY_CHARS - 3] + "..."
        lines.append(summary)

    return "\n".join(lines)


def _parse_attack_chains(raw_response: str) -> list[str]:
    """Parse the LLM's JSON list response into a list of chain strings.

    Defends against common drift: markdown code fences, bare strings,
    trailing text, or malformed JSON.
    """
    text = raw_response.strip()

    # Strip markdown code fences.
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    # Attempt JSON parse.
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if item and str(item).strip()]
        if isinstance(parsed, str):
            stripped = parsed.strip()
            return [stripped] if stripped else []
    except json.JSONDecodeError:
        pass
        # Intentionally suppressed — reviewed 2026-09-03

    # Fallback: extract JSON array from the middle of the text.
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        try:
            parsed = json.loads(text[start : end + 1])
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if item and str(item).strip()]
        except json.JSONDecodeError:
            pass
            # Intentionally suppressed — reviewed 2026-09-03

    logger.warning("Could not parse attack-chain response as JSON list")
    return []


def cross_reasoning_node(state: PentestState) -> dict:
    """LangGraph node implementing the cross-reasoning phase.

    Analyses all findings to identify potential attack chains and
    appends them to ``state["hypotheses"]``.

    Args:
        state: Current graph state. Must contain ``target`` and
            ``findings``.

    Returns:
        A partial state update with three keys:
          * ``hypotheses`` — list of attack-chain strings. Appended to
            existing hypotheses via the :func:`merge_lists` reducer.
          * ``messages`` — a single :class:`AIMessage` summarising the
            phase outcome.
          * ``current_phase`` — set to ``"cross_reasoning"``.
    """
    target = state["target"]
    findings: list[Finding] = list(state.get("findings") or [])

    logger.info(
        "Cross-reasoning phase starting for target=%s (%d findings)",
        target.url,
        len(findings),
    )

    if not findings:
        logger.info("Cross-reasoning: no findings to analyse — skipping")
        return {
            "hypotheses": [],
            "messages": [AIMessage(content="Cross-reasoning skipped — no findings.")],
            "current_phase": "cross_reasoning",
        }

    llm = try_get_llm(TaskType.ANALYSIS)
    if llm is None:
        summary = (
            "Cross-reasoning skipped in deterministic offline mode — "
            "semantic attack-chain synthesis requires an enabled provider."
        )
        logger.info(summary)
        return {
            "hypotheses": [],
            "messages": [AIMessage(content=summary)],
            "current_phase": "cross_reasoning",
        }

    human_prompt = safe_prompt_format(
        _HUMAN_TEMPLATE,
        url=target.url,
        count=len(findings),
        findings=_format_findings(findings),
    )

    try:
        response = llm.invoke(
            [
                SystemMessage(content=get_safety_system_instruction()),
                SystemMessage(content=_SYSTEM_PROMPT),
                HumanMessage(content=human_prompt),
            ]
        )
        raw_text: str = (
            response.content if isinstance(response.content, str) else str(response.content)
        )
    except Exception as exc:  # noqa: BLE001 — all fallbacks exhausted
        logger.error("All LLM providers failed for cross-reasoning: %s", exc)
        return {
            "hypotheses": [],
            "messages": [
                AIMessage(content="Cross-reasoning failed — all LLM providers unavailable.")
            ],
            "current_phase": "cross_reasoning",
        }

    attack_chains = _parse_attack_chains(raw_text)
    logger.info(
        "Cross-reasoning identified %d potential attack chain(s)",
        len(attack_chains),
    )

    # V7 Cognitive Upgrade — Phase 1: wrap each chain string in a
    # Hypothesis object so state["hypotheses"] stays list[Hypothesis]
    # (atomic type migration — no mixed-type list window). The chain
    # is LLM-proposed narrative, so origin=CROSS_REASONS and
    # confidence_score=0.3 (same base as a heuristic match — the LLM
    # drafted it, but no tool has confirmed it). It must remain a proposal
    # until a tool-backed causal signal and negative control are validated.
    # V10 P3-1 FIX: Previously ALL cross-reasoning chain hypotheses got
    # vuln_class=UNKNOWN, which is NOT in EXPLOITABLE_CLASSES — so the
    # Strategist's promote_hypothesis_to_finding (prioritization.py)
    # blocked them and the cross-reasoning -> Strategist closed loop
    # was functionally inert (same bug class as rabbit_hole's H3).
    # Fix: map each chain to the higher-severity finding's vuln_class
    # (so the chain inherits the class of its strongest link). If the
    # findings list is empty OR the top-severity finding's vuln_class
    # is not in EXPLOITABLE_CLASSES (no clear mapping), fall back to
    # VulnClass.SSRF.value (same default as rabbit_hole's
    # _infer_rabbit_hole_vuln_class). The chain is still an LLM-synthesized
    # narrative and cannot receive deterministic promotion from links alone.
    _chain_vuln_class: str = VulnClass.SSRF.value  # safe default
    if findings:
        _sorted_for_class = sorted(
            findings,
            key=lambda f: _SEVERITY_RANKS.get(str(f.severity), 99),
        )
        _top_vuln_class = getattr(_sorted_for_class[0], "vuln_class", None)
        if _top_vuln_class and _top_vuln_class in EXPLOITABLE_CLASSES:
            _chain_vuln_class = _top_vuln_class

    new_hypotheses: list[Hypothesis] = []
    for chain_text in attack_chains:
        if not chain_text or not chain_text.strip():
            continue
        new_hypotheses.append(
            Hypothesis(
                target_url=target.url,
                statement=chain_text.strip()[:500],  # enforce model max_length
                vuln_class=_chain_vuln_class,
                origin=HypothesisOrigin.CROSS_REASONS.value,
                origin_detail=(
                    "Attack chain proposed by cross_reasoning_node "
                    "via LLM narrative synthesis across confirmed findings."
                ),
                confidence_score=compute_initial_hypothesis_confidence(
                    HypothesisOrigin.CROSS_REASONS,
                    source_kind="cross_reasoning",
                    deterministic_match=False,
                ),
                # LLM narrative synthesis is not a deterministic validator.
                # Promotion remains gated by tool-backed causal evidence and
                # a completed negative control in the normal pipeline.
                deterministic_match=False,
            )
        )

    summary = (
        f"Cross-reasoning completed. Identified {len(new_hypotheses)} "
        f"potential attack chain(s) from {len(findings)} finding(s)."
    )
    logger.info(summary)

    return {
        "hypotheses": new_hypotheses,
        "messages": [AIMessage(content=summary)],
        "current_phase": "cross_reasoning",
    }
