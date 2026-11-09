# src/webpent/agents/waf_detector/agent.py
"""webpent.agents.waf_detector.agent

LangGraph node that detects the presence of a Web Application Firewall
(WAF) by analysing crawled data and the conversation transcript.

Knowing whether a WAF is in front of the target is critical for the
payload generator and validator: a WAF may block standard payloads
(naive ``<script>alert(1)</script>``, ``' OR 1=1--``) while allowing
WAF-bypass variants (SVG-based XSS, Unicode-encoded SQLi). The WAF
detector surfaces this context early so downstream agents can adjust
their payload strategies.

Resilience:
    LLM invocation is wrapped in ``try/except``. If all providers fail,
    the node returns a conservative "unknown" verdict so the graph
    continues without crashing.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from webpent.shared.llm import (
    TaskType,
    get_safety_system_instruction,
    safe_prompt_format,
    try_get_llm,
)
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a Web Application Firewall (WAF) detection specialist. "
    "Analyse the provided crawl data and conversation messages for "
    "evidence of a WAF. Look for indicators such as: blocked requests, "
    "HTTP 403/406 responses, challenge pages, WAF-specific headers "
    "(e.g. cf-ray, x-sucuri-id), or cookie patterns. "
    "Respond with a single paragraph describing whether a WAF is "
    "present, which WAF it might be, and any bypass strategies you "
    "recommend. Do not use markdown."
)

_HUMAN_TEMPLATE = (
    "Target URL: {url}\n\n"
    "Crawled data:\n{crawled_data}\n\n"
    "Recent conversation:\n{conversation}\n\n"
    "Analyse this data for WAF presence and respond with your assessment."
)

# Maximum number of crawled endpoints to include in the prompt.
_MAX_ENDPOINTS_FOR_LLM = 30

# Maximum number of recent messages to include in the prompt.
_MAX_MESSAGES_FOR_LLM = 10


def _format_crawled_data(crawled_data: dict[str, Any]) -> str:
    """Format crawled data for inclusion in the LLM prompt."""
    if not crawled_data:
        return "(no crawled data)"

    endpoints = crawled_data.get("endpoints", [])
    if not endpoints:
        return "(no endpoints discovered)"

    lines: list[str] = []
    for i, endpoint in enumerate(endpoints[:_MAX_ENDPOINTS_FOR_LLM], start=1):
        if isinstance(endpoint, str):
            lines.append(f"  {i}. {endpoint}")
        elif isinstance(endpoint, dict):
            url = endpoint.get("url") or endpoint.get("endpoint") or "?"
            lines.append(f"  {i}. {url}")
        else:
            lines.append(f"  {i}. {endpoint}")

    return "\n".join(lines)


def _format_conversation(messages: list[Any]) -> str:
    """Format recent conversation messages for the LLM prompt."""
    if not messages:
        return "(no conversation)"

    recent = messages[-_MAX_MESSAGES_FOR_LLM:]
    lines: list[str] = []
    for msg in recent:
        role = getattr(msg, "type", "unknown") or "unknown"
        content = getattr(msg, "content", "")
        if not content:
            continue
        content_str = str(content)
        if len(content_str) > 300:
            content_str = content_str[:297] + "..."
        lines.append(f"  [{role}] {content_str}")

    return "\n".join(lines) if lines else "(no conversation)"


def waf_detector_node(state: PentestState) -> dict:
    """LangGraph node implementing the WAF detection phase.

    Args:
        state: Current graph state. Must contain ``target``. Reads
            ``crawled_data`` and ``messages`` for context.

    Returns:
        A partial state update with two keys:
          * ``messages`` — a single :class:`AIMessage` containing the
            WAF detection assessment.
          * ``current_phase`` — set to ``"waf_detection"``.
    """
    target = state["target"]
    crawled_data: dict[str, Any] = state.get("crawled_data") or {}
    messages: list[Any] = list(state.get("messages") or [])

    logger.info("WAF detection phase starting for target=%s", target.url)
    # V10 P3-6: the WAF detector's output is informational only — no
    # structured state field (e.g. `waf_present: bool`) is consumed by
    # downstream agents (payload_generator, validator). The assessment
    # is preserved in the conversation log so it appears in the final
    # report's transcript and an operator can read it. RESIDUAL:
    # wiring a structured `waf` state field consumed by payload
    # selection is deferred.
    logger.info(
        "WAF detector: assessment is informational only — no structured "
        "state field consumed by downstream agents"
    )

    llm = try_get_llm(TaskType.ANALYSIS)
    if llm is None:
        assessment = (
            "WAF Detection: inconclusive — LLM assistance is unavailable or "
            "disabled. No WAF presence is asserted; continue with the "
            "deterministic evidence collected by the crawler."
        )
    else:
        human_prompt = safe_prompt_format(
            _HUMAN_TEMPLATE,
            url=target.url,
            crawled_data=_format_crawled_data(crawled_data),
            conversation=_format_conversation(messages),
        )
        try:
            response = llm.invoke(
                [
                    SystemMessage(content=get_safety_system_instruction()),
                    SystemMessage(content=_SYSTEM_PROMPT),
                    HumanMessage(content=human_prompt),
                ]
            )
            assessment = (
                response.content
                if isinstance(response.content, str)
                else str(response.content)
            )
            logger.info("WAF detection completed; assessment length=%d", len(assessment))
        except Exception as exc:  # noqa: BLE001 — all fallbacks exhausted
            logger.error("All LLM providers failed for WAF detector: %s", exc)
            assessment = (
                "WAF Detection: unable to determine WAF presence — all LLM "
                "providers were unavailable. Proceeding with caution; the "
                "payload generator should include WAF-bypass variants."
            )

    return {
        "messages": [AIMessage(content=f"WAF Detection: {assessment}")],
        "current_phase": "waf_detection",
    }
