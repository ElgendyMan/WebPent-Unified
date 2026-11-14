# src/webpent/agents/reflection/agent.py
"""webpent.agents.reflection.agent

LangGraph node that extracts lessons learned from an engagement and
persists them to long-term memory.

The reflection agent runs *after* the reporter (it is the terminal
node before END). It analyses the engagement's findings and
conversation transcript, then asks the LLM to distill 1–2 concise,
high-level lessons (e.g. "The target WAF blocks standard XSS but
allows SVG payloads").

Each extracted lesson is persisted to **two** stores:

  1. **SQLite** via :class:`LessonsManager` — for structured, queryable
     access (e.g. the ``viewer.py`` CLI can list all lessons).
  2. **Chroma vector store** via :class:`VectorStoreManager` — for
     semantic retrieval on future engagements (RAG). A future run
     against a similar target can retrieve this lesson by similarity
     search, informing the hypothesis and exploitation phases.

Resilience:
    LLM invocation, JSON parsing, SQLite persistence, and ChromaDB
    persistence are each wrapped in independent ``try/except`` blocks.
    A failure in any one store does not abort the others — e.g. if
    ChromaDB is unavailable, the lesson is still saved to SQLite. If
    the LLM fails entirely, the node returns an empty lessons list
    and the graph terminates cleanly.

RAG retrieval (future use):
    The lessons stored here can be retrieved at the start of a future
    engagement by calling ``get_vector_store_manager().search_lessons(target.url)``
    and feeding the results into the planner's prompt as context.
    This closes the learning loop: the framework gets smarter with
    every engagement.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from webpent.memory.vectorstore import get_vector_store_manager
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
    "You are a Security Reflection Agent. Analyze the pentest findings "
    "and extract 1 or 2 concise, high-level lessons learned (e.g., "
    "'The target WAF blocks standard XSS but allows SVG payloads'). "
    "Return a JSON list of strings. If no findings, return an empty list."
)

_HUMAN_TEMPLATE = (
    "Target URL: {url}\n"
    "Total findings: {findings_count}\n\n"
    "Findings summary:\n{findings_summary}\n\n"
    "Recent conversation:\n{conversation}\n\n"
    "Extract 1 or 2 concise, high-level lessons learned from this "
    "engagement. Return a JSON list of strings."
)

# Maximum number of findings to include in the LLM prompt. Including
# all findings could blow up the token budget on large engagements;
# the first 20 (sorted by severity) is a representative sample.
_MAX_FINDINGS_FOR_LLM = 20

# Maximum number of recent messages to include in the prompt.
_MAX_MESSAGES_FOR_LLM = 10

# Cap on per-finding summary length to keep the prompt compact.
_MAX_FINDING_SUMMARY_CHARS = 200

# Severity ranking for sorting findings (most severe first) so the LLM
# sees the most impactful issues first.
_SEVERITY_RANKS: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _format_findings_summary(findings: list[Finding]) -> str:
    """Format findings into a compact summary for the LLM prompt.

    Findings are sorted by severity (most severe first) and truncated
    to :data:`_MAX_FINDINGS_FOR_LLM` entries to stay within token
    limits.
    """
    if not findings:
        return "(no findings)"

    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_RANKS.get(str(f.severity), 99),
    )

    lines: list[str] = []
    for i, finding in enumerate(sorted_findings[:_MAX_FINDINGS_FOR_LLM], start=1):
        summary = f"  {i}. [{finding.severity}] {finding.title} (confidence: {finding.confidence})"
        if finding.payload:
            summary += f" — payload: {str(finding.payload)[:60]}"
        # Truncate to keep the prompt compact.
        if len(summary) > _MAX_FINDING_SUMMARY_CHARS:
            summary = summary[: _MAX_FINDING_SUMMARY_CHARS - 3] + "..."
        lines.append(summary)

    return "\n".join(lines)


def _format_conversation(messages: list[Any]) -> str:
    """Format recent conversation messages for the LLM prompt.

    Only the last :data:`_MAX_MESSAGES_FOR_LLM` messages are included
    to stay within token limits.
    """
    if not messages:
        return "(no conversation)"

    recent = messages[-_MAX_MESSAGES_FOR_LLM:]
    lines: list[str] = []
    for msg in recent:
        # ``msg`` is a LangChain BaseMessage; ``type`` is the role
        # (human/ai/system) and ``content`` is the text.
        role = getattr(msg, "type", "unknown") or "unknown"
        content = getattr(msg, "content", "")
        if not content:
            continue
        # Truncate long messages.
        content_str = str(content)
        if len(content_str) > 300:
            content_str = content_str[:297] + "..."
        lines.append(f"  [{role}] {content_str}")

    return "\n".join(lines) if lines else "(no conversation)"


def _parse_lessons(raw_response: str) -> list[str]:
    """Parse the LLM's JSON list response into a list of lesson strings.

    The LLM is instructed to emit a JSON array of strings, but we
    defend against common drift: markdown code fences, a bare string,
    trailing text, or a completely malformed response.
    """
    text = raw_response.strip()
    # Deterministic/no-LLM runs intentionally provide no model response.
    # Treat the empty value as an explicit no-op instead of reporting a
    # malformed LLM response; malformed non-empty responses still warn.
    if not text:
        return []

    # Strip markdown code fences if present.
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
            lessons = [str(item).strip() for item in parsed if item and str(item).strip()]
            return lessons
        if isinstance(parsed, str):
            # Bare string instead of list — wrap it.
            stripped = parsed.strip()
            return [stripped] if stripped else []
    except json.JSONDecodeError:
        pass
        # Intentionally suppressed — reviewed 2026-09-03

    # Fallback: try to extract a JSON array from the middle of the text.
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

    logger.warning("Could not parse LLM lessons response as JSON list")
    return []


def _persist_lesson(
    lesson: str,
    target_url: str,
    *,
    client_id: str | None,
    engagement_id: str | None,
) -> None:
    """Persist a single lesson to both SQLite and the Chroma vector store.

    Each store is persisted independently — a failure in one does not
    abort the other.

    V6 DX-Final — RAG Moderation:
    Both stores now receive the *sanitised* lesson content. The
    sanitisation itself happens inside ``LessonsManager.save_lesson``
    (SQLite path) and is replicated here for the Chroma path so the
    two stores stay consistent. If sanitisation reduces the lesson to
    an empty string (i.e. it was entirely a payload), the lesson is
    dropped from BOTH stores — we never want a sanitised SQLite row
    paired with a raw-payload Chroma embedding (that would defeat the
    moderation entirely).
    """
    if not str(client_id or "").strip() or not str(engagement_id or "").strip():
        logger.warning("Skipping lesson persistence without client_id and engagement_id")
        return

    # V6 DX-Final: Sanitise ONCE, up-front, so both stores receive
    # the same moderated content. Importing lazily to avoid a circular
    # import at module load time (memory.lessons imports nothing from
    # agents, but the lazy import keeps the dependency direction
    # explicit and survives future refactors).
    from webpent.memory.lessons import _sanitize_lesson_content

    sanitized_lesson = _sanitize_lesson_content(lesson)
    if not sanitized_lesson:
        logger.warning(
            "RAG moderation: lesson dropped before persistence "
            "(content was entirely payload or too short after "
            "sanitization). Original preview: %r",
            lesson[:80],
        )
        return

    # ---- SQLite persistence ----------------------------------------------
    try:
        from webpent.memory.lessons import get_lessons_manager

        lessons_manager = get_lessons_manager()
        # save_lesson re-applies _sanitize_lesson_content, but since
        # we already sanitised above, the second pass is a no-op
        # (idempotent). We keep the call to save_lesson (rather than
        # writing raw SQL) so the manager's locking + DDL path is
        # honoured. The return value is None when the manager's own
        # moderation drops the lesson — in that case we also skip
        # the Chroma write to keep the two stores consistent.
        lesson_id = lessons_manager.save_lesson(
            target_url=target_url,
            content=sanitized_lesson,
            client_id=client_id,
            engagement_id=engagement_id,
        )
        if lesson_id is None:
            logger.warning(
                "RAG moderation: lesson dropped by LessonsManager "
                "(SQLite). Skipping Chroma write to keep stores "
                "consistent. Preview: %r",
                sanitized_lesson[:80],
            )
            return
        logger.debug("Lesson saved to SQLite: %s", sanitized_lesson[:80])
    except Exception as exc:  # noqa: BLE001 — degrade gracefully
        logger.warning(
            "Failed to save lesson to SQLite: %s. Lesson: %s",
            exc,
            sanitized_lesson[:80],
        )

    # ---- Chroma vector store persistence ---------------------------------
    try:
        # V6 Titanium P2: use the process-wide singleton instead of
        # constructing a new VectorStoreManager. Each construction
        # re-loads the sentence-transformers embeddings model (~5s)
        # and re-opens Chroma collection handles, dominating RAG
        # latency. The singleton caches both for the process lifetime.
        vector_manager = get_vector_store_manager()
        # V6 DX-Final: persist the SANITISED lesson to the vector
        # store so semantic search cannot retrieve a raw payload as
        # a "lesson" on a future engagement.
        vector_manager.add_lesson(
            text=sanitized_lesson,
            metadata={
                "url": target_url,
                "client_id": str(client_id).strip(),
                "engagement_id": str(engagement_id).strip(),
            },
        )
        logger.debug("Lesson saved to Chroma: %s", sanitized_lesson[:80])
    except Exception as exc:  # noqa: BLE001 — degrade gracefully
        logger.warning(
            "Failed to save lesson to Chroma vector store: %s. Lesson: %s",
            exc,
            sanitized_lesson[:80],
        )


def reflection_node(state: PentestState) -> dict:
    """LangGraph node implementing the reflection phase.

    Analyses the engagement's findings and conversation transcript,
    extracts 1–2 high-level lessons, and persists them to long-term
    memory (SQLite + Chroma) for use in future engagements.

    Args:
        state: Current graph state. Must contain ``target``,
            ``findings``, and ``messages``.

    Returns:
        A partial state update with three keys:
          * ``lessons`` — list of extracted lesson strings. Appended to
            existing lessons via the :func:`merge_lists` reducer.
          * ``messages`` — a single :class:`AIMessage` summarising the
            reflection outcome.
          * ``current_phase`` — set to ``"reflection"``.
    """
    target = state["target"]
    findings: list[Finding] = list(state.get("findings") or [])
    messages: list[Any] = list(state.get("messages") or [])

    logger.info(
        "Reflection phase starting for target=%s (%d findings)",
        target.url,
        len(findings),
    )

    llm = try_get_llm(TaskType.ANALYSIS)

    human_prompt = safe_prompt_format(
        _HUMAN_TEMPLATE,
        url=target.url,
        findings_count=len(findings),
        findings_summary=_format_findings_summary(findings),
        conversation=_format_conversation(messages),
    )

    if llm is None:
        logger.info("Reflection LLM disabled/unavailable; using deterministic no-lesson fallback")
        raw_text = ""
    else:
        try:
            response = llm.invoke(
                [
                    SystemMessage(content=get_safety_system_instruction()),
                    SystemMessage(content=_SYSTEM_PROMPT),
                    HumanMessage(content=human_prompt),
                ]
            )
            raw_text = (
                response.content if isinstance(response.content, str) else str(response.content)
            )
        except Exception as exc:  # noqa: BLE001 — all fallbacks exhausted
            logger.warning(
                "Reflection LLM unavailable: %s. Using deterministic no-lesson fallback.",
                exc,
            )
            raw_text = ""

    extracted_lessons = _parse_lessons(raw_text)
    logger.info("Reflection agent extracted %d lesson(s)", len(extracted_lessons))

    # V9 P5 FEAT-1: Deterministic harvest of Tool-Confirmed findings.
    # Persist confirmed-finding patterns as cross-engagement intelligence
    # WITHOUT relying on the LLM. Only Tool-Confirmed findings are
    # harvested (no tentative/ai-assessed). No raw secrets/tokens are
    # stored — only the vuln_class, url path, and tool_name.
    client_id = state.get("client_id")
    engagement_id = state.get("engagement_id") or state.get("thread_id")

    confirmed_findings = [
        f for f in findings if getattr(f, "confidence_level", "") == "Tool-Confirmed"
    ]
    for cf in confirmed_findings:
        try:
            # Build a sanitized, non-sensitive lesson from the confirmed finding.
            from urllib.parse import urlparse

            parsed = urlparse(cf.url)
            path = parsed.path or "/"
            vc = cf.vuln_class or "unknown"
            tool = cf.tool_name or "unknown"
            sev = str(cf.severity or "unknown")
            intent = state.get("application_intent") or {}
            assumptions = [
                str(value)
                for value in (
                    intent.get("policy_assumptions") or state.get("policy_assumptions") or []
                )
                if str(value)
            ][:7]
            provenance = [
                str(value) for value in (getattr(cf, "hint_provenance", []) or []) if str(value)
            ][:8]
            # Store ONLY structural pattern intelligence, never host, payload,
            # cookies, request bodies, or raw evidence.
            pattern_lesson = (
                f"Pattern memory: confirmed {vc} ({sev}) at route shape '{path}' "
                f"via validator '{tool}'; hint_methods={','.join(provenance) or 'unknown'}; "
                f"policy_context={','.join(assumptions) or 'unknown'}."
            )
            _persist_lesson(
                pattern_lesson,
                target.url,
                client_id=client_id,
                engagement_id=engagement_id,
            )
            logger.info(
                "FEAT-1: persisted confirmed-finding pattern: %s",
                pattern_lesson,
            )
        except Exception as exc:
            logger.debug("FEAT-1: confirmed-finding harvest failed: %s", exc)

    # Persist each LLM-extracted lesson to both stores.
    for lesson in extracted_lessons:
        _persist_lesson(
            lesson,
            target.url,
            client_id=client_id,
            engagement_id=engagement_id,
        )

    if extracted_lessons:
        summary = (
            f"Reflection completed. Extracted and persisted "
            f"{len(extracted_lessons)} lesson(s) to SQLite and Chroma."
        )
    else:
        summary = (
            "Reflection completed. No lessons extracted (either no "
            "findings or LLM returned empty list)."
        )
    logger.info(summary)

    return {
        "lessons": extracted_lessons,
        "messages": [AIMessage(content=summary)],
        "current_phase": "reflection",
    }
