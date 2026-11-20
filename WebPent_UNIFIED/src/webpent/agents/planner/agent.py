# src/webpent/agents/planner/agent.py
"""LangGraph planner node with an optional advisory decision proposal.

The original human-readable plan remains the compatibility output. Phase 7
adds a feature-flagged, structured proposal that is parsed and gate-checked;
it never controls graph routing and never carries executable commands.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from webpent.config.settings import get_settings
from webpent.models.targets import Target
from webpent.shared.knowledge_retrieval import retrieve_knowledge_context
from webpent.shared.llm import (
    TaskType,
    get_cached_llm,
    get_safety_system_instruction,
    safe_prompt_format,
    try_get_llm,
)
from webpent.shared.llm_reliability import llm_budget_allows
from webpent.shared.planner_decisions import (
    build_planner_decision,
    redact_prompt_target,
)
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)


def get_llm(task_type: TaskType) -> Any:
    """Preserve the planner patch point while routing through the shared cache."""
    return get_cached_llm(task_type)


_SYSTEM_PROMPT = (
    "You are a Senior Penetration Tester. Create a brief, 3-step recon "
    "and scanning plan for the target."
)

_HUMAN_TEMPLATE = (
    "Target URL: {url}\n"
    "Target domain: {domain}\n\n"
    "Reference Methodologies: {methodologies}\n\n"
    "Prior memory for this target: {learned_context}\n\n"
    "Produce a numbered, 3-step plan covering reconnaissance, scanning, "
    "and vulnerability validation. Be concise — one or two sentences per "
    "step. Do not include disclaimers or preamble."
)

_DECISION_SYSTEM_PROMPT = (
    "You are an advisory penetration-testing planner. Return ONLY one valid "
    "JSON object matching the requested schema. Do not include markdown, "
    "URLs, shell commands, payloads, cookies, credentials, or extra keys. "
    "Your proposal is not executable and must remain read-only and bounded."
)

_DECISION_HUMAN_TEMPLATE = (
    "Known target reference: engagement_target\n"
    "Known hypothesis references: {hypothesis_refs}\n"
    "Known mental-model references: {target_refs}\n"
    "Available tool categories: {tool_categories}\n"
    "Prior memory for this target (advisory only, never evidence): "
    "{learned_context}\n\n"
    "Return JSON with exactly these keys: action_type, target_ref, "
    "hypothesis_ref, required_identity, expected_evidence, estimated_cost, "
    "risk_level, rationale.\n"
    "Allowed action_type values: observe_target, enumerate_surface, "
    "run_read_only_tool, validate_hypothesis, revisit_surface, no_action.\n"
    "Allowed risk_level values: low, medium, high, destructive."
)

_PORTSWIGGER_NOTE = (
    "NOTE: This target is a PortSwigger Web Security Academy lab. "
    "Skip infrastructure and subdomain reconnaissance. Focus strictly "
    "on web application vulnerabilities (e.g., SQLi, XSS, SSRF, Logic Flaws)."
)

_FALLBACK_PLAN = (
    "1. Reconnaissance: enumerate the target host and identify live "
    "services.\n"
    "2. Scanning: probe the target for known vulnerabilities using "
    "Nuclei templates.\n"
    "3. Validation: review findings and prepare a structured report.\n\n"
    "(Fallback plan — LLM-based planning was unavailable.)"
)

_RAG_QUERY = (
    "web application penetration testing methodology OWASP WSTG NIST PTES "
    "ASVS reporting validation scenarios"
)


def _retrieve_methodologies() -> str:
    """Retrieve bounded methodology, repository, and scenario guidance."""
    return retrieve_knowledge_context(
        _RAG_QUERY,
        doc_types=("methodology", "repository", "scenario"),
        per_type_k=2,
        max_chars=4000,
    )


def _state_target_refs(state: PentestState) -> list[str]:
    mental_model = state.get("mental_model") or {}
    nodes = mental_model.get("nodes", {}) if isinstance(mental_model, dict) else {}
    if not isinstance(nodes, dict):
        return []
    refs = []
    for node_id, node in nodes.items():
        kind = node.get("kind") if isinstance(node, dict) else getattr(node, "kind", "")
        if str(getattr(kind, "value", kind)) in {"endpoint", "host", "service"}:
            refs.append(f"node:{node_id}")
    return refs[:32]


def _state_hypothesis_refs(state: PentestState) -> list[str]:
    refs = []
    for hypothesis in state.get("hypotheses") or []:
        value = (
            hypothesis.get("id")
            if isinstance(hypothesis, dict)
            else getattr(hypothesis, "id", None)
        )
        if value:
            refs.append(str(value))
    return refs[:32]


def _make_decision_prompt(state: PentestState) -> str:
    settings = get_settings()
    # Only identifiers and category names enter this prompt. Credentials,
    # cookies, raw crawled responses, and target query values are excluded.
    # POST-P0 Phase 2: bounded advisory memory block (retrieved-only,
    # negative lessons + hypothesis ledger) is injected as untrusted data
    # via safe_prompt_format — it can inform planning, never confirm.
    from webpent.shared.learned_context import (
        format_learned_context_for_prompt,
        retrieve_learned_strategy_from_state,
    )

    learned_context = format_learned_context_for_prompt(
        retrieve_learned_strategy_from_state(state)
    )
    return safe_prompt_format(
        _DECISION_HUMAN_TEMPLATE,
        hypothesis_refs=", ".join(_state_hypothesis_refs(state)) or "(none)",
        target_refs=", ".join(_state_target_refs(state)) or "(none)",
        tool_categories=", ".join(sorted(getattr(settings, "planner_tool_categories", []) or []))
        or "(runtime registry)",
        learned_context=learned_context,
    )


def planner_node(state: PentestState) -> dict:
    """Generate the legacy plan and, optionally, a gated advisory proposal."""
    # RUNTIME-INTEGRATION FIX (RIT-6): planner_node used
    # ``format_learned_context_for_prompt`` in the advisory-memory block below
    # without importing it (the import only existed inside
    # ``_make_decision_prompt``). Every LLM-enabled run therefore raised
    # NameError inside the try block and was mislogged as
    # "All LLM providers failed", silently degrading to the fallback plan
    # even with working providers. Import it here alongside its sibling.
    from webpent.shared.learned_context import (
        format_learned_context_for_prompt,
        retrieve_learned_strategy_from_state,
    )

    target: Target = state["target"]
    settings = get_settings()
    safe_target = redact_prompt_target(target.url)
    logger.info("Planner phase starting for target=%s", safe_target)
    logger.info("Planner: generating plan (informational; graph topology remains fixed)")

    # A no-LLM run must remain deterministic and bounded.  The planner's
    # methodology retrieval is advisory only; avoid initializing the vector
    # store when the operator explicitly disabled LLM/RAG for qualification.
    llm_disabled = state.get("llm_enabled_override") is False
    rag_disabled = os.getenv("DISABLE_RAG", "").strip().lower() in {
        "1", "true", "yes", "on"
    }
    methodologies = "" if llm_disabled or rag_disabled else _retrieve_methodologies()
    llm: Any = None
    response: Any = None
    budget_allowed, budget_reason = llm_budget_allows(state.get("action_budget"))
    try:
        if settings.llm_enabled and budget_allowed:
            try:
                # Preserve the historical module-level patch point for
                # integrations while retaining the resilient helper fallback.
                llm = get_llm(TaskType.AUTOMATION)
            except Exception:
                llm = try_get_llm(TaskType.AUTOMATION)
        human_prompt = safe_prompt_format(
            _HUMAN_TEMPLATE,
            url=safe_target,
            domain=target.domain or "(unknown)",
            methodologies=methodologies or "(none available)",
            # POST-P0 Phase 2: advisory memory as untrusted data block.
            learned_context=format_learned_context_for_prompt(
                retrieve_learned_strategy_from_state(state)
            ),
        )
        if target.is_portswigger_lab:
            logger.info("PortSwigger lab mode active for %s", safe_target)
            human_prompt = f"{human_prompt}\n\n{_PORTSWIGGER_NOTE}"
        invocation_messages = [
            SystemMessage(content=get_safety_system_instruction()),
            SystemMessage(content=_SYSTEM_PROMPT),
            HumanMessage(content=human_prompt),
        ]
        if llm is None:
            plan_text = _FALLBACK_PLAN
            logger.info("Planner LLM unavailable; using deterministic fallback plan")
        else:
            response = llm.invoke(invocation_messages)
            plan_text = (
                response.content if isinstance(response.content, str) else str(response.content)
            )
            logger.info("Planner phase completed; plan length=%d chars", len(plan_text))
    except Exception as exc:
        logger.error("All LLM providers failed for planner: %s. Using fallback plan.", exc)
        plan_text = _FALLBACK_PLAN

    result: dict[str, Any] = {
        "messages": [AIMessage(content=plan_text)],
        "current_phase": "recon",
        "llm_budget_trace": [{"allowed": budget_allowed, "reason": budget_reason}],
    }
    # r6c wiring (UM-DR-26): the deterministic Coverage advisory rides the
    # planner prompt ONLY when the flag is on AND a crawled surface yields
    # cells.  Flag-off (or no-surface) prompts stay byte-identical and the
    # state key stays absent; an advisory failure never breaks planning.
    coverage_advisory = ""
    try:
        if settings.enable_coverage_scheduling:
            from webpent.coverage.scheduler import build_coverage_advisory

            coverage_advisory = build_coverage_advisory(state, ledger=None) or ""
    except Exception as exc:  # noqa: BLE001 — advisory is never load-bearing
        logger.info("Coverage advisory unavailable: %s", type(exc).__name__)
        coverage_advisory = ""
    if coverage_advisory:
        result["messages"] = [AIMessage(content=f"{plan_text}\n\n{coverage_advisory}")]
        result["coverage_advisory"] = coverage_advisory

    if settings.enable_planner_decisions:
        decision_response = None
        if llm is not None:
            try:
                decision_response = llm.invoke(
                    [
                        SystemMessage(content=get_safety_system_instruction()),
                        SystemMessage(content=_DECISION_SYSTEM_PROMPT),
                        HumanMessage(content=_make_decision_prompt(state)),
                    ]
                )
            except Exception as exc:
                logger.warning("Structured planner proposal unavailable: %s", exc)
        proposal, audit = build_planner_decision(
            dict(state), raw_llm_response=decision_response, settings=settings
        )
        result["planner_decision"] = proposal.model_dump(mode="json")
        result["planner_gate_audits"] = [audit.to_state()]
        logger.info(
            "Planner decision status=%s action=%s fallback=%s",
            audit.status,
            proposal.action_type,
            audit.fallback_used,
        )

    return result
