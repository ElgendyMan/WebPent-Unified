# src/webpent/graph/lesson_nodes.py
"""Closed-loop learning nodes for the main engagement graph.

Ultimate plan 2026-10-27, proposal 3 (Closed-Loop Learning):

The memory infrastructure (``memory/lessons.py`` LessonsManager,
``memory/lesson_consultant.py`` consult_lessons,
``memory/lesson_extractor.py`` extract_campaign_lessons,
``memory/postmortem.py``) was mature but DISCONNECTED from the main
graph — only ``production/chain_composer.py`` consulted it, so ``scan``
and ``hunt`` runs started every campaign from zero, cognitively
speaking.

This module wires the loop into the graph at the two points the plan
specifies:

* ``lesson_consultation_node`` — directly after the planner (before
  auth): consults accumulated lessons for this target type and writes
  an ADVISORY context (``consulted_lessons`` +
  ``lesson_priority_adjustments``) that the hypothesis and
  payload-generator nodes read as prioritization hints.
* ``lesson_extraction_node`` — after reflection (the last node before
  END): extracts structural lessons from the campaign result and
  stores them via LessonsManager; every false-positive the
  devil's-advocate logged becomes a negative lesson automatically
  (the postmortem link).

Hard contracts (unchanged from the memory layer, restated here because
the graph is the widest attack surface for them):

* Lesson content is DATA, never instructions — the consultation output
  is numeric modifiers (route/family boost factors in [-0.5, 0.5]) and
  bounded redacted summaries. No lesson text is ever interpolated into
  a prompt as an instruction.
* Both nodes are fail-open for the CAMPAIGN and fail-closed for the
  MEMORY: any storage/consultation problem logs a warning and returns
  an empty dict — the campaign proceeds exactly as if no lessons
  existed (the pre-plan behavior), and nothing unvalidated is written.
* Cross-client learning is READ-side only through target_type-scoped
  queries with sanitized decision-level content (the extractor's
  documented posture); nothing from client A is ever written into
  client B's scope.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

logger = logging.getLogger(__name__)

__all__ = [
    "lesson_consultation_node",
    "lesson_extraction_node",
    "_lesson_consultation_enabled",
]

#: Hard cap on the consulted-lessons advisory payload kept in state —
#: the summaries are small (decision-level), this is belt-and-braces.
_MAX_CONSULTED_LESSON_SUMMARIES = 25


def _lesson_consultation_enabled() -> bool:
    """Read the feature flag (Ultimate plan, default ON)."""
    try:
        from webpent.config.settings import get_settings

        return bool(get_settings().enable_lesson_consultation)
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        return False


def _surface_map_from_state(state: Mapping[str, Any]) -> Any:
    """Project crawled_data into the shape consult_lessons expects.

    ``consult_lessons`` reads ``surface_map.routes`` (a mapping of
    route → {parameters, external_resource_count, api_signal}). The
    crawler's ``crawled_data`` carries endpoint/parameter knowledge
    under several keys; this projection stays defensive and bounded:
    anything unparseable yields an empty map (consultation then runs
    with zero route hits — still useful for family-level lessons).
    """

    class _Param:
        def __init__(self, name: str) -> None:
            self.name = name
            shape = name.lower()
            if shape.endswith(("id", "_id", "id[]")) or shape in {"uid", "uuid"}:
                self.value_shape = "id-shaped"
            elif "url" in shape or "redirect" in shape or "next" in shape:
                self.value_shape = "url-shaped"
            elif "q" == shape or "query" in shape or "search" in shape or "name" in shape:
                self.value_shape = "query-shaped"
            else:
                self.value_shape = "text-shaped"

    class _Route:
        def __init__(self, route: str, params: list[str]) -> None:
            self.route = route
            self.parameters = [_Param(p) for p in params[:16]]
            self.external_resource_count = 0
            self.api_signal = "/api/" in route or route.startswith("api/")

    class _SurfaceMap:
        def __init__(self, routes: dict[str, _Route]) -> None:
            self.routes = routes

    crawled = state.get("crawled_data") or {}
    if not isinstance(crawled, Mapping):
        return _SurfaceMap({})
    routes: dict[str, _Route] = {}
    # Primary source: curated_endpoints (list of endpoint dicts or
    # strings). Bounded to the first 200 endpoints — lesson matching
    # needs shape signals, not exhaustiveness.
    endpoints = crawled.get("curated_endpoints") or []
    if isinstance(endpoints, list):
        for ep in endpoints[:200]:
            if isinstance(ep, str):
                routes.setdefault(ep, _Route(ep, []))
            elif isinstance(ep, Mapping):
                path = str(ep.get("path") or ep.get("url") or ep.get("endpoint") or "")
                if not path:
                    continue
                params = ep.get("parameters") or ep.get("params") or []
                if isinstance(params, Mapping):
                    params = list(params.keys())
                routes.setdefault(
                    path, _Route(path, [str(p) for p in params[:16] if p])
                )
    # Secondary: forms contribute parameters on their action paths.
    forms = crawled.get("discovered_forms") or crawled.get("forms") or []
    if isinstance(forms, list):
        for form in forms[:100]:
            if not isinstance(form, Mapping):
                continue
            action = str(form.get("action") or form.get("path") or "")
            if not action:
                continue
            fields = form.get("fields") or form.get("inputs") or []
            if isinstance(fields, Mapping):
                fields = list(fields.keys())
            existing = routes.get(action)
            names = [str(f) for f in fields[:16] if f]
            if existing is None:
                routes[action] = _Route(action, names)
            else:
                merged = {p.name for p in existing.parameters} | set(names)
                routes[action] = _Route(action, sorted(merged)[:16])
    return _SurfaceMap(routes)


def lesson_consultation_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Consult prior lessons after planning; write ADVISORY context only.

    Reads: state["target"], state["crawled_data"], state["client_id"].
    Writes: state["consulted_lessons"], state["lesson_priority_adjustments"].

    Advisory contract: the adjustments are numeric modifiers the
    hypothesis/payload nodes may use for PRIORITIZATION only — never
    gating, never authority, never instructions.
    """
    if not _lesson_consultation_enabled():
        return {}
    target = state.get("target")
    target_url = ""
    for attr in ("url", "base_url", "target_url", "host"):
        value = getattr(target, attr, None)
        if isinstance(value, str) and value:
            target_url = value
            break
    if not target_url:
        return {}
    client_id = state.get("client_id")
    try:
        from webpent.memory.lesson_consultant import consult_lessons

        adjustment, summary = consult_lessons(
            target_url=target_url,
            surface_map=_surface_map_from_state(state),
            client_id=client_id if isinstance(client_id, str) else None,
            engagement_id=state.get("engagement_id"),
        )
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("Lesson consultation unavailable (campaign proceeds without): %s", exc)
        return {}

    modifiers = {
        "route_modifiers": dict(adjustment.route_modifiers or {}),
        "family_modifiers": dict(adjustment.family_modifiers or {}),
        "minimum_family_quota": dict(adjustment.minimum_family_quota or {}),
    }
    bounded_summary = {
        key: summary.get(key)
        for key in ("target_type", "lesson_hits", "knowledge_hits", "applied_lesson_ids")
        if key in (summary or {})
    }
    bounded_summary.setdefault("advisory_only", True)
    return {
        "consulted_lessons": [bounded_summary][:_MAX_CONSULTED_LESSON_SUMMARIES],
        "lesson_priority_adjustments": modifiers,
    }


def lesson_extraction_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Extract and store lessons from THIS campaign at reflection time.

    Reads the final state (hypotheses lifecycle, decision log,
    findings, devil's-advocate refutations) and stores:

    * POSITIVE lessons for promoted findings (route+family signals),
    * NEGATIVE lessons for refuted candidates — this is the automatic
      postmortem link: every false-positive logged during the campaign
      becomes a consultable lesson, not just a historical record.

    Writes: state["extracted_lessons"] (bounded summaries, no payload
    content). Storage goes through LessonsManager (SQLite), fail-open
    for the campaign.
    """
    if not _lesson_consultation_enabled():
        return {}
    client_id = state.get("client_id")
    campaign_id = state.get("engagement_id") or state.get("thread_id") or ""
    if not isinstance(client_id, str) or not str(client_id).strip():
        # Nothing scoped to persist under — extraction is a no-op (the
        # pre-plan behavior for unscoped runs).
        return {}
    result: dict[str, Any] = {
        "hypotheses": [
            h if isinstance(h, dict) else getattr(h, "model_dump", dict)()
            for h in (state.get("hypotheses") or [])[:500]
        ],
        "decisions": (state.get("decision_log") or [])[:500],
        "findings": [
            f if isinstance(f, dict) else getattr(f, "model_dump", dict)()
            for f in (state.get("findings") or [])[:200]
        ],
    }
    target = state.get("target")
    target_url = ""
    for attr in ("url", "base_url", "target_url", "host"):
        value = getattr(target, attr, None)
        if isinstance(value, str) and value:
            target_url = value
            break
    try:
        from webpent.memory.lesson_consultant import detect_target_type
        from webpent.memory.lesson_extractor import extract_campaign_lessons

        target_type = detect_target_type(target_url, _surface_map_from_state(state))
        extracted = extract_campaign_lessons(
            result,
            campaign_id=str(campaign_id or "unified-hunt"),
            client_id=client_id,
            target_type=str(target_type),
        )
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("Lesson extraction unavailable (campaign proceeds without): %s", exc)
        return {}

    lessons = extracted.get("lessons") or []
    stored = 0
    try:
        from webpent.memory.lessons import get_lessons_manager

        manager = get_lessons_manager()
        for lesson in lessons[:100]:
            manager.save_structured_lesson(lesson)
            stored += 1
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("Lesson storage unavailable (lessons kept in state only): %s", exc)

    summary = extracted.get("summary") or {}
    return {
        "extracted_lessons": [
            {
                "campaign_id": str(campaign_id or "unified-hunt"),
                "lesson_count": len(lessons),
                "stored_count": stored,
                "summary": {
                    key: summary.get(key)
                    for key in ("tested", "promoted", "refuted", "families")
                    if key in summary
                },
            }
        ],
    }
