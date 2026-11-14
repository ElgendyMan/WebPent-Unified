"""Advisory consultation of structured lessons and RAG knowledge.

Consultation changes ranking metadata only. It never removes a hypothesis or
makes an execution, validation, proof, or promotion decision.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from webpent.memory.lesson_models import (
    PriorityAdjustmentMap,
    normalize_family,
    normalize_route_pattern,
)
from webpent.memory.lessons import get_lessons_manager
from webpent.memory.vectorstore import get_vector_store_manager


def detect_target_type(target_url: str, surface_map: Any | None = None) -> str:
    host = (urlsplit(str(target_url)).hostname or "").lower()
    if surface_map is not None:
        routes = getattr(surface_map, "routes", {}) or {}
        route_text = " ".join(str(key) for key in routes.keys()).lower()
        if any(token in route_text for token in ("/graphql", "/rest/", "/api/")):
            return "rest_api"
        if any(token in route_text for token in ("/login", "/search", "/register")):
            return "form_based"
    if "juice" in host or "shop" in host:
        return "e_commerce"
    return "generic_web"


def _matches(pattern: str, route: str) -> bool:
    pattern = normalize_route_pattern(pattern)
    route = normalize_route_pattern(route)
    if pattern in {"/*", "/"}:
        return pattern == "/" and route == "/" or pattern == "/*"
    if pattern.endswith("*"):
        return route.startswith(pattern[:-1])
    return route == pattern


class LessonConsultant:
    """Build a bounded adjustment map from one client-scoped memory view."""

    def __init__(self, *, lessons_manager: Any | None = None, vector_manager: Any | None = None) -> None:
        self.lessons_manager = lessons_manager or get_lessons_manager()
        self.vector_manager = vector_manager or get_vector_store_manager()

    def consult(
        self, *, target_url: str, surface_map: Any, client_id: str | None,
        engagement_id: str | None = None,
    ) -> tuple[PriorityAdjustmentMap, dict[str, Any]]:
        target_type = detect_target_type(target_url, surface_map)
        if not str(client_id or "").strip():
            empty = PriorityAdjustmentMap(target_type=target_type)
            return empty, {"target_type": target_type, "applied_lesson_ids": [], "lesson_hits": 0, "knowledge_hits": 0, "disabled_reason": "missing_client_scope"}

        rows = self.lessons_manager.get_structured_lessons(client_id=client_id, target_type=target_type, limit=500)
        route_modifiers: dict[str, float] = defaultdict(float)
        family_modifiers: dict[str, float] = defaultdict(float)
        minimum_quota: dict[str, int] = defaultdict(int)
        applied: list[str] = []
        route_hits = family_hits = 0

        routes = getattr(surface_map, "routes", {}) or {}
        route_values = list(routes.values()) if hasattr(routes, "values") else []
        route_names = [getattr(item, "route", str(item)) for item in route_values]
        families = set()
        for item in route_values:
            for parameter in getattr(item, "parameters", ()) or ():
                shape = str(getattr(parameter, "value_shape", ""))
                families.add({"id-shaped": "IDOR", "url-shaped": "OPEN_REDIRECT", "query-shaped": "SQLI", "text-shaped": "XSS"}.get(shape, "INFO_DISCLOSURE"))
            if getattr(item, "external_resource_count", 0):
                families.add("SSRF")
            if getattr(item, "api_signal", False):
                families.add("INFO_DISCLOSURE")
        for row in rows:
            lesson_id = str(row.get("lesson_id") or row.get("id") or "")
            lesson_type = str(row.get("lesson_type") or "")
            family = normalize_family(row.get("family"))
            pattern = normalize_route_pattern(row.get("route_pattern") or "/*")
            matched_routes = [route for route in route_names if _matches(pattern, route)]
            family_match = not family or family in families
            if not matched_routes and not (pattern == "/*" and family_match):
                continue
            if not family_match:
                continue
            if lesson_id:
                applied.append(lesson_id)
            if matched_routes:
                route_hits += len(matched_routes)
            if family:
                family_hits += 1
            if lesson_type in {"positive", "negative"}:
                modifier = float(row.get("boost_factor") or (0.3 if lesson_type == "positive" else -0.2))
                route_modifiers[pattern] = max(-0.5, min(0.5, route_modifiers[pattern] + modifier))
            elif lesson_type == "priority" and family:
                family_modifiers[family] = max(-0.5, min(0.5, family_modifiers[family] + float(row.get("boost_factor") or 0.3)))
            elif lesson_type == "coverage_gap" and family:
                minimum_quota[family] = max(minimum_quota[family], 1)

        knowledge_hits = 0
        knowledge_refs: list[str] = []
        query = " ".join(sorted(set(route_names[:20]))) or target_type
        try:
            knowledge = self.vector_manager.search_knowledge(query, k=5, doc_type="writeup")
            knowledge_hits = len(knowledge)
            knowledge_refs = [f"knowledge:{index}" for index, _ in enumerate(knowledge)]
        except Exception:
            # Advisory retrieval is best effort; no campaign authority depends
            # on Chroma availability.
            knowledge_hits = 0

        adjustment = PriorityAdjustmentMap(
            target_type=target_type,
            route_modifiers=dict(route_modifiers),
            family_modifiers=dict(family_modifiers),
            minimum_family_quota=dict(minimum_quota),
            applied_lesson_ids=tuple(dict.fromkeys(applied))[:200],
            route_hits=route_hits,
            family_hits=family_hits,
            knowledge_hits=knowledge_hits,
        )
        return adjustment, {
            "target_type": target_type,
            "applied_lesson_ids": list(adjustment.applied_lesson_ids),
            "route_hits": route_hits,
            "family_hits": family_hits,
            "knowledge_hits": knowledge_hits,
            "knowledge_refs": knowledge_refs,
            "minimum_family_quota": dict(minimum_quota),
            "client_id": str(client_id)[:128],
            "engagement_id": str(engagement_id or "")[:160] or None,
        }


def consult_lessons(*, target_url: str, surface_map: Any, client_id: str | None, engagement_id: str | None = None, consultant: LessonConsultant | None = None) -> tuple[PriorityAdjustmentMap, dict[str, Any]]:
    return (consultant or LessonConsultant()).consult(
        target_url=target_url, surface_map=surface_map, client_id=client_id, engagement_id=engagement_id,
    )


__all__ = ["LessonConsultant", "consult_lessons", "detect_target_type"]
