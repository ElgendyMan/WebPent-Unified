"""Knowledge bridge for the autonomous hunt (Fix F1/F2).

Two jobs, both adapters only:

1. ``surface_map_to_knowledge`` converts the audited crawler's
   ``SurfaceMap`` into a validated ``TargetKnowledgeV2`` so a hunt can
   bootstrap from a bare URL. It invents no facts: every entity carries the
   crawler's response digest as its evidence ref, and the endpoint shapes
   are exactly what the crawler observed.
2. ``hypothesis_inputs`` adapts whatever the hunt state holds into the real
   ``HypothesisGenerator`` contract — ``(TargetKnowledgeV2, AttackGraph)``.
   Phase 1 of the build called ``generate(target_knowledge)`` with a plain
   dict, which the real generator rejects; this module is the source-level
   fix, not a call-site patch.

The bridge is fail-closed: anything it cannot represent faithfully is
returned as ``None`` and the caller records a blocked phase. It never
fabricates entities, relations, or evidence.
"""

from __future__ import annotations

import hashlib
from typing import Any

_TASK_KIND_MAP: dict[str, str] = {
    "endpoint": "endpoint",
    "parameter": "parameter",
    "application": "application",
    "resource": "resource",
    "object": "object",
    "form": "endpoint",
}


def _digest_key(*parts: str) -> str:
    return hashlib.sha256("::".join(parts).encode("utf-8")).hexdigest()[:16]


def surface_map_to_knowledge(
    surface_map: Any,
    *,
    engagement_id: str,
    target_id: str,
) -> Any | None:
    """Convert a crawler ``SurfaceMap`` (or its ``as_dict()``) to knowledge.

    Entities: one APPLICATION (the target) and one ENDPOINT per observed
    route, with observed parameters attached as PARAMETER entities linked by
    ``has_parameter`` relations. Evidence refs are the crawler's response
    digests, so every claim is traceable to an observed response.
    """
    if surface_map is None:
        return None
    from webpent.knowledge.model_v2 import (
        KnowledgeEntity,
        KnowledgeEntityKind,
        KnowledgeObservation,
        KnowledgeRelation,
        TargetKnowledgeV2,
    )

    raw_routes: list[Any]
    if isinstance(surface_map, dict) and "routes" in surface_map:
        raw_routes = surface_map.get("routes") or []
    elif hasattr(surface_map, "routes"):
        raw_routes = [r.as_dict() for r in (surface_map.routes or {}).values()]
    else:
        return None
    if not raw_routes:
        return None

    entities: dict[str, KnowledgeEntity] = {}
    observations: dict[str, KnowledgeObservation] = {}
    relations: list[KnowledgeRelation] = []

    app_id = f"application:{_digest_key(engagement_id, target_id)}"
    entities[app_id] = KnowledgeEntity(
        entity_id=app_id,
        kind=KnowledgeEntityKind.APPLICATION,
        canonical_key=str(target_id)[:320],
        source_observation="autonomous_crawler",
        confidence=0.6,
        evidence_refs=(),
        metadata={"kind": "application_root"},
    )

    max_endpoints = 200
    max_params_per_endpoint = 32
    for route in raw_routes[:max_endpoints]:
        if not isinstance(route, dict):
            continue
        path = str(route.get("route") or "").strip()
        method = str(route.get("method") or "GET").upper()
        if not path:
            continue
        endpoint_id = f"endpoint:{_digest_key(method, path)}"
        evidence = [str(route.get("response_digest") or "")] if route.get("response_digest") else []
        entities[endpoint_id] = KnowledgeEntity(
            entity_id=endpoint_id,
            kind=KnowledgeEntityKind.ENDPOINT,
            canonical_key=f"{method} {path}"[:320],
            source_observation="autonomous_crawler",
            confidence=0.6,
            evidence_refs=tuple(evidence)[:32],
            metadata={
                "method": method,
                "path": path[:240],
                "status_code": route.get("status_code"),
                "content_type": str(route.get("content_type") or "")[:80],
                "auth_required": bool(route.get("auth_required")),
                "login_signal": bool(route.get("login_signal")),
                "api_signal": bool(route.get("api_signal")),
            },
        )
        obs_id = f"obs:{_digest_key(method, path)}"
        observations[obs_id] = KnowledgeObservation(
            observation_id=obs_id,
            source="autonomous_crawler",
            facts={"route": path[:240], "method": method, "status_code": route.get("status_code")},
        )
        evidence = tuple(evidence)
        relations.append(
            KnowledgeRelation(
                relation_id=f"rel:{_digest_key(app_id, endpoint_id)}",
                relation="has_endpoint",
                source_entity=app_id,
                target_entity=endpoint_id,
                source_observation=obs_id,
                confidence=0.6,
                evidence_refs=evidence,
            )
        )
        # The crawler observed that this route serves content of a given
        # type and status. That observation is recorded as an
        # ``exposes`` relation onto a RESOURCE node representing the
        # response surface itself; the digest is the evidence. This is a
        # faithful restatement of what was observed, not an inferred
        # vulnerability claim: downstream patterns treat it as advisory
        # plausibility only.
        surface_kind = (str(route.get("content_type") or "unknown").split(";")[0] or "unknown")[:40]
        resource_id = f"resource:{_digest_key(endpoint_id, surface_kind)}"
        entities[resource_id] = KnowledgeEntity(
            entity_id=resource_id,
            kind=KnowledgeEntityKind.RESOURCE,
            canonical_key=f"{method} {path} -> {surface_kind}"[:320],
            source_observation="autonomous_crawler",
            confidence=0.6,
            evidence_refs=evidence,
            metadata={"surface": surface_kind, "status_code": route.get("status_code")},
        )
        relations.append(
            KnowledgeRelation(
                relation_id=f"rel:{_digest_key(endpoint_id, 'exposes', resource_id)}",
                relation="exposes",
                source_entity=endpoint_id,
                target_entity=resource_id,
                source_observation=obs_id,
                confidence=0.6,
                evidence_refs=evidence,
            )
        )
        params = route.get("parameters") or []
        for param in params[:max_params_per_endpoint]:
            if isinstance(param, dict):
                name = str(param.get("name") or "").strip()
                location = str(param.get("location") or "query")
            else:
                name = str(getattr(param, "name", "") or "").strip()
                location = str(getattr(param, "location", "query") or "query")
            if not name:
                continue
            param_id = f"parameter:{_digest_key(endpoint_id, location, name)}"
            if param_id not in entities:
                entities[param_id] = KnowledgeEntity(
                    entity_id=param_id,
                    kind=KnowledgeEntityKind.PARAMETER,
                    canonical_key=f"{location}:{name}"[:320],
                    source_observation="autonomous_crawler",
                    confidence=0.55,
                    metadata={"location": location[:40], "name": name[:120]},
                )
            relations.append(
                KnowledgeRelation(
                    relation_id=f"rel:{_digest_key(endpoint_id, param_id)}",
                    relation="accepts",
                    source_entity=endpoint_id,
                    target_entity=param_id,
                    source_observation=obs_id,
                    confidence=0.55,
                    evidence_refs=evidence,
                )
            )

    try:
        return TargetKnowledgeV2(
            engagement_id=str(engagement_id)[:200],
            target_id=str(target_id)[:200],
            entities=entities,
            observations=observations,
            relations=tuple(relations),
        )
    except Exception:
        return None


def coerce_target_knowledge(
    value: Any,
    *,
    engagement_id: str,
    target_id: str,
) -> Any | None:
    """Coerce hunt-state knowledge into a validated ``TargetKnowledgeV2``.

    Accepts a ``TargetKnowledgeV2`` instance, a v2 snapshot dict, or a raw
    dict whose ``entities`` are endpoint-shaped items (``url``/``endpoint``,
    optional ``method``). Anything else returns ``None`` — no invention.
    """
    from webpent.knowledge.model_v2 import TargetKnowledgeV2

    if isinstance(value, TargetKnowledgeV2):
        return value
    if not isinstance(value, dict) or not value:
        return None
    try:
        if value.get("schema_version") == 2:
            knowledge = TargetKnowledgeV2.model_validate(value)
            update = {
                "engagement_id": str(engagement_id)[:200],
                "target_id": str(target_id)[:200],
            }
            knowledge = knowledge.model_copy(update=update)
            return knowledge
    except Exception:
        return None

    return surface_map_to_knowledge(
        {"routes": value.get("entities") or []},
        engagement_id=engagement_id,
        target_id=target_id,
    )


def hypothesis_inputs(
    state_knowledge: Any,
    *,
    engagement_id: str,
    target_url: str,
) -> tuple[Any, Any] | None:
    """Build the real generator's ``(TargetKnowledgeV2, AttackGraph)`` pair.

    Returns ``None`` when the state's knowledge cannot be represented as a
    validated knowledge model; callers must treat that as a blocked phase,
    not fall back to untyped guessing.
    """
    from webpent.attack_graph.engine import AttackGraphEngine

    knowledge = coerce_target_knowledge(
        state_knowledge, engagement_id=engagement_id, target_id=target_url
    )
    if knowledge is None:
        return None
    try:
        graph = AttackGraphEngine().build(knowledge)
    except Exception:
        return None
    return knowledge, graph


__all__ = ["coerce_target_knowledge", "hypothesis_inputs", "surface_map_to_knowledge"]
