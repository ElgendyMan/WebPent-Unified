"""webpent.appmodel.builder — M3 UM-DR-17: derive the application model
from the REAL PentestState channels.

Part 4 §5's appmodel is only honest if its entities carry real
provenance. This builder derives the Organization→…→Observation spine
from channels the production graph already populates:

* ``engagement_id`` / declared context → Organization + Tenant
  (``declared`` provenance);
* ``crawled_data`` (openapi_routes, surface_records, endpoints,
  shadow_endpoints) → Applications + Endpoints (``observed``);
* ``identity_profiles`` → Identities (``declared``/``observed`` by
  validation state);
* ``mental_model`` nodes / ``novel_behavior_observations`` →
  Observations (``observed``), attached to the endpoints they were
  made on when the URL matches.

Every derivation is fail-soft and bounded; a channel that is absent
simply contributes nothing (and the model records a coverage gap, so
"no tenants derived" is visible, not silent).
"""

from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import urlsplit

from webpent.appmodel.models import (
    AppModelEntity,
    AppModelEntityKind,
    AppModelRelation,
    AppModelRelationKind,
    ApplicationModel,
    DiscoveryProvenance,
    provenance_confidence,
)

__all__ = ["build_application_model", "build_appmodel_research_hints", "merge_appmodel_into_attack_graph"]

_MAX_ENTITIES = 2_000
_HOST_RE = re.compile(r"^[a-z0-9.-]+$", re.IGNORECASE)


def _slug(value: str, fallback: str) -> str:
    cleaned = re.sub(r"[^a-z0-9-]+", "-", str(value or "").strip().lower()).strip("-")
    return cleaned[:60] or fallback


def _host_of(url: str) -> str | None:
    try:
        host = (urlsplit(str(url)).hostname or "").lower()
    except ValueError:
        return None
    return host if host and _HOST_RE.match(host) else None


def _path_of(url: str) -> str:
    try:
        return urlsplit(str(url)).path or "/"
    except ValueError:
        return "/"


def _entity_id(prefix: str, key: str) -> str:
    return f"appmodel-{prefix}:{_slug(key, prefix)[:60]}"


def _add_ownership_relation(
    model: ApplicationModel,
    owner_key: str,
    endpoint_id: str,
    url: str,
) -> None:
    """Materialize an identity→endpoint OWNS relation from REAL evidence.

    The owner identity is created (``observed``) only if not already
    materialized; the relation carries the evidence ref of the crawled
    record it was derived from. No ownership relation is ever invented
    from hypothesis text (UM-DR-36 §2.5).
    """
    ident_id = _entity_id("identity", owner_key)
    if ident_id not in model.entities:
        model.add_entity(
            AppModelEntity(
                id=ident_id,
                kind=AppModelEntityKind.IDENTITY,
                label=f"identity:{_slug(owner_key, 'identity')}",
                provenance=DiscoveryProvenance.OBSERVED,
                confidence=provenance_confidence(DiscoveryProvenance.OBSERVED),
                evidence_refs=[f"ownership-evidence:{_slug(owner_key, 'owner')}"],
                metadata={"role": owner_key, "validated": True},
            )
        )
    model.add_relation(
        AppModelRelation(
            id=f"{ident_id}->owns->{endpoint_id}",
            kind=AppModelRelationKind.OWNS,
            source_id=ident_id,
            target_id=endpoint_id,
            provenance=DiscoveryProvenance.OBSERVED,
            confidence=provenance_confidence(DiscoveryProvenance.OBSERVED),
            evidence_refs=[f"surface-record:{_host_of(url)}{_path_of(url)}"],
        )
    )


def build_application_model(state: Mapping[str, Any] | Any) -> ApplicationModel:
    """Derive the typed application model from real state channels."""

    def get(key: str) -> Any:
        if isinstance(state, Mapping):
            return state.get(key)
        return getattr(state, key, None)

    engagement_id = str(get("engagement_id") or "").strip()
    model = ApplicationModel(engagement_id=engagement_id[:200])

    # -- Organization + Tenant (declared by the engagement context) ------
    org_id = _entity_id("org", engagement_id or "engagement")
    model.add_entity(
        AppModelEntity(
            id=org_id,
            kind=AppModelEntityKind.ORGANIZATION,
            label=f"organization:{_slug(engagement_id, 'engagement')}",
            provenance=DiscoveryProvenance.DECLARED,
            confidence=provenance_confidence(DiscoveryProvenance.DECLARED),
            evidence_refs=[f"engagement:{engagement_id}"] if engagement_id else [],
        )
    )
    tenant_id = _entity_id("tenant", engagement_id or "default")
    model.add_entity(
        AppModelEntity(
            id=tenant_id,
            kind=AppModelEntityKind.TENANT,
            label=f"tenant:{_slug(engagement_id, 'default')}",
            provenance=DiscoveryProvenance.DECLARED,
            confidence=provenance_confidence(DiscoveryProvenance.DECLARED),
            evidence_refs=[f"engagement:{engagement_id}"] if engagement_id else [],
        )
    )
    model.add_relation(
        AppModelRelation(
            id=f"{org_id}->contains->{tenant_id}",
            kind=AppModelRelationKind.CONTAINS,
            source_id=org_id,
            target_id=tenant_id,
            provenance=DiscoveryProvenance.DECLARED,
            confidence=provenance_confidence(DiscoveryProvenance.DECLARED),
        )
    )

    # -- Applications + Endpoints (observed on the crawled surface) ------
    crawled = get("crawled_data") or {}
    if not isinstance(crawled, Mapping):
        crawled = {}
    target_url = str(get("target_url") or getattr(get("target"), "url", "") or "")
    application_host = _host_of(target_url)

    application_ids: dict[str, str] = {}
    endpoint_ids: set[str] = set()

    def ensure_application(host: str) -> str | None:
        if not host or len(application_ids) >= 32:
            return None
        app_id = _entity_id("app", host)
        if app_id not in application_ids:
            application_ids[app_id] = app_id
            model.add_entity(
                AppModelEntity(
                    id=app_id,
                    kind=AppModelEntityKind.APPLICATION,
                    label=f"application:{host}"[:160],
                    provenance=DiscoveryProvenance.OBSERVED,
                    confidence=provenance_confidence(DiscoveryProvenance.OBSERVED),
                    evidence_refs=[f"observed-host:{host}"],
                    metadata={"host": host},
                )
            )
            model.add_relation(
                AppModelRelation(
                    id=f"{tenant_id}->contains->{app_id}",
                    kind=AppModelRelationKind.CONTAINS,
                    source_id=tenant_id,
                    target_id=app_id,
                    provenance=DiscoveryProvenance.INFERRED,
                    confidence=provenance_confidence(DiscoveryProvenance.INFERRED),
                    evidence_refs=[f"observed-host:{host}"],
                )
            )
        return app_id

    def ensure_endpoint(url: str, source: str) -> str | None:
        host = _host_of(url)
        if not host or len(endpoint_ids) >= _MAX_ENTITIES:
            return None
        app_id = ensure_application(host)
        if app_id is None:
            return None
        path = _path_of(url)
        endpoint_id = _entity_id("endpoint", f"{host}{path}")
        if endpoint_id in endpoint_ids:
            return endpoint_id
        endpoint_ids.add(endpoint_id)
        model.add_entity(
            AppModelEntity(
                id=endpoint_id,
                kind=AppModelEntityKind.ENDPOINT,
                label=f"endpoint:{host}{path}"[:160],
                provenance=DiscoveryProvenance.OBSERVED,
                confidence=provenance_confidence(DiscoveryProvenance.OBSERVED),
                evidence_refs=[f"{source}:{host}{path}"],
                metadata={"host": host, "path": path},
            )
        )
        model.add_relation(
            AppModelRelation(
                id=f"{app_id}->hosts->{endpoint_id}",
                kind=AppModelRelationKind.HOSTS,
                source_id=app_id,
                target_id=endpoint_id,
                provenance=DiscoveryProvenance.OBSERVED,
                confidence=provenance_confidence(DiscoveryProvenance.OBSERVED),
                evidence_refs=[f"{source}:{host}{path}"],
            )
        )
        return endpoint_id

    for route in crawled.get("openapi_routes") or []:
        if isinstance(route, Mapping):
            path = str(route.get("path") or "")
            if path and target_url:
                ensure_endpoint(f"{target_url.rstrip('/')}{path}", "openapi")

    for record in crawled.get("surface_records") or []:
        if isinstance(record, Mapping):
            url = str(record.get("url") or "")
            if url:
                endpoint_id = ensure_endpoint(url, "surface")
                # UM-DR-36: materialize REAL object-ownership evidence. A
                # crawled endpoint record carrying ``owner_identity`` is
                # recorded evidence that this resource belongs to that
                # principal — the ownership relation (identity→endpoint)
                # exists only when the evidence says so.
                owner = str(record.get("owner_identity") or "").strip()
                if endpoint_id and owner:
                    _add_ownership_relation(model, owner, endpoint_id, url)

    for shadow in crawled.get("shadow_endpoints") or []:
        if isinstance(shadow, Mapping):
            path = shadow.get("path") or shadow.get("route") or shadow.get("url")
            if path and target_url:
                ensure_endpoint(f"{target_url.rstrip('/')}{str(path)}", "shadow")
        elif isinstance(shadow, str) and shadow.strip():
            ensure_endpoint(shadow, "shadow")

    for url in crawled.get("endpoints") or []:
        if isinstance(url, str) and url.strip():
            ensure_endpoint(url, "crawl")

    # UM-DR-36: ownership evidence on plain crawled endpoint records too.
    for record in crawled.get("endpoints") or []:
        if isinstance(record, Mapping):
            url = str(record.get("url") or "")
            owner = str(record.get("owner_identity") or "").strip()
            if url and owner:
                endpoint_id = ensure_endpoint(url, "crawl-owned")
                if endpoint_id:
                    _add_ownership_relation(model, owner, endpoint_id, url)

    # -- Identities (from the engagement's identity profiles) ------------
    profiles = get("identity_profiles") or {}
    identity_ids: dict[str, str] = {}
    if isinstance(profiles, Mapping):
        for label, profile in list(profiles.items())[:64]:
            if not isinstance(profile, Mapping):
                continue
            role = str(profile.get("role") or label or "").strip()
            if not role:
                continue
            ident_id = _entity_id("identity", role)
            identity_ids[role] = ident_id
            validated = bool(profile.get("validated"))
            model.add_entity(
                AppModelEntity(
                    id=ident_id,
                    kind=AppModelEntityKind.IDENTITY,
                    label=f"identity:{_slug(role, 'identity')}",
                    provenance=(
                        DiscoveryProvenance.OBSERVED
                        if validated
                        else DiscoveryProvenance.DECLARED
                    ),
                    confidence=(
                        provenance_confidence(DiscoveryProvenance.OBSERVED)
                        if validated
                        else provenance_confidence(DiscoveryProvenance.DECLARED) * 0.5
                    ),
                    evidence_refs=[f"identity-profile:{_slug(label, 'profile')}"],
                    metadata={"role": role, "validated": validated},
                )
            )
            model.add_relation(
                AppModelRelation(
                    id=f"{ident_id}->authenticates_as->{tenant_id}",
                    kind=AppModelRelationKind.AUTHENTICATES_AS,
                    source_id=ident_id,
                    target_id=tenant_id,
                    provenance=DiscoveryProvenance.INFERRED,
                    confidence=provenance_confidence(DiscoveryProvenance.INFERRED),
                )
            )

    # -- Observations (mental-model nodes / novel behaviors) -------------
    observation_count = 0
    mental_model = get("mental_model")
    mental_nodes = getattr(mental_model, "nodes", None) or {}
    if isinstance(mental_nodes, Mapping):
        for node_id, node in list(mental_nodes.items())[:200]:
            metadata = getattr(node, "metadata", None) or {}
            if not isinstance(metadata, Mapping):
                metadata = {}
            url = str(metadata.get("url") or "")
            obs_id = _entity_id("observation", str(node_id))
            model.add_entity(
                AppModelEntity(
                    id=obs_id,
                    kind=AppModelEntityKind.OBSERVATION,
                    label=f"observation:{_slug(str(node_id), 'obs')}"[:160],
                    provenance=DiscoveryProvenance.OBSERVED,
                    confidence=provenance_confidence(DiscoveryProvenance.OBSERVED),
                    evidence_refs=[f"mental-model:{str(node_id)[:200]}"],
                )
            )
            observation_count += 1
            if url:
                endpoint_id = _entity_id("endpoint", f"{_host_of(url)}{_path_of(url)}")
                if endpoint_id in endpoint_ids:
                    model.add_relation(
                        AppModelRelation(
                            id=f"{obs_id}->observed_on->{endpoint_id}",
                            kind=AppModelRelationKind.OBSERVED_ON,
                            source_id=obs_id,
                            target_id=endpoint_id,
                            provenance=DiscoveryProvenance.OBSERVED,
                            confidence=provenance_confidence(DiscoveryProvenance.OBSERVED),
                            evidence_refs=[f"mental-model:{str(node_id)[:200]}"],
                        )
                    )

    if not endpoint_ids:
        # Honest accounting: no endpoints derived is a COVERAGE fact.
        model.coverage_gaps.append("appmodel_no_endpoints_derived")
    if not identity_ids and not any(
        str(rel.kind) == "owns" for rel in model.relations
    ):
        model.coverage_gaps.append("appmodel_no_identities_derived")
    if observation_count == 0:
        model.coverage_gaps.append("appmodel_no_observations_derived")
    if not any(str(rel.kind) == "owns" for rel in model.relations):
        # Honest accounting: ownership evidence absent (not manufactured).
        model.coverage_gaps.append("appmodel_no_ownership_relations_derived")
    return model


# ---------------------------------------------------------------------------
# UM-DR-36: research hints derived from the built model — the bridge that
# makes the semantic model INFLUENCE actual research decisions.
# ---------------------------------------------------------------------------

_MAX_HINTS = 128


def build_appmodel_research_hints(model: ApplicationModel) -> dict[str, dict[str, Any]]:
    """Derive advisory research hints from REAL model facts.

    Every hint names the entity/relation it came from, its evidence refs,
    and a deterministic priority. The hints exist to make the semantic
    model influence hypothesis generation and experiment selection — they
    carry NO authority: they cannot authorize, expand scope, confirm, or
    bypass CausalGuard (consumers treat them as advisory priority only).
    """
    hints: dict[str, dict[str, Any]] = {}

    def add_hint(hint_id: str, kind: str, priority: float, reason: str,
                 evidence_refs: list[str], subject: dict[str, Any]) -> None:
        if len(hints) >= _MAX_HINTS:
            return
        hints[hint_id[:200]] = {
            "kind": kind,
            "priority": round(float(min(max(priority, 0.0), 1.0)), 4),
            "reason": str(reason)[:300],
            "evidence_refs": [str(r)[:240] for r in evidence_refs[:8]],
            "subject": subject,
            "advisory_only": True,
            "source": "appmodel",
        }

    # 1. Identity-bound endpoints: an endpoint an identity owns or
    #    authenticates to is a prime authorization-boundary research target.
    endpoint_path: dict[str, str] = {}
    for entity in model.entities.values():
        if str(entity.kind) == "endpoint":
            path = str(entity.metadata.get("path") or "")
            if path:
                endpoint_path[entity.id] = path

    ownership: dict[str, list[str]] = {}
    for relation in model.relations:
        if str(relation.kind) == "owns" and relation.target_id in endpoint_path:
            ownership.setdefault(relation.target_id, []).append(relation.source_id)
    for endpoint_id, owners in ownership.items():
        path = endpoint_path[endpoint_id]
        add_hint(
            f"appmodel-hint:ownership-boundary:{endpoint_id}",
            "object_ownership_boundary",
            0.9,
            (
                "an object/resource endpoint is owned by a specific identity "
                f"({len(owners)} owner relation(s)) — an authorization boundary "
                "deserves a foreign-principal access experiment"
            ),
            model.entities[endpoint_id].ref_list(),
            {"endpoint_id": endpoint_id, "path": path, "owner_identity_ids": owners},
        )

    # 2. Identities authenticating into the tenant/application: identity
    #    relationships matter for privilege/role differentials.
    for relation in model.relations:
        if str(relation.kind) == "authenticates_as":
            identity = model.entities.get(relation.source_id)
            if identity is None:
                continue
            add_hint(
                f"appmodel-hint:identity:{relation.source_id}",
                "identity_relationship",
                0.7,
                (
                    "an identity authenticates into the application — "
                    "principal/role differential experiments are relevant"
                ),
                identity.ref_list() + relation.ref_list(),
                {"identity_id": relation.source_id, "role": identity.metadata.get("role")},
            )

    # 3. Observations on endpoints: observed behavior suggests the
    #    endpoint's runtime semantics are worth probing.
    for relation in model.relations:
        if str(relation.kind) == "observed_on":
            obs = model.entities.get(relation.source_id)
            endpoint = model.entities.get(relation.target_id)
            if obs is None or endpoint is None:
                continue
            add_hint(
                f"appmodel-hint:observed:{relation.source_id}",
                "observed_behavior",
                0.5,
                "runtime behavior was observed on this endpoint",
                obs.ref_list() + endpoint.ref_list(),
                {"observation_id": relation.source_id, "endpoint_id": relation.target_id},
            )

    # 4. Coverage gaps: missing semantic coverage is itself a research
    #    priority (probe what the model could not see).
    for gap in model.coverage_gaps[:16]:
        add_hint(
            f"appmodel-hint:gap:{gap}",
            "coverage_gap",
            0.3,
            f"semantic coverage gap recorded: {gap}",
            [f"coverage-gap:{gap}"],
            {"gap": gap},
        )
    return hints


def merge_appmodel_into_attack_graph(
    graph: dict[str, Any],
    appmodel: ApplicationModel,
) -> dict[str, Any]:
    """Merge the appmodel's attack-graph projection into a built graph.

    Additive: existing nodes/edges are never replaced; appmodel nodes
    use their own id space (``appmodel-*``) so collisions are structural.
    """
    projection = appmodel.to_attack_graph_projection()
    nodes = dict(graph.get("nodes") or {})
    for node_id, node in projection["nodes"].items():
        nodes.setdefault(node_id, node)
    existing_edge_ids = {
        edge.get("id") for edge in (graph.get("edges") or []) if isinstance(edge, Mapping)
    }
    edges = list(graph.get("edges") or [])
    for edge in projection["edges"]:
        if edge["id"] not in existing_edge_ids:
            edges.append(edge)
    graph["nodes"] = nodes
    graph["edges"] = edges
    generated = list(graph.get("generated_from") or [])
    if "appmodel" not in generated:
        generated.append("appmodel")
    graph["generated_from"] = generated
    return graph
