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

__all__ = ["build_application_model", "merge_appmodel_into_attack_graph"]

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
                ensure_endpoint(url, "surface")

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
    if not identity_ids:
        model.coverage_gaps.append("appmodel_no_identities_derived")
    if observation_count == 0:
        model.coverage_gaps.append("appmodel_no_observations_derived")
    return model


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
