"""UM-DR-46 Phase A — the Security Knowledge Graph (SKG) builder.

The mission turns the AppModel from "endpoint drawing" into a living
SECURITY model with the nine entity classes: Users (IDENTITY —
extend-not-rewrite), Roles, Resources, Endpoints, Sessions, Workflows,
Parameters, Trust Boundaries and State-before-after. This module
derives those entities and their relations from REAL state channels —
every entity and relation carries provenance and evidence refs (the
A5a/A5d discipline extended); nothing is invented:

* ``identity_profiles``        → Role entities + ASSUMES_ROLE
* ``session_cookies`` /        → Session entities (KEY ONLY — secret
  ``session_headers`` /          values are NEVER recorded) + BOUND_TO
  ``credentials``
* ``authorization_observations`` → Resources + principals + ACCESSES
  (production RC-2 finding-projection shape: actor/resource/owner)
* ``object_identity_observations`` → Resources + endpoint ACCESSES
* ``workflow_observations``    → Workflows + STATE entities +
                                 TRANSITIONS (state-before-after) +
                                 EXPOSES
* endpoint path variance       → PARAMETER entities + HAS_PARAMETER
* endpoint origins             → TRUST_BOUNDARY entities + CROSSES
* openapi ``security``         → endpoint ``authz_declared`` markers
* ``skg_evidence``             → typed evidence records:
  ``authz_marker`` (PERMITS), ``ownership_change`` (MODIFIES
  attribute=owner), ``resource_access`` (READS/MODIFIES) — the
  evidence-backed extension point Phase B's inference writes into.

Deterministic by construction: same state in ⇒ same graph out (modulo
first-observation timestamps). Bounded everywhere. Advisory only —
this module performs no I/O, grants nothing, confirms nothing.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from webpent.appmodel.builder import (
    _endpoint_id_of,
    _entity_id,
    build_application_model,
)
from webpent.appmodel.models import (
    ApplicationModel,
    AppModelEntity,
    AppModelEntityKind,
    AppModelRelation,
    AppModelRelationKind,
    DiscoveryProvenance,
    provenance_confidence,
)

__all__ = ["build_security_knowledge_graph", "build_skg_research_hints"]

_MAX_ROLES = 32
_MAX_SESSIONS = 64
_MAX_RESOURCES = 256
_MAX_WORKFLOWS = 64
_MAX_STATES = 128
_MAX_TRANSITIONS = 256
_MAX_PARAMETERS = 64
_MAX_BOUNDARIES = 32
_MAX_EVIDENCE_RECORDS = 512
_MAX_PARAMETER_VALUES = 8
_WRITE_OPERATIONS = {"write", "update", "patch", "delete", "remove", "create",
                     "post", "put"}
_V_RE = re.compile(r"^v\d+$", re.IGNORECASE)


def _get(state: Any, key: str) -> Any:
    if isinstance(state, Mapping):
        return state.get(key)
    return getattr(state, key, None)


def _record_refs(record: Mapping[str, Any], *extra: str) -> list[str]:
    refs = [
        str(ref)[:240]
        for ref in (record.get("evidence_refs") or [])
        if str(ref).strip()
    ]
    for ref in extra:
        if str(ref).strip():
            refs.append(str(ref)[:240])
    return list(dict.fromkeys(refs))[:8]


def _ensure_entity(
    model: ApplicationModel,
    entity_id: str,
    *,
    kind: AppModelEntityKind,
    label: str,
    provenance: DiscoveryProvenance,
    evidence_refs: list[str],
    metadata: dict[str, Any] | None = None,
) -> str:
    model.add_entity(
        AppModelEntity(
            id=entity_id,
            kind=kind,
            label=label[:160],
            provenance=provenance,
            confidence=provenance_confidence(provenance),
            evidence_refs=list(evidence_refs)[:50],
            metadata=dict(metadata or {}),
        )
    )
    return entity_id


def _resolve_endpoint(
    model: ApplicationModel,
    endpoint_field: Any,
    path_lookup: dict[str, str],
) -> str | None:
    """Resolve an endpoint reference (URL or path) to an EXISTING
    endpoint entity id — never invents an endpoint."""
    raw = str(endpoint_field or "").strip()
    if not raw:
        return None
    if raw.startswith(("http://", "https://")):
        endpoint_id = _endpoint_id_of(raw)
        return endpoint_id if endpoint_id in model.entities else None
    return path_lookup.get(raw)


def _build_path_lookup(model: ApplicationModel) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for entity_id, entity in model.entities.items():
        if str(entity.kind) == "endpoint":
            path = str(entity.metadata.get("path") or "")
            if path:
                lookup.setdefault(path, entity_id)
    return lookup


def _ensure_role(
    model: ApplicationModel,
    role: str,
    evidence_refs: list[str],
    *,
    declared: bool,
) -> str:
    role_id = _entity_id("role", role)
    _ensure_entity(
        model,
        role_id,
        kind=AppModelEntityKind.ROLE,
        label=f"role:{role}",
        provenance=(
            DiscoveryProvenance.DECLARED
            if declared
            else DiscoveryProvenance.OBSERVED
        ),
        evidence_refs=evidence_refs,
        metadata={"role": role[:120]},
    )
    return role_id


def _ensure_identity(
    model: ApplicationModel,
    principal: str,
    evidence_refs: list[str],
    *,
    provenance: DiscoveryProvenance,
) -> str:
    ident_id = _entity_id("identity", principal)
    _ensure_entity(
        model,
        ident_id,
        kind=AppModelEntityKind.IDENTITY,
        label=f"identity:{principal}"[:160],
        provenance=provenance,
        evidence_refs=evidence_refs,
    )
    return ident_id


def _ensure_resource(
    model: ApplicationModel,
    resource_key: str,
    evidence_refs: list[str],
) -> str:
    resource_id = _entity_id("resource", resource_key)
    _ensure_entity(
        model,
        resource_id,
        kind=AppModelEntityKind.RESOURCE,
        label=f"resource:{resource_key}"[:160],
        provenance=DiscoveryProvenance.OBSERVED,
        evidence_refs=evidence_refs,
        metadata={"resource_key": resource_key[:160]},
    )
    return resource_id


def _add_relation(
    model: ApplicationModel,
    *,
    kind: AppModelRelationKind,
    source_id: str,
    target_id: str,
    provenance: DiscoveryProvenance,
    evidence_refs: list[str],
    metadata: dict[str, Any] | None = None,
) -> None:
    model.add_relation(
        AppModelRelation(
            id=f"{source_id}->{kind.value}->{target_id}"[:220],
            kind=kind,
            source_id=source_id,
            target_id=target_id,
            provenance=provenance,
            confidence=provenance_confidence(provenance),
            evidence_refs=list(evidence_refs)[:50],
            metadata=dict(metadata or {}),
        )
    )


def build_security_knowledge_graph(
    state: Mapping[str, Any] | Any,
) -> ApplicationModel:
    """Build the AppModel WITH the security knowledge graph layers.

    Starts from the base ``build_application_model`` spine (extend-not-
    rewrite) and derives the security entities/relations from the real
    evidence channels above. Fail-soft per channel; bounded everywhere.
    """
    model = build_application_model(state)
    path_lookup = _build_path_lookup(model)

    # -- 1. Roles (from the engagement's identity profiles) ---------------
    roles_seen: set[str] = set()
    profiles = _get(state, "identity_profiles") or {}
    if isinstance(profiles, Mapping):
        for label, profile in list(profiles.items())[:_MAX_ROLES]:
            if not isinstance(profile, Mapping):
                continue
            role = str(profile.get("role") or label or "").strip()
            if not role or role in roles_seen:
                continue
            roles_seen.add(role)
            ref = f"identity-profile:{label}"
            role_id = _ensure_role(model, role, [ref], declared=True)
            profile_identity = _entity_id("identity", role)
            if profile_identity in model.entities:
                _add_relation(
                    model,
                    kind=AppModelRelationKind.ASSUMES_ROLE,
                    source_id=profile_identity,
                    target_id=role_id,
                    provenance=DiscoveryProvenance.INFERRED,
                    evidence_refs=[ref],
                )

    # -- 2. Sessions (channel KEYS only — values are never recorded) ------
    for channel in ("session_cookies", "session_headers", "credentials"):
        channel_data = _get(state, channel) or {}
        if not isinstance(channel_data, Mapping):
            continue
        for key in list(channel_data.keys())[:_MAX_SESSIONS]:
            principal = str(key).strip()
            if not principal:
                continue
            ref = f"session-channel:{channel}:{principal}"
            session_id = _entity_id("session", principal)
            _ensure_entity(
                model,
                session_id,
                kind=AppModelEntityKind.SESSION,
                label=f"session:{principal}"[:160],
                provenance=DiscoveryProvenance.DECLARED,
                evidence_refs=[ref],
                metadata={
                    "channel": channel,
                    "principal": principal[:120],
                    "value_policy": "never-recorded",
                },
            )
            ident_id = _ensure_identity(
                model, principal, [ref],
                provenance=DiscoveryProvenance.INFERRED,
            )
            _add_relation(
                model,
                kind=AppModelRelationKind.BOUND_TO,
                source_id=session_id,
                target_id=ident_id,
                provenance=DiscoveryProvenance.DECLARED,
                evidence_refs=[ref],
                metadata={"channel": channel},
            )

    # -- 3. Resources + principals from authorization observations ---------
    # (production RC-2 shape: one record per Tool-Confirmed finding)
    resources_seen: set[str] = set()
    for record in (_get(state, "authorization_observations") or [])[
        :_MAX_RESOURCES
    ]:
        if not isinstance(record, Mapping):
            continue
        finding_id = str(record.get("finding_id") or "").strip()
        ref = f"authorization-observation:{finding_id}" if finding_id else ""
        if not ref:
            continue
        resource_key = str(
            record.get("resource_id") or record.get("object_id_from_url") or ""
        ).strip()
        if resource_key and resource_key not in resources_seen:
            resources_seen.add(resource_key)
            _ensure_resource(model, resource_key, [ref])
        actor = str(record.get("actor_id") or "").strip()
        owner = str(record.get("resource_owner") or "").strip()
        principals = [(actor, AppModelRelationKind.ACCESSES)]
        if owner:
            principals.append((owner, AppModelRelationKind.OWNS))
        for principal, relation_kind in principals:
            if not principal:
                continue
            ident_id = _ensure_identity(
                model, principal, [ref],
                provenance=DiscoveryProvenance.OBSERVED,
            )
            if not resource_key:
                continue
            resource_id = _entity_id("resource", resource_key)
            _add_relation(
                model,
                kind=relation_kind,
                source_id=ident_id,
                target_id=resource_id,
                provenance=DiscoveryProvenance.OBSERVED,
                evidence_refs=[ref],
                metadata={"ownership_basis": str(
                    record.get("ownership_basis") or "")[:200]},
            )

    # -- 4. Resources + endpoint ACCESSES from object identity ------------
    for record in (_get(state, "object_identity_observations") or [])[
        :_MAX_RESOURCES
    ]:
        if not isinstance(record, Mapping):
            continue
        resource_type = str(record.get("resource_type") or "").strip()
        object_id = str(record.get("object_id") or "").strip()
        obs_ref = str(record.get("observation_ref") or "").strip()
        if not (resource_type and object_id and obs_ref):
            continue
        resource_key = f"{resource_type}:{object_id}"
        if resource_key not in resources_seen:
            resources_seen.add(resource_key)
            _ensure_resource(model, resource_key, [obs_ref])
        endpoint_id = _resolve_endpoint(
            model, record.get("endpoint"), path_lookup)
        if endpoint_id is None:
            continue
        _add_relation(
            model,
            kind=AppModelRelationKind.ACCESSES,
            source_id=endpoint_id,
            target_id=_entity_id("resource", resource_key),
            provenance=DiscoveryProvenance.OBSERVED,
            evidence_refs=[obs_ref],
        )

    # -- 5. Workflows + states + transitions (state-before-after) ----------
    workflow_refs: dict[str, list[str]] = {}
    workflow_endpoints: dict[str, set[str]] = {}
    state_names: set[tuple[str, str]] = set()
    transitions: list[Mapping[str, Any]] = []
    for record in (_get(state, "workflow_observations") or [])[
        :_MAX_TRANSITIONS
    ]:
        if not isinstance(record, Mapping):
            continue
        workflow_key = str(record.get("workflow_key") or "").strip()
        from_state = str(record.get("from_state") or "").strip()
        to_state = str(record.get("to_state") or "").strip()
        if not workflow_key:
            continue
        refs = _record_refs(record)
        workflow_refs.setdefault(workflow_key, [])
        workflow_refs[workflow_key].extend(refs)
        endpoint_id = _resolve_endpoint(
            model, record.get("endpoint"), path_lookup)
        if endpoint_id is not None:
            workflow_endpoints.setdefault(workflow_key, set()).add(endpoint_id)
        transitions.append(record)
        for state_name in (from_state, to_state):
            if state_name:
                state_names.add((workflow_key, state_name))
    for workflow_key in list(workflow_refs)[:_MAX_WORKFLOWS]:
        _ensure_entity(
            model,
            _entity_id("workflow", workflow_key),
            kind=AppModelEntityKind.WORKFLOW,
            label=f"workflow:{workflow_key}"[:160],
            provenance=DiscoveryProvenance.OBSERVED,
            evidence_refs=list(dict.fromkeys(workflow_refs[workflow_key])),
            metadata={"workflow_key": workflow_key[:160]},
        )
        workflow_id = _entity_id("workflow", workflow_key)
        for endpoint_id in sorted(workflow_endpoints.get(workflow_key, ())):
            _add_relation(
                model,
                kind=AppModelRelationKind.EXPOSES,
                source_id=endpoint_id,
                target_id=workflow_id,
                provenance=DiscoveryProvenance.OBSERVED,
                evidence_refs=list(dict.fromkeys(workflow_refs[workflow_key])),
            )
    for workflow_key, state_name in sorted(state_names)[:_MAX_STATES]:
        state_id = _entity_id("state", f"{workflow_key}:{state_name}")
        refs = workflow_refs.get(workflow_key) or []
        _ensure_entity(
            model,
            state_id,
            kind=AppModelEntityKind.STATE,
            label=f"state:{workflow_key}:{state_name}"[:160],
            provenance=DiscoveryProvenance.OBSERVED,
            evidence_refs=list(dict.fromkeys(refs)),
            metadata={"workflow_key": workflow_key[:160], "state": state_name[:120]},
        )
    for record in transitions[:_MAX_TRANSITIONS]:
        workflow_key = str(record.get("workflow_key") or "").strip()
        from_state = str(record.get("from_state") or "").strip()
        to_state = str(record.get("to_state") or "").strip()
        if not (workflow_key and from_state and to_state):
            continue
        from_id = _entity_id("state", f"{workflow_key}:{from_state}")
        to_id = _entity_id("state", f"{workflow_key}:{to_state}")
        if from_id not in model.entities or to_id not in model.entities:
            continue
        _add_relation(
            model,
            kind=AppModelRelationKind.TRANSITIONS,
            source_id=from_id,
            target_id=to_id,
            provenance=DiscoveryProvenance.OBSERVED,
            evidence_refs=_record_refs(record),
            metadata={
                "workflow_key": workflow_key[:160],
                "transition_key": str(
                    record.get("transition_key") or "")[:160],
                "endpoint": str(record.get("endpoint") or "")[:240],
                "method": str(record.get("method") or "")[:16],
                "destructive": bool(record.get("destructive")),
            },
        )

    # -- 6. Parameters (observed path variance) ----------------------------
    _derive_parameters(model)

    # -- 7. Trust boundaries (endpoint origins) + CROSSES ------------------
    _derive_trust_boundaries(model)

    # -- 8. Declared authz markers (openapi security requirements) --------
    crawled = _get(state, "crawled_data") or {}
    if isinstance(crawled, Mapping):
        for route in (crawled.get("openapi_routes") or [])[:_MAX_RESOURCES]:
            if not isinstance(route, Mapping):
                continue
            path = str(route.get("path") or "").strip()
            security = route.get("security")
            if not path or not security:
                continue
            endpoint_id = _resolve_endpoint(model, path, path_lookup)
            if endpoint_id is None:
                continue
            existing = model.entities[endpoint_id]
            model.add_entity(
                AppModelEntity(
                    id=endpoint_id,
                    kind=AppModelEntityKind.ENDPOINT,
                    label=existing.label,
                    provenance=DiscoveryProvenance.DECLARED,
                    confidence=provenance_confidence(
                        DiscoveryProvenance.DECLARED),
                    evidence_refs=[f"openapi-security:{path}"],
                    metadata={"authz_declared": True},
                )
            )

    # -- 9. Typed SKG evidence records --------------------------------------
    for record in (_get(state, "skg_evidence") or [])[:_MAX_EVIDENCE_RECORDS]:
        if not isinstance(record, Mapping):
            continue
        _apply_skg_evidence_record(model, record, path_lookup)

    return model


def _apply_skg_evidence_record(
    model: ApplicationModel,
    record: Mapping[str, Any],
    path_lookup: dict[str, str],
) -> None:
    evidence_kind = str(record.get("evidence_kind") or "").strip()
    refs = _record_refs(record)
    endpoint_id = _resolve_endpoint(model, record.get("endpoint"), path_lookup)
    operation = str(record.get("operation") or "").strip().lower()

    if evidence_kind == "authz_marker":
        role = str(record.get("role") or "").strip()
        if not role:
            return
        declared = bool(record.get("declared"))
        role_id = _ensure_role(model, role, refs, declared=declared)
        if endpoint_id is None:
            return
        _add_relation(
            model,
            kind=AppModelRelationKind.PERMITS,
            source_id=role_id,
            target_id=endpoint_id,
            provenance=(
                DiscoveryProvenance.DECLARED
                if declared
                else DiscoveryProvenance.OBSERVED
            ),
            evidence_refs=refs,
            metadata={"operation": operation[:32]},
        )
        return

    if evidence_kind in {"ownership_change", "resource_access"}:
        resource_key = str(record.get("resource") or "").strip()
        if not resource_key:
            return
        resource_id = _ensure_resource(model, resource_key, refs)
        attribute = str(record.get("attribute") or "").strip()
        if evidence_kind == "ownership_change":
            kind = AppModelRelationKind.MODIFIES
            metadata = {
                "attribute": (attribute or "owner")[:120],
                "operation": operation[:32],
            }
            actor = str(record.get("actor") or "").strip()
            if actor:
                metadata["actor"] = actor[:120]
                ident_id = _ensure_identity(
                    model, actor, refs,
                    provenance=DiscoveryProvenance.OBSERVED)
                _add_relation(
                    model,
                    kind=AppModelRelationKind.MODIFIES,
                    source_id=ident_id,
                    target_id=resource_id,
                    provenance=DiscoveryProvenance.OBSERVED,
                    evidence_refs=refs,
                    metadata=dict(metadata),
                )
        elif operation in _WRITE_OPERATIONS:
            kind = AppModelRelationKind.MODIFIES
            metadata = {"operation": operation[:32]}
        else:
            kind = AppModelRelationKind.READS
            metadata = {"operation": operation[:32]}
        if endpoint_id is None:
            return
        _add_relation(
            model,
            kind=kind,
            source_id=endpoint_id,
            target_id=resource_id,
            provenance=DiscoveryProvenance.OBSERVED,
            evidence_refs=refs,
            metadata=metadata,
        )


def _derive_parameters(model: ApplicationModel) -> None:
    """PARAMETER entities from observed path variance.

    Endpoints on the same origin with the same segment count that
    differ in exactly ONE segment position evidence a parameter at
    that position. Deterministic masked-key clustering; bounded.
    """
    groups: dict[tuple[str, str, int, int], list[tuple[str, list[str]]]] = {}
    for entity_id, entity in model.entities.items():
        if str(entity.kind) != "endpoint":
            continue
        path = str(entity.metadata.get("path") or "")
        segments = [seg for seg in path.split("/") if seg]
        if len(segments) < 2:
            continue
        key = (
            str(entity.metadata.get("scheme") or ""),
            str(entity.metadata.get("host") or ""),
            int(entity.metadata.get("port") or 0),
            len(segments),
        )
        groups.setdefault(key, []).append((entity_id, segments))
    derived = 0
    for (scheme, host, port, _count), members in sorted(groups.items()):
        if derived >= _MAX_PARAMETERS:
            break
        for position in range(len(next(iter(members), ("", []))[1]) if members else 0):
            clusters: dict[tuple[str, ...], list[tuple[str, list[str]]]] = {}
            for entity_id, segments in members:
                masked = tuple(
                    "*" if i == position else seg
                    for i, seg in enumerate(segments)
                )
                clusters.setdefault(masked, []).append((entity_id, segments))
            for masked, cluster in sorted(clusters.items()):
                values = sorted({segments[position] for _, segments in cluster})
                if len(cluster) < 2 or derived >= _MAX_PARAMETERS:
                    continue
                prefix = [seg for seg in masked[:position] if seg != "*"]
                suffix = [seg for seg in masked[position + 1:] if seg != "*"]
                pattern = "/".join(
                    [*(seg for seg in masked[:position] if seg != "*"),
                     "{param}",
                     *(seg for seg in masked[position + 1:] if seg != "*")]
                )
                parameter_id = _entity_id(
                    "parameter", f"{scheme}://{host}:{port}/{pattern}")
                evidence = list(dict.fromkeys(
                    ref
                    for entity_id, _segments in cluster
                    for ref in model.entities[entity_id].ref_list()
                ))[:8]
                _ensure_entity(
                    model,
                    parameter_id,
                    kind=AppModelEntityKind.PARAMETER,
                    label=f"parameter:/{pattern}"[:160],
                    provenance=DiscoveryProvenance.OBSERVED,
                    evidence_refs=evidence,
                    metadata={
                        "pattern": f"/{pattern}"[:200],
                        "position": position,
                        "values_observed": values[:_MAX_PARAMETER_VALUES],
                        "origin": f"{scheme}://{host}:{port}"[:200],
                        "prefix": "/".join(prefix)[:120],
                        "suffix": "/".join(suffix)[:120],
                    },
                )
                for entity_id, _segments in cluster:
                    _add_relation(
                        model,
                        kind=AppModelRelationKind.HAS_PARAMETER,
                        source_id=entity_id,
                        target_id=parameter_id,
                        provenance=DiscoveryProvenance.OBSERVED,
                        evidence_refs=evidence,
                    )
                derived += 1


def _derive_trust_boundaries(model: ApplicationModel) -> None:
    """TRUST_BOUNDARY entities from endpoint origins + CROSSES relations."""
    origins: dict[tuple[str, str, int], list[str]] = {}
    for entity_id, entity in model.entities.items():
        if str(entity.kind) != "endpoint":
            continue
        scheme = str(entity.metadata.get("scheme") or "")
        host = str(entity.metadata.get("host") or "")
        port = int(entity.metadata.get("port") or 0)
        if not (scheme and host and port):
            continue
        origins.setdefault((scheme, host, port), []).append(entity_id)
    for (scheme, host, port), endpoint_ids in sorted(origins.items())[
        :_MAX_BOUNDARIES
    ]:
        boundary_key = f"{scheme}://{host}:{port}"
        boundary_id = _entity_id("trust_boundary", boundary_key)
        evidence = list(dict.fromkeys(
            ref
            for endpoint_id in endpoint_ids
            for ref in model.entities[endpoint_id].ref_list()
        ))[:8]
        _ensure_entity(
            model,
            boundary_id,
            kind=AppModelEntityKind.TRUST_BOUNDARY,
            label=f"trust_boundary:{boundary_key}"[:160],
            provenance=DiscoveryProvenance.OBSERVED,
            evidence_refs=evidence,
            metadata={
                "boundary_type": "origin",
                "scheme": scheme,
                "host": host,
                "port": port,
            },
        )
        for endpoint_id in sorted(endpoint_ids):
            _add_relation(
                model,
                kind=AppModelRelationKind.CROSSES,
                source_id=endpoint_id,
                target_id=boundary_id,
                provenance=DiscoveryProvenance.OBSERVED,
                evidence_refs=model.entities[endpoint_id].ref_list()[:8],
            )
    # a workflow whose observed endpoints span >1 origin crosses the
    # other boundaries (evidence: the workflow's own observation refs)
    for entity in list(model.entities.values()):
        if str(entity.kind) != "workflow":
            continue
        workflow_id = entity.id
        origins_of: set[tuple[str, str, int]] = set()
        for relation in model.relations:
            if str(relation.kind) != "exposes" or relation.target_id != workflow_id:
                continue
            endpoint = model.entities.get(relation.source_id)
            if endpoint is None:
                continue
            scheme = str(endpoint.metadata.get("scheme") or "")
            host = str(endpoint.metadata.get("host") or "")
            port = int(endpoint.metadata.get("port") or 0)
            if scheme and host and port:
                origins_of.add((scheme, host, port))
        if len(origins_of) <= 1:
            continue
        for scheme, host, port in sorted(origins_of):
            boundary_id = _entity_id(
                "trust_boundary", f"{scheme}://{host}:{port}")
            if boundary_id not in model.entities:
                continue
            _add_relation(
                model,
                kind=AppModelRelationKind.CROSSES,
                source_id=workflow_id,
                target_id=boundary_id,
                provenance=DiscoveryProvenance.OBSERVED,
                evidence_refs=entity.ref_list()[:8],
            )


# ---------------------------------------------------------------------------
# UM-DR-46 Phase A — SKG research hints (advisory, evidence-carrying).
# ---------------------------------------------------------------------------

_MAX_SKG_HINTS = 64


def build_skg_research_hints(
    model: ApplicationModel,
) -> dict[str, dict[str, Any]]:
    """Advisory hints derived from the SKG discriminating questions.

    Same contract as ``build_appmodel_research_hints``: advisory_only,
    source "appmodel", model_revision stamped, evidence_refs carried.
    Consumed by the hypothesis analyzer's by-path hint index (unknown
    kinds rank below the four canonical kinds — a safe default).
    """
    # imported here to keep the module import graph acyclic at load time
    from webpent.appmodel.skg_queries import (
        ownership_changers,
        reads_without_authz_marker,
        ui_vs_api_permission_diff,
        workflow_skip_candidates,
    )

    hints: dict[str, dict[str, Any]] = {}

    def add_hint(hint_id: str, kind: str, priority: float, reason: str,
                 evidence_refs: list[str], subject: dict[str, Any]) -> None:
        if len(hints) >= _MAX_SKG_HINTS:
            return
        hints[hint_id[:200]] = {
            "kind": kind,
            "priority": round(float(min(max(priority, 0.0), 1.0)), 4),
            "reason": str(reason)[:300],
            "evidence_refs": [str(r)[:240] for r in evidence_refs[:8]],
            "subject": subject,
            "advisory_only": True,
            "source": "appmodel",
            "model_revision": int(model.revision),
        }

    for entry in reads_without_authz_marker(model)[:16]:
        add_hint(
            f"appmodel-hint:skg-reads-no-authz:{entry['endpoint_id']}",
            "skg_reads_without_authz",
            0.85,
            "an endpoint accesses a resource with NO observed authorization "
            "marker — an authorization-boundary experiment is warranted",
            entry["evidence_refs"],
            {
                "endpoint_id": entry["endpoint_id"],
                "path": entry["path"],
                "resource_labels": entry["resource_labels"],
            },
        )
    for entry in ownership_changers(model)[:16]:
        add_hint(
            f"appmodel-hint:skg-ownership-changer:{entry['endpoint_id']}",
            "skg_ownership_changer",
            0.8,
            "an endpoint can change the ownership of a resource — the "
            "strongest object-authorization research target",
            entry["evidence_refs"],
            {
                "endpoint_id": entry["endpoint_id"],
                "path": entry["endpoint_path"],
                "resource_label": entry["resource_label"],
            },
        )
    workflow_keys = sorted(
        str(entity.metadata.get("workflow_key") or entity.label)
        for entity in model.entities.values()
        if str(entity.kind) == "workflow"
    )
    for workflow_key in workflow_keys[:16]:
        for skip in workflow_skip_candidates(model, workflow_key)[:8]:
            add_hint(
                "appmodel-hint:skg-workflow-skip:"
                f"{workflow_key}:{skip['from_state']}->{skip['to_state']}",
                "skg_workflow_skip",
                0.75,
                "an observed state transition bypasses an observed "
                "intermediate state — a workflow-abuse candidate",
                skip["evidence_refs"],
                {
                    "workflow_key": workflow_key,
                    "path": None,
                    "from_state": skip["from_state"],
                    "to_state": skip["to_state"],
                    "skipped_states": skip["skipped_states"],
                },
            )
    for diff in ui_vs_api_permission_diff(model)[:16]:
        add_hint(
            f"appmodel-hint:skg-ui-api-diff:{diff['ui_path']}|{diff['api_path']}",
            "skg_ui_api_diff",
            0.7,
            "the UI and API surfaces of the same resource disagree on "
            "authorization markers — a surface-differential experiment",
            diff["evidence_refs"],
            {"ui_path": diff["ui_path"], "api_path": diff["api_path"]},
        )
    return hints
