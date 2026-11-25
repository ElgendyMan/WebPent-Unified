"""UM-DR-46 Phase J — multi-protocol depth (SKG-driven targets).

See the test module for the contract. Pure, bounded (32), advisory —
targets, never requests, never authority.
"""
from __future__ import annotations

from typing import Any

from webpent.appmodel.models import ApplicationModel

__all__ = [
    "protocol_depth_targets",
    "graphql_skg_records",
    "websocket_session_records",
    "oauth_trust_boundary_records",
    "cross_surface_hypothesis",
]

_MAX_TARGETS = 32


def protocol_depth_targets(model: ApplicationModel) -> list[dict[str, Any]]:
    """All SKG-driven protocol-depth targets (bounded, sorted)."""
    targets: list[dict[str, Any]] = []

    # 1. workflow sequences: ≥2 observed transitions = sequence-replay work
    workflow_edges: dict[str, list[Any]] = {}
    for relation in model.relations:
        if str(relation.kind) != "transitions":
            continue
        workflow_key = str((relation.metadata or {}).get("workflow_key") or "")
        if workflow_key:
            workflow_edges.setdefault(workflow_key, []).append(relation)
    for workflow_key, relations in sorted(workflow_edges.items()):
        if len(relations) < 2:
            continue
        refs = sorted({ref for r in relations for ref in r.ref_list()})[:8]
        targets.append({
            "kind": "workflow_protocol",
            "workflow_key": workflow_key,
            "transition_count": len(relations),
            "transitions": sorted(
                f"{str((model.entities.get(r.source_id) or r.source_id))}"
                f"→{str((model.entities.get(r.target_id) or r.target_id))}"
                for r in relations
            )[:8],
            "evidence_refs": refs,
            "advisory_only": True,
        })

    # 2. enumerable object-id spaces: numeric observed parameter values
    for entity in sorted(
        (e for e in model.entities.values() if str(e.kind) == "parameter"),
        key=lambda e: e.id,
    ):
        values = sorted(str(v) for v in (
            entity.metadata.get("values_observed") or []))
        numeric = [v for v in values if v.isdigit()]
        if len(numeric) < 2:
            continue
        targets.append({
            "kind": "object_id_space",
            "parameter_id": entity.id,
            "pattern": str(entity.metadata.get("pattern") or ""),
            "numeric_values": numeric[:8],
            "evidence_refs": entity.ref_list(),
            "advisory_only": True,
        })

    # 3. cross-origin workflows: transitions whose trigger endpoints span
    #    >1 trust boundary (CROSSES from endpoints involved in the workflow)
    for workflow_key, relations in sorted(workflow_edges.items()):
        if len(relations) < 2:
            continue
        origins: set[str] = set()
        for relation in relations:
            endpoint_path = str((relation.metadata or {}).get("endpoint") or "")
            for entity in model.entities.values():
                if (str(entity.kind) == "endpoint"
                        and str(entity.metadata.get("path") or "")
                        == endpoint_path):
                    host = str(entity.metadata.get("host") or "")
                    port = str(entity.metadata.get("port") or "")
                    if host:
                        origins.add(f"{host}:{port}")
        if len(origins) > 1:
            targets.append({
                "kind": "cross_origin",
                "workflow_key": workflow_key,
                "origins": sorted(origins)[:4],
                "evidence_refs": sorted(
                    {ref for r in relations for ref in r.ref_list()})[:8],
                "advisory_only": True,
            })
    targets.sort(key=lambda t: (t["kind"], str(t.get("workflow_key")
                                           or t.get("parameter_id") or "")))
    return targets[:_MAX_TARGETS]

# ---------------------------------------------------------------------------
# UM-DR-47 Phase F2.3 — protocol depth beyond the 46 surface
# ---------------------------------------------------------------------------

_GRAPHQL_KIND_BY_OPERATION = {"query": "query", "mutation": "mutation"}


def graphql_skg_records(crawled_data: dict[str, Any]) -> list[dict[str, Any]]:
    """GraphQL operations → SKG evidence records (query/mutation).

    Each introspected operation (``graphql_operations`` from the crawl —
    ``{operation, kind, container, args}``) becomes ONE ``skg_evidence``
    record: the mutation kinds are MODIFIES-shaped relations (a mutation
    can change state), the queries are READS-shaped. This is what F2.3
    means by "GraphQL schema يدخل الـSKG ككيانات" — evidence-backed
    records the brain's SKG build consumes, not a parallel store.
    """
    ops = (crawled_data or {}).get("graphql_operations")
    if not isinstance(ops, list):
        return []
    records: list[dict[str, Any]] = []
    for op in ops[:32]:
        if not isinstance(op, dict):
            continue
        name = str(op.get("operation") or "").strip()
        if not name:
            continue
        kind = str(op.get("kind") or "query").lower()
        container = str(op.get("container") or "Query")
        arg_names = [
            str(a.get("name")) for a in (op.get("args") or [])
            if isinstance(a, dict) and a.get("name")
        ][:8]
        records.append({
            "evidence_kind": "graphql_operation",
            "endpoint": "/graphql",
            "operation_name": name,
            "operation_kind": kind,
            "container": container,
            "arg_names": arg_names,
            "evidence_refs": [f"graphql-introspection:{container}.{name}"],
        })
    return records


def websocket_session_records(crawled_data: dict[str, Any]) -> list[dict[str, Any]]:
    """WebSocket sessions → SKG workflow-observation records.

    The crawl records websocket upgrade endpoints (``ws_endpoints`` /
    ``websocket_endpoints`` channels when present). Each becomes a
    STATE-carrying workflow observation: a WS session is a stateful
    channel — tracking it as a workflow record gives the SKG its
    state-before-after semantics for the socket lifecycle.
    """
    crawled = crawled_data or {}
    ws_list: list[Any] = []
    for key in ("ws_endpoints", "websocket_endpoints"):
        value = crawled.get(key)
        if isinstance(value, list):
            ws_list.extend(value)
    records: list[dict[str, Any]] = []
    for i, entry in enumerate(ws_list[:16]):
        if isinstance(entry, dict):
            path = str(entry.get("path") or entry.get("url") or "")
        else:
            path = str(entry or "")
        if not path:
            continue
        records.append({
            "workflow_key": f"websocket-session:{path}",
            "transition_key": "upgrade",
            "endpoint": path,
            "method": "GET",
            "from_state": "disconnected",
            "to_state": "connected",
            "signals": {},
            "evidence_refs": [f"ws-observation:{i}:{path}"],
            "destructive": False,
            "authorization_boundary": "same_identity",
        })
    return records


_OAUTH_BOUNDARY_KINDS = ("oauth_flow", "oidc_flow", "trust_boundary_oauth")


def oauth_trust_boundary_records(
    crawled_data: dict[str, Any],
    identity_profiles: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """OAuth/OIDC flows → SKG trust-boundary evidence records.

    Crawl-visible OAuth surfaces (``oauth_endpoints`` / well-known
    providers) plus identity profiles that authenticate through a
    provider become TRUST_BOUNDARY-shaped records: an OAuth grant
    crosses a trust boundary by definition (the client acts with the
    user's delegated authority).
    """
    crawled = crawled_data or {}
    oauth_list: list[Any] = []
    for key in ("oauth_endpoints", "oauth_providers", "oidc_endpoints"):
        value = crawled.get(key)
        if isinstance(value, list):
            oauth_list.extend(value)
    records: list[dict[str, Any]] = []
    for i, entry in enumerate(oauth_list[:12]):
        if isinstance(entry, dict):
            path = str(entry.get("path") or entry.get("url") or "")
            grant = str(entry.get("grant_type") or entry.get("flow") or
                        "authorization_code")
        else:
            path = str(entry or "")
            grant = "authorization_code"
        if not path:
            continue
        records.append({
            "evidence_kind": "oauth_trust_boundary",
            "endpoint": path,
            "grant_type": grant,
            "boundary": "identity_provider",
            "evidence_refs": [f"oauth-boundary:{i}:{path}"],
        })
    # identity profiles declaring a provider = the delegated boundary
    for name, profile in (identity_profiles or {}).items():
        if not isinstance(profile, dict):
            continue
        provider = str(profile.get("oauth_provider")
                       or profile.get("identity_provider") or "")
        if provider:
            records.append({
                "evidence_kind": "oauth_trust_boundary",
                "endpoint": f"identity-profile:{name}",
                "grant_type": "delegated_identity",
                "boundary": provider,
                "evidence_refs": [f"oauth-profile:{name}:{provider}"],
            })
    return records


def cross_surface_hypothesis(
    model: "ApplicationModel",
    crawled_data: dict[str, Any],
) -> dict[str, Any] | None:
    """F2.3's the cross-protocol hypothesis (at least ONE, real):

    "OAuth-delegated permission against a GraphQL mutation": if the SKG
    holds an OAuth trust boundary AND a GraphQL mutation on the same
    target, emit the cross-relation candidate — an authorized mutation
    executed under a DELEGATED (OAuth) identity that the direct session
    could not perform. Returned as a canonical hypothesis dict (the
    caller funnels it through the ordinary pool — never a finding).
    """
    gql_mutations = [
        r for r in graphql_skg_records(crawled_data)
        if r["operation_kind"] == "mutation"
    ]
    oauth_boundaries = oauth_trust_boundary_records(crawled_data)
    if not (gql_mutations and oauth_boundaries):
        return None
    mutation = gql_mutations[0]
    boundary = oauth_boundaries[0]
    import hashlib
    from uuid import NAMESPACE_URL, uuid5

    blob = hashlib.sha256(
        f"{boundary['boundary']}|{mutation['operation_name']}".encode()
    ).hexdigest()[:40]
    return {
        "id": str(uuid5(NAMESPACE_URL, f"webpent:umdr47f23:{blob}")),
        "statement": (
            f"Cross-protocol authorization: the OAuth-delegated boundary "
            f"'{boundary['boundary']}' can reach the GraphQL mutation "
            f"'{mutation['container']}.{mutation['operation_name']}' — "
            f"verify the delegated principal cannot perform a mutation "
            f"the direct-session authorization would deny"
        ),
        "vuln_class": "auth_bypass",
        "origin": "researcher_brain",
        "origin_detail": (
            f"UM-DR-47 F2.3 cross-surface hypothesis; "
            f"oauth_boundary={boundary['boundary']}; "
            f"graphql_mutation={mutation['operation_name']}"
        ),
        "expected_behavior": (
            "the delegated-identity replay of the mutation is denied "
            "where the direct-session authorization denies it"
        ),
        "negative_control": (
            "replay the mutation as the direct-session owner (must "
            "succeed) AND as the OAuth-delegated principal (the "
            "differential must reproduce under sealed replay)"
        ),
        "info_gain": 0.7,
        "evidence_contract": {
            "evidence_refs": [
                *mutation["evidence_refs"][:4],
                *boundary["evidence_refs"][:4],
            ],
            "appmodel_hint": {"kind": "identity_relationship"},
        },
    }
