"""Passive application-intent and identity-matrix extraction.

The builder consumes metadata already collected by crawler/browser adapters. It
never sends requests, creates accounts, replays workflows, or confirms findings.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from webpent.models.application_intent import (
    ApplicationIntentModel,
    IdentityContext,
    IntentEdge,
    IntentNode,
)
from webpent.models.evidence import canonical_json, redact_sensitive

_ROLE_KEYS = ("role", "actor_role", "user_role", "required_role", "authorization_scope")
_SECRET_KEY = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|cookie|authorization|jwt)")
_OBJECT_KEY = re.compile(
    r"(?i)(?:^|[_-])(id|user|account|owner|order|invoice|document|payment|resource|file)(?:[_-]|$)"
)
_ALLOWED_ROLES = {"anonymous", "owner", "foreign_user", "tenant_admin", "global_admin"}


def _text(value: Any, limit: int = 600) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return clean.strip()[:limit]


def _hash_ref(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(_text(value).encode("utf-8", "ignore")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _provenance(record: Mapping[str, Any] | None, fallback: str = "passive_inference") -> list[str]:
    """Return bounded, redacted provenance labels for an inference."""
    if not isinstance(record, Mapping):
        return [fallback]
    values: list[str] = []
    for key in (
        "source",
        "source_kind",
        "adapter",
        "discovery_kind",
        "identity",
        "tenant",
        "workflow_state",
    ):
        value = _text(record.get(key), 80).lower()
        if value and value not in values:
            values.append(value)
    return values[:20] or [fallback]


def _records(data: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    value = data.get(key)
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    if isinstance(value, Mapping):
        return [value]
    return []


def _all_records(data: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    records: list[Mapping[str, Any]] = []
    for key in (
        "forms",
        "requests",
        "api_requests",
        "responses",
        "workflow_steps",
        "endpoints",
        "surface_records",
        "xhr_requests",
        "browser_requests",
        "openapi_routes",
        "graphql_operations",
        "multipart_fields",
        "identity_contexts",
    ):
        records.extend(_records(data, key))
    return records


def _semantic_text(record: Mapping[str, Any]) -> str:
    """Use route-independent semantics for intent fingerprints."""
    keys = (
        "title",
        "name",
        "action",
        "operation",
        "workflow",
        "state",
        "next_state",
        "method",
        "content_type",
        "service",
        "sink",
        "job",
        "role",
        "required_role",
    )
    fields = record.get("fields") or record.get("parameters") or {}
    if isinstance(fields, Mapping):
        field_names = ",".join(sorted(str(key).lower() for key in fields))
    else:
        field_names = ""
    return " ".join(_text(record.get(key), 240) for key in keys) + f" fields:{field_names}"


def _safe_actor_label(key: str, value: Any) -> str:
    normalized = _text(value).lower().replace("-", "_").replace(" ", "_")
    if not normalized:
        return ""
    if normalized in _ALLOWED_ROLES:
        return normalized
    if key == "authorization_scope":
        return "scoped_actor"
    return _hash_ref("actor", normalized)


def _node(
    node_type: str,
    label: str,
    attributes: Mapping[str, Any],
    evidence: list[str],
    confidence: float = 0.45,
    provenance: list[str] | None = None,
) -> IntentNode:
    payload = {
        "node_type": node_type,
        "label": label.lower(),
        "attributes": dict(attributes),
        "evidence": sorted(set(evidence)),
    }
    return IntentNode(
        node_id=_hash_ref("intent", canonical_json(payload)),
        node_type=node_type,
        label=label[:160],
        attributes=dict(attributes),
        evidence_refs=list(dict.fromkeys(evidence))[:20],
        provenance=list(dict.fromkeys(provenance or ["passive_inference"]))[:20],
        confidence=confidence,
    )


def _identity_matrix(
    data: Mapping[str, Any], records: list[Mapping[str, Any]]
) -> list[IdentityContext]:
    observed_roles: dict[str, list[str]] = {}
    observed_provenance: dict[str, list[str]] = {}
    for record in records:
        values = [record.get(key) for key in _ROLE_KEYS]
        for value in values:
            role = _text(value).lower().replace("-", "_").replace(" ", "_")
            if role in _ALLOWED_ROLES:
                observed_roles.setdefault(role, []).append(
                    _hash_ref("evidence", _semantic_text(record))
                )
                observed_provenance.setdefault(role, []).extend(_provenance(record))
        if record.get("authenticated") is True:
            observed_roles.setdefault("owner", []).append(
                _hash_ref("evidence", _semantic_text(record))
            )
            observed_provenance.setdefault("owner", []).extend(_provenance(record))
    for item in _records(data, "identity_matrix"):
        role = _text(item.get("role")).lower().replace("-", "_").replace(" ", "_")
        if role in _ALLOWED_ROLES:
            observed_roles.setdefault(role, []).append(
                _hash_ref("evidence", _semantic_text(item))
            )
            observed_provenance.setdefault(role, []).extend(_provenance(item))

    contexts: list[IdentityContext] = []
    for role in ("anonymous", "owner", "foreign_user", "tenant_admin", "global_admin"):
        refs = list(dict.fromkeys(observed_roles.get(role, [])))[:20]
        contexts.append(
            IdentityContext(
                context_id=_hash_ref("identity-context", role),
                role=role,
                disposition="observed" if refs else "not_observed",
                authenticated=role != "anonymous" and bool(refs),
                session_health="unknown",
                capability_refs=[f"capability:{role}"],
                evidence_refs=refs,
                provenance=list(dict.fromkeys(observed_provenance.get(role, [])))[:20]
                or ["identity_matrix_absent"],
            )
        )
    return contexts


def build_application_intent_model(
    crawled_data: Mapping[str, Any] | None,
    *,
    target_url: str = "",
) -> ApplicationIntentModel:
    """Build a bounded intent graph from passive metadata only."""
    data = crawled_data if isinstance(crawled_data, Mapping) else {}
    records = _all_records(data)
    actors: dict[str, IntentNode] = {}
    objects: dict[str, IntentNode] = {}
    fields: dict[str, IntentNode] = {}
    boundaries: dict[str, IntentNode] = {}
    sinks: dict[str, IntentNode] = {}
    transitions: dict[str, IntentNode] = {}
    jobs: dict[str, IntentNode] = {}
    services: dict[str, IntentNode] = {}
    edges: dict[str, IntentEdge] = {}
    evidence_refs: list[str] = []

    def add_edge(source: IntentNode, target: IntentNode, relation: str, refs: list[str]) -> None:
        edge_id = _hash_ref("edge", f"{source.node_id}|{target.node_id}|{relation}")
        edges[edge_id] = IntentEdge(
            edge_id=edge_id,
            source_id=source.node_id,
            target_id=target.node_id,
            relation=relation,
            evidence_refs=list(dict.fromkeys(refs))[:20],
            provenance=list(dict.fromkeys(source.provenance + target.provenance))[:20],
        )

    for record in records[:250]:
        semantic = _semantic_text(record)
        if not semantic.strip():
            continue
        evidence = [_hash_ref("evidence", semantic)]
        record_provenance = _provenance(record)
        evidence_refs.extend(evidence)
        actor_labels = [
            _safe_actor_label(key, record.get(key))
            for key in _ROLE_KEYS
            if _text(record.get(key))
        ]
        if record.get("authenticated") or record.get("requires_auth"):
            actor_labels.append("authenticated_actor")
        for label in actor_labels[:3]:
            actors.setdefault(
                label,
                _node(
                    "actor",
                    label,
                    {"target": target_url},
                    evidence,
                    provenance=record_provenance,
                ),
            )

        values = record.get("fields") or record.get("parameters") or {}
        if isinstance(values, Mapping):
            for key in list(values)[:20]:
                name = _text(key, 100).lower()
                if not name or _SECRET_KEY.search(name):
                    continue
                field_node = _node(
                    "field",
                    name,
                    {"semantic_key": name},
                    evidence,
                    provenance=record_provenance,
                )
                fields.setdefault(name, field_node)
                if _OBJECT_KEY.search(name):
                    object_label = name.split("_", 1)[0] if "_" in name else name
                    object_node = _node(
                        "object",
                        object_label,
                        {"field": name},
                        evidence,
                        provenance=record_provenance,
                    )
                    objects.setdefault(object_label, object_node)
                    add_edge(object_node, field_node, "has_field", evidence)

        state = _text(record.get("state") or record.get("workflow_state"), 80)
        next_state = _text(record.get("next_state") or record.get("to_state"), 80)
        if state or next_state or record.get("workflow"):
            transition_label = f"{state or 'unknown'}->{next_state or 'unknown'}"
            transition = _node(
                "state_transition",
                transition_label,
                {"method": _text(record.get("method"), 12).upper() or "GET"},
                evidence,
                provenance=record_provenance,
            )
            transitions.setdefault(transition_label, transition)

        sink_text = " ".join(
            _text(record.get(key))
            for key in ("sink", "template", "content_type", "action", "operation")
        ).lower()
        for label, needles in {
            "template": ("template", "blade", "ssti", "render"),
            "external_fetch": ("url", "webhook", "swagger", "image", "fetch"),
            "parser": ("xml", "xslt", "csv", "multipart", "upload"),
        }.items():
            if any(needle in sink_text for needle in needles):
                sinks.setdefault(
                    label,
                    _node("sink", label, {}, evidence, provenance=record_provenance),
                )

        job_text = " ".join(_text(record.get(key)) for key in ("job", "queue", "worker", "async"))
        if any(token in job_text.lower() for token in ("job", "queue", "worker", "async")):
            job = _node(
                "background_job",
                _text(job_text, 80) or "background_job",
                {},
                evidence,
                provenance=record_provenance,
            )
            jobs.setdefault(job.label, job)

        service_text = " ".join(
            _text(record.get(key))
            for key in ("service", "backend", "dependency", "response_headers")
        ).lower()
        for label in ("elasticsearch", "mysql", "redis", "graphql", "swagger", "oauth"):
            if label in service_text or label in semantic.lower():
                services.setdefault(
                    label,
                    _node(
                        "service_dependency",
                        label,
                        {},
                        evidence,
                        provenance=record_provenance,
                    ),
                )

        if record.get("tenant") or record.get("tenant_id") or record.get("cross_tenant"):
            boundary = _node(
                "trust_boundary",
                "tenant_boundary",
                {},
                evidence,
                provenance=record_provenance,
            )
            boundaries.setdefault("tenant_boundary", boundary)
        if (
            record.get("authorization")
            or record.get("required_role")
            or record.get("cross_identity")
        ):
            boundary = _node(
                "trust_boundary",
                "authorization_boundary",
                {},
                evidence,
                provenance=record_provenance,
            )
            boundaries.setdefault("authorization_boundary", boundary)

    for actor in actors.values():
        for transition in transitions.values():
            add_edge(actor, transition, "actor_transition", transition.evidence_refs)
    for transition in transitions.values():
        for sink in sinks.values():
            add_edge(transition, sink, "transition_reaches_sink", transition.evidence_refs)
    for job in jobs.values():
        for sink in sinks.values():
            add_edge(job, sink, "job_reaches_sink", job.evidence_refs)

    return ApplicationIntentModel(
        actors=list(actors.values())[:20],
        objects=list(objects.values())[:50],
        fields=list(fields.values())[:80],
        trust_boundaries=list(boundaries.values())[:20],
        sinks=list(sinks.values())[:40],
        state_transitions=list(transitions.values())[:60],
        background_jobs=list(jobs.values())[:30],
        service_dependencies=list(services.values())[:30],
        identities=_identity_matrix(data, records),
        edges=list(edges.values())[:160],
        evidence_refs=list(dict.fromkeys(evidence_refs))[:50],
    )


__all__ = ["build_application_intent_model"]
