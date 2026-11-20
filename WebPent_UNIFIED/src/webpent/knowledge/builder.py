"""Deterministic Target Knowledge Model projection helpers."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit

from webpent.knowledge.target_knowledge import (
    AuthorizationProfile,
    DataFlow,
    KnowledgeEdge,
    KnowledgeKind,
    KnowledgeNode,
    TargetKnowledgeModel,
    WorkflowState,
)


def _stable_id(kind: str, value: str) -> str:
    digest = hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()[:20]
    return f"tk_{kind}_{digest}"


def _record_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _evidence(record: dict[str, Any]) -> list[str]:
    refs = record.get("evidence_refs") or record.get("source_evidence_ids") or []
    if isinstance(refs, str):
        refs = [refs]
    return [str(ref) for ref in refs if ref]


def _host_for_url(url: str) -> str:
    parsed = urlsplit(url)
    return parsed.netloc or parsed.path.split("/", 1)[0]


def _safe_text(value: Any, *, limit: int = 200) -> str | None:
    """Return a bounded non-empty string, or None for untrusted input."""
    if not isinstance(value, (str, int, float, bool)):
        return None
    text = str(value).strip()
    return text[:limit] if text else None


def _safe_node_metadata(raw: dict[str, Any], kind: str) -> dict[str, Any]:
    """Project bounded business metadata from an observed mental node only."""
    metadata: dict[str, Any] = {
        "discovery_source": _safe_text(raw.get("discovery_source"), limit=100) or "unknown"
    }
    raw_metadata = raw.get("metadata")
    if not isinstance(raw_metadata, Mapping):
        return metadata

    allowed_fields: dict[str, tuple[str, ...]] = {
        "object": ("object_type", "url"),
        "identity": ("role", "auth_pattern", "ownership_signal"),
        "workflow": ("required_role", "auth_pattern"),
        "endpoint": ("methods", "parameter_names", "is_form", "auth_signals"),
    }
    list_fields = {"methods", "parameter_names", "auth_signals"}
    for field in allowed_fields.get(kind, ()):
        value = raw_metadata.get(field)
        if field in list_fields:
            if not isinstance(value, list):
                continue
            cleaned = [item for item in (_safe_text(item, limit=100) for item in value) if item]
            if cleaned:
                metadata[field] = list(dict.fromkeys(cleaned))[:100]
            continue
        if field == "is_form":
            if isinstance(value, bool) and value:
                metadata[field] = True
            continue
        safe_value = _safe_text(value)
        if safe_value:
            if field == "url":
                parsed = urlsplit(safe_value)
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    continue
            metadata[field] = safe_value
    return metadata


def _normalise_transitions(raw: dict[str, Any]) -> list[dict[str, str]]:
    """Normalize observed workflow transitions or form steps only."""
    candidates = raw.get("transitions")
    if not isinstance(candidates, list) or not candidates:
        candidates = raw.get("steps")
    if not isinstance(candidates, list):
        return []

    transitions: list[dict[str, str]] = []
    field_aliases = {
        "method": ("method",),
        "endpoint": ("endpoint", "url", "action_url"),
        "from_state": ("from_state", "state_from"),
        "to_state": ("to_state", "state_to"),
    }
    for candidate in candidates[:100]:
        if not isinstance(candidate, Mapping):
            continue
        transition: dict[str, str] = {}
        for output_field, aliases in field_aliases.items():
            for alias in aliases:
                value = _safe_text(candidate.get(alias), limit=200)
                if value:
                    transition[output_field] = value
                    break
        if transition:
            transitions.append(transition)
    return transitions


def _safe_confidence(value: Any, default: float = 0.5) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        confidence = default
    return max(0.0, min(1.0, confidence))


def build_target_knowledge_model(
    *,
    engagement_id: str,
    mental_model: dict[str, Any] | None = None,
    target_understanding: dict[str, Any] | None = None,
    workflows: Iterable[dict[str, Any]] | None = None,
    authorization_profiles: Iterable[dict[str, Any]] | None = None,
    data_flows: Iterable[dict[str, Any]] | None = None,
) -> TargetKnowledgeModel:
    """Build a bounded projection from existing state-only observations.

    The builder is intentionally read-only: it performs no requests, does not
    infer authorization, and never copies credential values into metadata.
    """
    model = TargetKnowledgeModel(engagement_id=engagement_id)
    mental = mental_model if isinstance(mental_model, dict) else {}
    raw_nodes = mental.get("nodes") if isinstance(mental.get("nodes"), dict) else {}
    for raw_id, raw in raw_nodes.items():
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("kind", "object"))
        try:
            node_kind = KnowledgeKind(kind)
        except ValueError:
            node_kind = KnowledgeKind.OBJECT
        key = str(raw.get("identity_key") or raw_id)
        model.add_node(
            KnowledgeNode(
                node_id=str(raw_id),
                kind=node_kind,
                canonical_key=key,
                confidence=1.0 if raw.get("in_scope") is True else 0.5,
                in_scope=raw.get("in_scope"),
                evidence_refs=_evidence(raw),
                metadata=_safe_node_metadata(raw, node_kind.value),
            )
        )
    for raw in mental.get("edges", []) if isinstance(mental.get("edges"), list) else []:
        if not isinstance(raw, dict) or not raw.get("source_id") or not raw.get("target_id"):
            continue
        model.add_edge(
            KnowledgeEdge(
                source_id=str(raw["source_id"]),
                target_id=str(raw["target_id"]),
                relation=str(raw.get("kind", "related_to")),
                confidence=0.8 if raw.get("source_ref") else 0.5,
                evidence_refs=_evidence(raw),
            )
        )

    understanding = target_understanding if isinstance(target_understanding, dict) else {}
    for endpoint in _record_list(understanding.get("endpoints")):
        url = str(endpoint.get("url") or endpoint.get("target_url") or "")
        if not url:
            continue
        endpoint_id = _stable_id("endpoint", url)
        model.add_node(
            KnowledgeNode(
                node_id=endpoint_id,
                kind=KnowledgeKind.ENDPOINT,
                canonical_key=url,
                confidence=_safe_confidence(endpoint.get("confidence", 0.5)),
                in_scope=endpoint.get("in_scope"),
                evidence_refs=_evidence(endpoint),
                metadata={"method": str(endpoint.get("method", "GET")).upper()},
            )
        )
        host = _host_for_url(url)
        if host:
            host_id = _stable_id("host", host)
            model.add_node(
                KnowledgeNode(
                    node_id=host_id,
                    kind=KnowledgeKind.HOST,
                    canonical_key=host,
                    confidence=0.8,
                    in_scope=endpoint.get("in_scope"),
                    evidence_refs=_evidence(endpoint),
                )
            )
            model.add_edge(
                KnowledgeEdge(
                    source_id=host_id,
                    target_id=endpoint_id,
                    relation="contains",
                    confidence=0.8,
                    evidence_refs=_evidence(endpoint),
                )
            )

    for raw in workflows or []:
        if not isinstance(raw, dict):
            continue
        workflow_id = str(raw.get("workflow_id") or raw.get("id") or "")
        if not workflow_id:
            continue
        transitions = _normalise_transitions(raw)
        observed_states = [
            str(item)[:100]
            for item in raw.get("states", [])
            if isinstance(item, (str, int, float)) and str(item).strip()
        ][:100]
        for transition in transitions:
            for field_name in ("from_state", "to_state"):
                state = transition.get(field_name)
                if state and state not in observed_states:
                    observed_states.append(state)
        required_role = _safe_text(raw.get("required_role"), limit=100)
        model.workflows[workflow_id] = WorkflowState(
            workflow_id=workflow_id,
            name=str(raw.get("name") or raw.get("label") or workflow_id),
            required_role=required_role,
            states=observed_states,
            transitions=transitions,
            identity_refs=[
                str(item)[:200]
                for item in raw.get("identity_refs", [])
                if isinstance(item, (str, int, float)) and str(item).strip()
            ][:100],
            evidence_refs=_evidence(raw),
            confidence=_safe_confidence(raw.get("confidence", 0.5)),
        )
        model.add_node(
            KnowledgeNode(
                node_id=workflow_id,
                kind=KnowledgeKind.WORKFLOW,
                canonical_key=workflow_id,
                confidence=model.workflows[workflow_id].confidence,
                evidence_refs=_evidence(raw),
                metadata={
                    key: value
                    for key, value in {
                        "required_role": required_role,
                        "auth_pattern": _safe_text(raw.get("auth_pattern")),
                    }.items()
                    if value
                },
            )
        )
        for transition in transitions:
            endpoint = transition.get("endpoint")
            if not endpoint:
                continue
            model.add_edge(
                KnowledgeEdge(
                    source_id=workflow_id,
                    target_id=_stable_id("endpoint", endpoint),
                    relation="contains",
                    confidence=model.workflows[workflow_id].confidence,
                    evidence_refs=_evidence(raw),
                )
            )

    for raw in authorization_profiles or []:
        if not isinstance(raw, dict):
            continue
        identity_id = str(raw.get("identity_id") or raw.get("id") or "")
        if not identity_id:
            continue
        profile = AuthorizationProfile(
            identity_id=identity_id,
            role_names=[str(item) for item in raw.get("role_names", []) if item],
            observed_capabilities=[
                str(item) for item in raw.get("observed_capabilities", []) if item
            ],
            authorization_status=str(raw.get("authorization_status", "unknown")),
            evidence_refs=_evidence(raw),
        )
        model.authorization_profiles[identity_id] = profile
        model.add_node(
            KnowledgeNode(
                node_id=identity_id,
                kind=KnowledgeKind.IDENTITY,
                canonical_key=identity_id,
                confidence=0.8 if profile.authorization_status == "observed" else 0.4,
                evidence_refs=profile.evidence_refs,
                metadata={"authorization_status": profile.authorization_status},
            )
        )

    for raw in data_flows or []:
        if not isinstance(raw, dict):
            continue
        source_id = str(raw.get("source_id") or "")
        destination_id = str(raw.get("destination_id") or "")
        channel = str(raw.get("channel") or "")
        if not source_id or not destination_id or not channel:
            continue
        model.data_flows.append(
            DataFlow(
                source_id=source_id,
                destination_id=destination_id,
                channel=channel,
                data_classes=[str(item) for item in raw.get("data_classes", []) if item],
                evidence_refs=_evidence(raw),
                observed=bool(raw.get("observed", False)),
            )
        )

    return model


class KnowledgeBuilder:
    """Build a TargetKnowledgeModel from an existing LangGraph state.

    The wrapper is intentionally additive and read-only. It accepts incomplete
    legacy state, uses a stable non-empty scope when no engagement identifier
    exists, and only projects explicitly observed records.
    """

    def __init__(self, state: Mapping[str, Any] | None = None) -> None:
        self.state = state if isinstance(state, Mapping) else {}

    @classmethod
    def from_state(cls, state: Mapping[str, Any] | None) -> KnowledgeBuilder:
        """Create a builder without mutating or validating the caller's state."""
        return cls(state)

    def build(self) -> TargetKnowledgeModel:
        """Return a bounded deterministic projection, failing closed on bad input."""
        state = self.state
        engagement_id = (
            str(state.get("engagement_id") or state.get("thread_id") or "unscoped").strip()
            or "unscoped"
        )
        understanding = state.get("target_understanding")
        if not isinstance(understanding, dict):
            understanding = {}
        mental_model = state.get("mental_model")
        if not isinstance(mental_model, dict):
            mental_model = {}

        workflows = state.get("knowledge_workflows")
        if not isinstance(workflows, list):
            workflows = understanding.get("workflows", [])
        authorization_profiles = state.get("knowledge_authorization_profiles")
        if not isinstance(authorization_profiles, list):
            authorization_profiles = []
        data_flows = state.get("knowledge_data_flows")
        if not isinstance(data_flows, list):
            data_flows = []

        return build_target_knowledge_model(
            engagement_id=engagement_id,
            mental_model=mental_model,
            target_understanding=understanding,
            workflows=workflows,
            authorization_profiles=authorization_profiles,
            data_flows=data_flows,
        )


__all__ = ["KnowledgeBuilder", "build_target_knowledge_model"]
