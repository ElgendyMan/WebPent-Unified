"""Passive causal research projection for the Smart Hunter loop.

This module consumes checkpoint-safe observations only.  It never performs
transport, creates findings, authorizes actions, or upgrades confidence.  The
projection is deliberately deterministic so every causal edge and every
next-best-action reference can be audited and replayed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from webpent.shared.research_intelligence import (
    NegativeEvidence,
    NegativeEvidenceLedger,
    ResearchSession,
)
from webpent.state.reducers import model_get

_MAX_ITEMS = 100


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    dumper = getattr(value, "model_dump", None)
    if callable(dumper):
        try:
            result = dumper(mode="json")
        except TypeError:
            result = dumper()
        return dict(result) if isinstance(result, Mapping) else {}
    return {}


def _text(value: Any, limit: int = 200) -> str:
    return str(value or "").strip()[:limit]


def _finding_ref(finding: Any) -> str:
    value = model_get(finding, "id")
    return f"finding:{value}" if value is not None else ""


def _edge_key(edge: Mapping[str, Any]) -> str:
    return "|".join(
        (
            _text(edge.get("kind"), 80),
            _text(edge.get("source_id"), 160),
            _text(edge.get("target_id"), 160),
            ",".join(_text(item, 120) for item in edge.get("evidence_refs", ())[:10]),
        )
    )


def _append_edge(edges: list[dict[str, Any]], edge: Mapping[str, Any]) -> None:
    clean = {
        "kind": _text(edge.get("kind"), 80),
        "source_id": _text(edge.get("source_id"), 160),
        "target_id": _text(edge.get("target_id"), 160),
        "evidence_refs": [_text(item, 160) for item in edge.get("evidence_refs", ())[:20]],
        "confidence": _text(edge.get("confidence") or "observed", 80),
        "causal_signal": bool(edge.get("causal_signal")),
        "negative_control_complete": bool(edge.get("negative_control_complete")),
        "control_complete": bool(edge.get("control_complete")),
        "metadata": _mapping(edge.get("metadata")),
    }
    if not clean["kind"] or not clean["source_id"] or not clean["target_id"]:
        return
    if not any(_edge_key(item) == _edge_key(clean) for item in edges):
        edges.append(clean)


def _load_negative_ledger(state: Mapping[str, Any]) -> NegativeEvidenceLedger:
    ledger = NegativeEvidenceLedger()
    raw_entries: list[Any] = []
    raw_entries.extend(state.get("negative_evidence_ledger") or [])
    session = _mapping(state.get("research_session"))
    raw_entries.extend(session.get("negative_evidence_ledger") or [])
    for raw in raw_entries[:500]:
        item = _mapping(raw)
        if not item:
            continue
        evidence = NegativeEvidence(
            evidence_id=_text(item.get("evidence_id") or "negative:unknown", 128),
            hypothesis_id=_text(item.get("hypothesis_id"), 128),
            action_fingerprint=_text(item.get("action_fingerprint"), 128),
            identity_context=_text(item.get("identity_context") or "anonymous", 120),
            tenant_context=_text(item.get("tenant_context") or "unknown", 120),
            method=_text(item.get("method") or "GET", 16),
            workflow_state=_text(item.get("workflow_state") or "unknown", 120),
            reason=_text(item.get("reason"), 500),
            confidence=float(item.get("confidence") or 0.0),
            reusable_if=tuple(_text(value, 80) for value in item.get("reusable_if", ())[:10]),
            expires_at=_text(item.get("expires_at"), 80),
            client_id=_text(item.get("client_id"), 128),
            engagement_id=_text(item.get("engagement_id"), 128),
            scope=tuple(_text(value, 160) for value in item.get("scope", ())[:10]),
        )
        ledger.record(evidence)
    return ledger


def _round_artifact(
    *,
    state: Mapping[str, Any],
    edges: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    action_context: list[dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    replanning = _mapping(state.get("smart_replanning"))
    try:
        round_number = max(0, int(replanning.get("round", 0) or 0))
    except (TypeError, ValueError):
        round_number = 0
    client_id = _text(state.get("client_id") or "client:unknown", 128)
    engagement_id = _text(state.get("engagement_id") or "engagement:unknown", 128)
    payload = {
        "round": round_number,
        "client_scope": client_id,
        "engagement_scope": engagement_id,
        "candidate_action_ids": sorted(
            _text(item.get("action_id"), 160)
            for item in candidates
            if _text(item.get("action_id"), 160)
        )[:_MAX_ITEMS],
        "causal_edge_refs": sorted(_edge_key(edge)[:64] for edge in edges)[- _MAX_ITEMS :],
        "decision_action_ids": sorted(
            _text(item.get("action_id"), 160)
            for item in action_context
            if _text(item.get("action_id"), 160)
        )[:_MAX_ITEMS],
        "counts": {
            "causal_edges": len(edges),
            "candidate_actions": len(candidates),
            "decision_links": len(action_context),
        },
        "negative_evidence_consulted": True,
        "evidence_only": True,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    artifact_id = "research-round:" + hashlib.sha256(canonical.encode()).hexdigest()[:24]
    return str(round_number), {"artifact_id": artifact_id, **payload}


def build_causal_research_projection(state: Mapping[str, Any]) -> dict[str, Any]:
    """Build causal edges and annotate candidates with their decision context."""
    edges: list[dict[str, Any]] = []
    nodes: dict[str, dict[str, Any]] = {}

    def node(node_id: str, kind: str, label: str, **metadata: Any) -> None:
        if node_id and node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "kind": kind,
                "label": label[:120],
                "metadata": {key: value for key, value in metadata.items() if value is not None},
            }

    for raw_finding in (state.get("findings") or [])[:_MAX_ITEMS]:
        finding = _mapping(raw_finding)
        finding_id = _finding_ref(raw_finding)
        if not finding_id:
            continue
        hypothesis_value = finding.get("hypothesis_id")
        hypothesis_id = (
            f"hypothesis:{hypothesis_value}"
            if hypothesis_value
            else f"hypothesis:direct:{finding_id[8:]}"
        )
        node(finding_id, "finding", "finding", vuln_class=_text(finding.get("vuln_class"), 80))
        node(hypothesis_id, "hypothesis", "originating hypothesis")
        evidence_refs = [finding_id]
        evidence = _mapping(finding.get("evidence"))
        evidence_refs.extend(_text(item, 160) for item in evidence.get("evidence_refs", ())[:10])
        contract = _mapping(finding.get("evidence_contract"))
        explicit_causal = bool(contract.get("causal_signal"))
        control_complete = bool(
            contract.get("negative_control_complete") or contract.get("control_complete")
        )
        _append_edge(
            edges,
            {
                "kind": "observation_supports_hypothesis",
                "source_id": finding_id,
                "target_id": hypothesis_id,
                "evidence_refs": evidence_refs,
                "confidence": _text(finding.get("confidence_level") or "observed", 80),
                "causal_signal": explicit_causal and control_complete,
                "negative_control_complete": control_complete,
                "control_complete": control_complete,
                "metadata": {"vuln_class": _text(finding.get("vuln_class"), 80)},
            },
        )

    for raw_observation in (state.get("research_active_observations") or [])[:_MAX_ITEMS]:
        observation = _mapping(raw_observation)
        observation_id = _text(observation.get("observation_id"), 160)
        action_id = _text(observation.get("action_id"), 160)
        if not observation_id or not action_id:
            continue
        source_id = f"observation:{observation_id}"
        target_id = f"research-action:{action_id}"
        node(source_id, "observation", _text(observation.get("status") or "observation", 80))
        node(target_id, "action", "research action")
        control_complete = bool(
            observation.get("control_complete")
            or observation.get("negative_control_complete")
        )
        _append_edge(
            edges,
            {
                "kind": "negative_control"
                if observation.get("status") == "negative" and control_complete
                else "causal_signal"
                if observation.get("causal_signal") and control_complete
                else "observation_supports_hypothesis",
                "source_id": source_id,
                "target_id": target_id,
                "evidence_refs": observation.get("evidence_refs") or [observation_id],
                "confidence": "explicit_control" if control_complete else "observed",
                "causal_signal": bool(observation.get("causal_signal")) and control_complete,
                "negative_control_complete": control_complete,
                "control_complete": control_complete,
                "metadata": {"status": _text(observation.get("status"), 80)},
            },
        )

    existing_edges = state.get("causal_attack_edges") or []
    for raw_edge in existing_edges[:_MAX_ITEMS]:
        if isinstance(raw_edge, Mapping):
            _append_edge(edges, raw_edge)

    client_id = _text(state.get("client_id") or "client:unknown", 128)
    engagement_id = _text(state.get("engagement_id") or "engagement:unknown", 128)
    ledger = _load_negative_ledger(state)
    candidates: list[dict[str, Any]] = []
    action_context: list[dict[str, Any]] = []
    for raw_candidate in (state.get("research_candidate_actions") or [])[:_MAX_ITEMS]:
        candidate = _mapping(raw_candidate)
        if not candidate:
            continue
        action_id = _text(candidate.get("action_id"), 160)
        if not action_id:
            continue
        fingerprint = _text(candidate.get("fingerprint"), 128)
        if not fingerprint:
            fingerprint = _text(candidate.get("idempotency_key"), 128)
        refs: list[str] = []
        candidate_hypothesis = _text(candidate.get("hypothesis_id"), 160)
        candidate_gap = _text(candidate.get("gap_id"), 160)
        hypothesis_refs = {candidate_hypothesis, f"hypothesis:{candidate_hypothesis}"}
        gap_refs = {candidate_gap, f"gap:{candidate_gap}"}
        for edge in edges:
            haystack = {
                edge.get("source_id"),
                edge.get("target_id"),
                *edge.get("evidence_refs", ()),
            }
            if (
                f"research-action:{action_id}" in haystack
                or bool(hypothesis_refs & haystack)
                or bool(gap_refs & haystack)
            ):
                refs.append(_edge_key(edge)[:64])
        reusable = ledger.reusable_for(
            action_fingerprint=fingerprint,
            client_id=client_id,
            engagement_id=engagement_id,
            hypothesis_id=_text(candidate.get("hypothesis_id"), 128) or None,
        ) if fingerprint else []
        metadata = _mapping(candidate.get("metadata"))
        metadata.update(
            {
                "causal_edge_refs": refs[:20],
                "negative_evidence_reusable_count": len(reusable),
                "negative_evidence_consulted": True,
            }
        )
        candidate["metadata"] = metadata
        candidates.append(candidate)
        action_context.append(
            {
                "action_id": action_id,
                "fingerprint": fingerprint,
                "causal_edge_refs": refs[:20],
                "negative_evidence_reusable_count": len(reusable),
                "decision_basis": "causal_graph_and_negative_ledger",
            }
        )

    session = ResearchSession.from_state(state)
    session.causal_attack_graph = edges[-_MAX_ITEMS:]
    session.next_best_actions = [
        {**item, "outcome": "causal_context_attached"} for item in action_context[-_MAX_ITEMS:]
    ]
    round_key, round_artifact = _round_artifact(
        state=state,
        edges=edges,
        candidates=candidates,
        action_context=action_context,
    )
    graph = {
        "version": 1,
        "nodes": list(nodes.values())[-_MAX_ITEMS:],
        "edges": edges[-_MAX_ITEMS:],
        "next_best_action_links": action_context[-_MAX_ITEMS:],
        "negative_evidence_consulted": True,
        "client_scope": client_id,
        "engagement_scope": engagement_id,
    }
    return {
        "causal_attack_edges": edges[-_MAX_ITEMS:],
        "causal_attack_graph": graph,
        "research_candidate_actions": candidates,
        "research_session": session.as_dict(),
        "research_unified_decision_trace": action_context[-_MAX_ITEMS:],
        "research_round_artifacts": {round_key: round_artifact},
    }


__all__ = ["build_causal_research_projection"]
