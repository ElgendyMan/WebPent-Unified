# src/webpent/causal_reasoning_v2/integration_layer.py
"""CausalIntegrationLayer — Phase 3: actual, safe integration hooks.

Three hooks, callable from the existing LangGraph pipeline WITHOUT modifying
any existing file (the graph builder can import and call these at the three
natural points).  Every hook is fail-safe: on ANY exception it returns an
empty/neutral result and logs the failure, so the existing pipeline behaves
exactly as before if the causal engine is unavailable, misconfigured, or
disabled.

Hook shapes match the ACTUAL models in this codebase:
  * input  Finding  (webpent.models.findings.Finding) — fields: id, url,
    route, request_method, target_param, vuln_class, severity, confidence.
  * input  state["target_knowledge"] (TargetKnowledgeModel) — nodes and edges;
    the older ``target_knowledge_v2`` entities/relations shape is also accepted.
  * output list[dict] shaped like Hypothesis (webpent.models.hypothesis.Hypothesis)
    — fields: target_url, statement, vuln_class, status, confidence_score,
    origin, origin_detail, request_method, target_param, hint_provenance,
    novelty_score. Downstream can validate each dict with
    ``Hypothesis.model_validate(dict)``.
  * output clusters shaped for the report's "root cause" section.

Disabling: set env var WEBPENT_CAUSAL_V2_DISABLED=1 and every hook returns
immediately with neutral results — identical to pre-causal behavior.
"""
from __future__ import annotations

import os
import traceback
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from webpent.causal_reasoning_v2.architecture_graph import (
    EdgeKind,
    NodeKind,
    SystemArchitectureGraph,
)
from webpent.causal_reasoning_v2.contextual_memory_v2 import (
    BehaviorProfile,
    ContextualMemoryV2,
)
from webpent.causal_reasoning_v2.root_cause_inferrer import (
    CausalConclusionV2,
    RootCauseClusterV2,
    RootCauseInferrer,
)

_DISABLED = os.environ.get("WEBPENT_CAUSAL_V2_DISABLED", "").strip() in ("1", "true", "yes")


def _hypothesis_dict(
    *, target_url: str, statement: str, vuln_class: str = "unknown",
    confidence_score: float = 0.5, origin_detail: str = "",
    origin: str = "heuristic",
    request_method: str = "GET", target_param: str | None = None,
    hint_provenance: Iterable[str] = (), novelty_score: float = 0.8,
) -> dict[str, Any]:
    """Build a dict that validates against webpent.models.hypothesis.Hypothesis."""
    return {
        "target_url": str(target_url)[:2000],
        "statement": str(statement)[:500],
        "vuln_class": str(vuln_class)[:60],
        "status": "unexplored",
        "confidence_score": round(min(1.0, max(0.0, float(confidence_score))), 4),
        # Causal provenance lives in origin_detail/hint_provenance. Keep
        # origin within the existing HypothesisOrigin enum so the existing
        # model and reducer accept this additive advisory hypothesis.
        "origin": origin,
        "origin_detail": str(origin_detail)[:200],
        "estimated_cost": None,
        "parent_hypothesis_id": None,
        "deterministic_match": True,
        "request_method": str(request_method)[:10].upper(),
        "request_data": {},
        "target_param": str(target_param)[:200] if target_param else None,
        "evidence_contract": None,
        "hint_provenance": [str(h)[:120] for h in hint_provenance][:8],
        "novelty_score": round(min(1.0, max(0.0, float(novelty_score))), 4),
    }


@dataclass
class CausalIntegrationLayer:
    """Three fail-safe hooks.  Holds per-engagement state (graph, memory)."""

    engagement_id: str = "unknown"
    memory_dir: str | None = None
    acceptance_threshold: float = 0.75
    disabled: bool = field(default_factory=lambda: _DISABLED)

    def __post_init__(self) -> None:
        self._graph = SystemArchitectureGraph()
        self._inferrer = RootCauseInferrer()
        self._memory: ContextualMemoryV2 | None = None
        self._conclusions: list[CausalConclusionV2] = []
        self._known_defective: set[str] = set()
        self._failures: list[str] = []

    # ------------------------------------------------------------------
    # Graph construction from existing state (TargetKnowledgeV2 + recon)
    # ------------------------------------------------------------------
    def build_graph_from_state(self, state: Mapping[str, Any]) -> SystemArchitectureGraph:
        """Populate the architecture graph from existing state.

        Reads the current project's ``state["target_knowledge"]`` projection
        (nodes + edges), while retaining compatibility with the older
        ``target_knowledge_v2`` (entities + relations) shape. Best-effort:
        missing data just yields a sparser graph, never an error.
        """
        g = self._graph
        try:
            tk = state.get("target_knowledge_v2")
            if tk is None:
                tk = state.get("target_knowledge")
            entities = {}
            if tk is not None:
                # Legacy TargetKnowledgeV2 object or current TargetKnowledgeModel.
                if hasattr(tk, "entities"):
                    entities = {eid: e for eid, e in tk.entities.items()}
                elif hasattr(tk, "nodes"):
                    entities = {eid: e for eid, e in tk.nodes.items()}
                elif isinstance(tk, Mapping):
                    entities = tk.get("entities") or tk.get("nodes", {})
            for eid, ent in entities.items():
                kind = getattr(ent, "kind", None)
                if kind is None and isinstance(ent, Mapping):
                    kind = ent.get("kind")
                kind = getattr(kind, "value", kind) or "endpoint"
                canon = str(getattr(ent, "canonical_key", None) or (ent.get("canonical_key") if isinstance(ent, Mapping) else eid))
                conf = float(getattr(ent, "confidence", 0.5) or (ent.get("confidence", 0.5) if isinstance(ent, Mapping) else 0.5))
                # Map knowledge entity kinds to architecture node kinds.
                node_kind = _map_kind(kind)
                g.add_node(str(eid), node_kind, canon, confidence=conf)
            # Relations -> edges (best-effort type mapping)
            relations = []
            if tk is not None:
                if hasattr(tk, "relations"):
                    relations = list(tk.relations)
                elif hasattr(tk, "edges"):
                    relations = list(tk.edges)
                elif isinstance(tk, Mapping):
                    relations = tk.get("relations") or tk.get("edges", [])
            for i, rel in enumerate(relations):
                src = (
                    getattr(rel, "source_entity", None)
                    or getattr(rel, "source_id", None)
                    or (rel.get("source_entity") or rel.get("source_id") if isinstance(rel, Mapping) else None)
                )
                tgt = (
                    getattr(rel, "target_entity", None)
                    or getattr(rel, "target_id", None)
                    or (rel.get("target_entity") or rel.get("target_id") if isinstance(rel, Mapping) else None)
                )
                rkind = str(getattr(rel, "relation", None) or (rel.get("relation") if isinstance(rel, Mapping) else "related"))
                if isinstance(rel, Mapping):
                    rkind = str(rel.get("relation") or rel.get("kind") or rkind)
                if src and tgt:
                    g.add_edge(f"ke:{i}", _map_edge(rkind), str(src), str(tgt), confidence=0.4, order=i)
        except Exception:
            self._failures.append(f"build_graph:{traceback.format_exc(limit=1)[:200]}")
        return g

    # ------------------------------------------------------------------
    # Hook 1 — engagement start: transfer insights from past engagements
    # ------------------------------------------------------------------
    def on_engagement_start(self, state: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Return transferred-insight hypotheses to prepend to the planner queue.

        Safe: returns [] on any failure or when disabled / no prior data.
        Never surfaces patterns below acceptance_threshold.
        """
        if self.disabled:
            return []
        try:
            profile = _behavior_profile_from_state(self.engagement_id, state)
            if self._memory is None:
                self._memory = ContextualMemoryV2(
                    memory_dir=__import__("pathlib").Path(self.memory_dir) if self.memory_dir else None,
                    acceptance_threshold=self.acceptance_threshold,
                )
            insights = self._memory.transfer_insights(profile)
            hyps: list[dict[str, Any]] = []
            for ins in insights:
                hyps.append(_hypothesis_dict(
                    target_url=_target_url_from_state(state),
                    statement=(
                        f"[transferred] Past behaviorally-analogous engagements confirm "
                        f"causal pattern '{ins.causal_label}' (conf={ins.confidence}, "
                        f"n={ins.sample_size}). Probe segments: {', '.join(ins.typical_segments[:4])}."
                    ),
                    vuln_class="unknown",
                    confidence_score=ins.confidence,
                    origin="rag_informed",
                    origin_detail=f"transferred from {len(ins.source_engagement_ids)} past engagements",
                    hint_provenance=[f"causal_v2_transfer:{ins.pattern_id}"],
                    novelty_score=0.9,
                ))
            return hyps
        except Exception:
            self._failures.append(f"on_start:{traceback.format_exc(limit=1)[:200]}")
            return []

    # ------------------------------------------------------------------
    # Hook 2 — after a confirmed finding: infer structural siblings
    # ------------------------------------------------------------------
    def on_finding_confirmed(self, finding: Mapping[str, Any], state: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Return sibling-probe hypotheses derived structurally from one finding.

        Safe: returns [] on any failure.  Siblings are endpoints sharing the
        flawed architectural segment OR a defective shared object — NOT
        route-glob text matches.  Confidence is derived from path confidence.
        """
        if self.disabled:
            return []
        try:
            graph = self.build_graph_from_state(state)
            conclusion = self._inferrer.infer(
                finding, graph, known_defective_objects=self._known_defective,
            )
            if conclusion is None:
                return []
            self._conclusions.append(conclusion)
            if conclusion.confidence < self._inferrer.min_path_confidence:
                return []  # too weak to act on
            # If a shared defective object was identified, mark it.
            for obj in conclusion.shared_defective_objects:
                self._known_defective.add(obj)
            hyps: list[dict[str, Any]] = []
            for sib_id in conclusion.sibling_endpoint_ids[:12]:
                node = graph.get_node(sib_id)
                if node is None:
                    continue
                hyps.append(_hypothesis_dict(
                    target_url=node.canonical_key if node.canonical_key.startswith("http") else f"https://target{node.canonical_key}",
                    statement=(
                        f"[causal sibling] Shares flawed segment with finding "
                        f"{str(finding.get('id',''))[:8]}… (root cause: "
                        f"{conclusion.causal_label}, conf={conclusion.confidence})."
                    ),
                    vuln_class=str(finding.get("vuln_class", "unknown")),
                    confidence_score=round(conclusion.confidence * 0.9, 4),
                    origin_detail=f"sibling_of:{str(finding.get('id',''))[:16]}|{conclusion.causal_label}",
                    target_param=finding.get("target_param"),
                    hint_provenance=[f"causal_v2_sibling:{conclusion.finding_id}"],
                    novelty_score=0.95,
                ))
            return hyps
        except Exception:
            self._failures.append(f"on_finding:{traceback.format_exc(limit=1)[:200]}")
            return []

    # ------------------------------------------------------------------
    # Hook 3 — before report finalize: root-cause clusters for the report
    # ------------------------------------------------------------------
    def on_report_finalize(self, findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Return root-cause cluster dicts for the report's 'Root Cause Analysis' section.

        Safe: returns [] on any failure.  Also records the engagement's
        confirmed causal labels into the observation store (learning).
        """
        if self.disabled:
            return []
        try:
            clusters = self._inferrer.cluster(self._conclusions, self._graph)
            out: list[dict[str, Any]] = []
            confirmed_labels: dict[str, list[str]] = {}
            for c in clusters:
                out.append({
                    "cluster_id": c.cluster_id,
                    "causal_label": c.causal_label,
                    "shared_object": c.shared_object,
                    "flawed_segment": list(c.flawed_segment),
                    "member_finding_ids": list(c.member_finding_ids),
                    "sibling_endpoints_to_probe_next": list(c.sibling_endpoint_ids),
                    "confidence": c.confidence,
                    "remediation_hint": c.remediation_hint,
                })
                confirmed_labels.setdefault(c.causal_label, []).extend(c.flawed_segment)
            # Learning: persist observation for future engagements.
            if self._memory is not None and confirmed_labels:
                profile = BehaviorProfile(profile_id=f"prof:{self.engagement_id}", engagement_id=self.engagement_id)
                self._memory.record_observation(
                    profile, confirmed_causal_labels=confirmed_labels,
                    total_findings=len(list(findings)),
                )
            return out
        except Exception:
            self._failures.append(f"on_report:{traceback.format_exc(limit=1)[:200]}")
            return []

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    @property
    def failures(self) -> tuple[str, ...]:
        return tuple(self._failures)

    @property
    def conclusion_count(self) -> int:
        return len(self._conclusions)


# ---------------------------------------------------------------------------
# Kind mapping helpers (best-effort, additive)
# ---------------------------------------------------------------------------

_KIND_MAP = {
    "endpoint": NodeKind.ENDPOINT, "application": NodeKind.SERVICE,
    "service": NodeKind.SERVICE, "role": NodeKind.ROLE,
    "permission": NodeKind.AUTH_POLICY, "security_control": NodeKind.VERIFICATION,
    "trust_boundary": NodeKind.MIDDLEWARE, "data_flow": NodeKind.DAO,
    "workflow": NodeKind.HANDLER, "resource": NodeKind.RESOURCE,
    "object": NodeKind.RESOURCE, "parameter": NodeKind.VALIDATION,
    "identity": NodeKind.ROLE, "user": NodeKind.ROLE,
}


def _map_kind(knowledge_kind: str) -> NodeKind:
    return _KIND_MAP.get(str(knowledge_kind).strip().lower(), NodeKind.ENDPOINT)


def _map_edge(relation: str) -> EdgeKind:
    r = str(relation).strip().lower()
    if any(w in r for w in ("auth", "permission", "enforce", "scope")):
        return EdgeKind.ENFORCES
    if any(w in r for w in ("read", "write", "mutate", "access", "query")):
        return EdgeKind.READS
    if any(w in r for w in ("call", "invoke", "flow", "route")):
        return EdgeKind.CALLS
    return EdgeKind.USES


def _behavior_profile_from_state(engagement_id: str, state: Mapping[str, Any]) -> BehaviorProfile:
    """Derive a BehaviorProfile from recon signals in state.  Best-effort."""
    values: dict[str, str] = {}
    recon = (
        state.get("recon_signals")
        or state.get("target_package")
        or state.get("target_understanding")
        or {}
    )
    if isinstance(recon, Mapping):
        values = {
            "auth_flow_type": str(recon.get("auth_flow_type", "unknown")),
            "verification_placement": str(recon.get("verification_placement", "unknown")),
            "error_handling_style": str(recon.get("error_handling_style", "unknown")),
            "data_binding_style": str(recon.get("data_binding_style", "unknown")),
            "session_management": str(recon.get("session_management", "unknown")),
            "object_resolution": str(recon.get("object_resolution", "unknown")),
            "input_validation": str(recon.get("input_validation", "unknown")),
            "query_construction": str(recon.get("query_construction", "unknown")),
        }
    return BehaviorProfile(profile_id=f"prof:{engagement_id}", engagement_id=engagement_id, values=values)


def _target_url_from_state(state: Mapping[str, Any]) -> str:
    """Read the real Target model's ``url`` or mapping-shaped URL safely."""
    target = state.get("target")
    if isinstance(target, Mapping):
        value = target.get("url") or target.get("base_url")
    else:
        value = getattr(target, "url", None) or getattr(target, "base_url", None)
    return str(value or "https://target/")[:2000]


__all__ = ["CausalIntegrationLayer", "_hypothesis_dict"]
