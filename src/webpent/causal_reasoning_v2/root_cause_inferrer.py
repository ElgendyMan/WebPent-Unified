# src/webpent/causal_reasoning_v2/root_cause_inferrer.py
"""RootCauseInferrer — Phase 1, structural causal inference.

Given a confirmed finding + the SystemArchitectureGraph, DERIVE the root
cause from graph structure rather than looking it up in a hardcoded table.

Steps for one finding:
  1. Locate the finding's endpoint node and the resource it touched.
  2. Trace ordered paths endpoint -> resource.  Compute the verification
     verdict (BEFORE/AFTER/NEVER) and the flawed segment.
  3. Identify shared objects on the flawed path (DAO, verifier, helper,
     error handler, validation layer).  A defect in a SHARED object is the
     strongest form of root cause because it propagates.
  4. Classify the causal relation DYNAMICALLY from the structural evidence:
       - path verdict NEVER + resource is object-by-id -> scope_leak_no_verification
       - path verdict AFTER_MUTATION -> verification_ordering_defect
       - input reaches sink without passing a VALIDATION node -> validation_bypass
       - shared object X is used and X is known-defective from a prior
         corroborated finding -> shared_object_defect(X)
       - multiple endpoints share the flawed segment -> systemic_layer_defect
     (The taxonomy is open; new labels are derived, not pre-enumerated.)
  5. Enumerate structural siblings: endpoints sharing the flawed segment
     OR sharing a defective shared object.  These are the "probe next"
     regions.  Confidence = path_confidence × shared_object_confidence.

This replaces v1's 12 hardcoded (vuln_class -> weakness) rules with a
single structural inference procedure that generalises to architectures
never seen before.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from webpent.causal_reasoning_v2.architecture_graph import (
    ArchNode,
    EdgeKind,
    NodeKind,
    PathTrace,
    SystemArchitectureGraph,
    VerificationVerdict,
)


def _normalize_route(raw: str) -> str:
    """Normalize a route for matching: strip method/query, replace {param}
    and numeric/uuid segments with '*'.  Deterministic."""
    import re
    text = str(raw or "").strip()
    if not text:
        return ""
    # strip scheme/host
    if "://" in text:
        text = text.split("://", 1)[1]
        text = text.split("/", 1)[1] if "/" in text else ""
        text = "/" + text
    # strip method prefix
    text = re.sub(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+", "", text, flags=re.IGNORECASE)
    # strip query/fragment
    text = text.split("?", 1)[0].split("#", 1)[0]
    # replace {var}, :var, numeric, uuid segments with *
    segments = [s for s in text.split("/") if s]
    out = []
    uuid_re = re.compile(r"^[0-9a-fA-F-]{8,}$")
    for s in segments:
        if re.match(r"^\{.*\}$", s) or s.startswith(":") or s.isdigit() or uuid_re.match(s):
            out.append("*")
        else:
            out.append(s.lower())
    return "/" + "/".join(out)


@dataclass(frozen=True)
class CausalConclusionV2:
    """A structurally-derived root-cause conclusion for one finding."""
    finding_id: str
    endpoint_id: str
    resource_id: str | None
    causal_label: str                    # dynamically derived, open taxonomy
    rationale: str
    confidence: float                    # 0..1, derived from path × object confidence
    flawed_segment: tuple[str, ...]      # node ids constituting the flawed segment
    shared_defective_objects: tuple[str, ...]  # node ids of shared objects on the segment
    sibling_endpoint_ids: tuple[str, ...]      # structural siblings (same segment OR same defective object)
    verdict: VerificationVerdict


@dataclass(frozen=True)
class RootCauseClusterV2:
    """Findings grouped by shared causal root (same flawed segment / object)."""
    cluster_id: str
    causal_label: str
    flawed_segment: tuple[str, ...]
    shared_object: str | None
    member_finding_ids: tuple[str, ...]
    sibling_endpoint_ids: tuple[str, ...]   # union — probe these next
    confidence: float
    remediation_hint: str


# Remediation hints keyed by structural causal pattern (derived labels map to these).
_REMEDIATION: dict[str, str] = {
    "verification_ordering_defect":
        "Move the verification check before any mutation on the affected path. "
        "Enforce ordering in middleware/decorator, not per-handler. Audit every "
        "handler sharing the flawed call sequence.",
    "scope_leak_no_verification":
        "Introduce a scope check in the shared object-resolver/DAO so every "
        "object lookup is bounded to the caller's identity. Fix in the resolver "
        "once; all endpoints using it inherit the fix.",
    "validation_bypass":
        "Route all input through the shared validation layer before it reaches "
        "the sink. Remove per-route ad-hoc sanitisation. Add a contract test "
        "asserting every sink is reachable only through the validation node.",
    "shared_object_defect":
        "Fix the defective shared object (verifier/DAO/helper/error handler). "
        "One fix remediates every endpoint that uses it. Add a regression test "
        "at the object's boundary.",
    "systemic_layer_defect":
        "The defect is in a shared architectural layer. Replace/repair the "
        "layer and re-run full coverage on every endpoint flowing through it. "
        "Do not patch endpoints individually.",
    "error_handling_leak":
        "Replace the global error handler with one that returns generic "
        "messages to clients and logs details server-side. Map all exception "
        "paths to the safe handler.",
    "unverifiable_structure":
        "Graph confidence too low to localise the root cause. Improve the "
        "architecture model (more recon) before drawing causal conclusions.",
}


def _remediation_for(label: str) -> str:
    for key, hint in _REMEDIATION.items():
        if label.startswith(key):
            return hint
    return (
        f"Root cause pattern '{label}' derived structurally. Inspect the flawed "
        "segment and repair at the shared layer, not at individual endpoints."
    )[:600]


@dataclass
class RootCauseInferrer:
    """Structural root-cause inference.  Stateless; holds thresholds only."""

    min_path_confidence: float = 0.3
    sibling_confidence_floor: float = 0.25

    def infer(
        self,
        finding: Mapping[str, Any],
        graph: SystemArchitectureGraph,
        *,
        endpoint_id: str | None = None,
        resource_id: str | None = None,
        known_defective_objects: Iterable[str] = (),
    ) -> CausalConclusionV2 | None:
        """Derive root cause for one finding from graph structure.

        Returns None if the graph cannot localise the finding (low
        confidence) — the caller then falls back to v1-style heuristic
        propagation, never to a fabricated causal claim.
        """
        finding_id = str(finding.get("id") or finding.get("finding_id") or "unknown")[:200]
        known_defective = set(known_defective_objects)

        # Resolve endpoint + resource nodes.
        ep = self._resolve_endpoint(finding, graph, endpoint_id)
        if ep is None:
            return None
        res = self._resolve_resource(finding, graph, resource_id)

        # Trace paths.
        if res is not None:
            paths = graph.trace_paths(ep.node_id, res.node_id)
        else:
            paths = ()
        if not paths:
            # No path to a specific resource — examine the endpoint's reachable
            # shared objects for known-defective ones.
            shared = self._reachable_shared_objects(ep.node_id, graph)
            defective_hits = [n.node_id for n in shared if n.node_id in known_defective]
            if defective_hits:
                label = f"shared_object_defect:{defective_hits[0]}"
                siblings = self._siblings_via_object(defective_hits[0], graph)
                return CausalConclusionV2(
                    finding_id=finding_id, endpoint_id=ep.node_id, resource_id=None,
                    causal_label=label,
                    rationale=(
                        f"Endpoint {ep.canonical_key} uses shared object "
                        f"{defective_hits[0]} already corroborated as defective. "
                        "The finding is explained by that shared defect."
                    ),
                    confidence=0.7, flawed_segment=(),
                    shared_defective_objects=tuple(defective_hits),
                    sibling_endpoint_ids=tuple(s.node_id for s in siblings),
                    verdict=VerificationVerdict.UNKNOWN,
                )
            return None

        best_path = paths[0]
        verdict, verdict_conf = graph.verification_verdict(ep.node_id, res.node_id)
        flawed_segment = graph.flawed_segment_nodes(best_path)

        # Shared objects ON the flawed segment.
        segment_objects = [
            nid for nid in flawed_segment
            if graph.get_node(nid) and graph.get_node(nid).kind in {
                NodeKind.DAO, NodeKind.VERIFICATION, NodeKind.FETCH_HELPER,
                NodeKind.ERROR_HANDLER, NodeKind.SESSION_MANAGER, NodeKind.VALIDATION,
            }
        ]
        defective_on_segment = [nid for nid in segment_objects if nid in known_defective]

        # Dynamic causal classification from structure.
        label, rationale, conf = self._classify(
            verdict=verdict, verdict_conf=verdict_conf,
            path_conf=best_path.path_confidence,
            has_validation_on_path=self._passes_validation(best_path, graph),
            defective_on_segment=defective_on_segment,
            resource_kind=res.kind,
        )
        if conf < self.min_path_confidence:
            label = "unverifiable_structure"
            conf = 0.2

        # Structural siblings: endpoints sharing the flawed segment OR sharing
        # a defective object.  Union, dedupe, exclude the finding's own endpoint.
        siblings: set[str] = set()
        if flawed_segment:
            for s in graph.endpoints_sharing_segment(flawed_segment):
                siblings.add(s.node_id)
        for obj_id in defective_on_segment:
            for s in self._siblings_via_object(obj_id, graph):
                siblings.add(s.node_id)
        siblings.discard(ep.node_id)

        return CausalConclusionV2(
            finding_id=finding_id, endpoint_id=ep.node_id, resource_id=res.node_id,
            causal_label=label, rationale=rationale, confidence=round(conf, 4),
            flawed_segment=flawed_segment,
            shared_defective_objects=tuple(defective_on_segment),
            sibling_endpoint_ids=tuple(sorted(siblings)),
            verdict=verdict,
        )

    # ------------------------------------------------------------------
    # Clustering: group findings by shared causal root
    # ------------------------------------------------------------------
    def cluster(
        self,
        conclusions: Iterable[CausalConclusionV2],
        graph: SystemArchitectureGraph,
    ) -> tuple[RootCauseClusterV2, ...]:
        """Group conclusions by (flawed_segment) or (shared defective object).

        Two findings share a root cause iff their flawed segments overlap on
        a shared object, OR they name the same defective object.  This is
        structural equivalence, not vuln-class equality.
        """
        clusters: dict[str, list[CausalConclusionV2]] = {}
        key_for: dict[str, str] = {}
        # Shared-object kinds — the cluster key is built from the SHARED CORE
        # of the flawed segment, not endpoint-specific handler nodes (which
        # are unique per endpoint and would prevent any clustering).
        shared_kinds = {"data_access_object", "verification_function", "fetch_helper",
                        "error_handler", "session_manager", "validation_layer",
                        "middleware", "auth_policy", "render_layer", "service"}
        for c in conclusions:
            if c.causal_label == "unverifiable_structure":
                key = "unverifiable"
            elif c.shared_defective_objects:
                key = f"obj:{c.shared_defective_objects[0]}"
            else:
                # Shared core = flawed segment nodes that are shared objects.
                core = sorted(nid for nid in c.flawed_segment
                              if graph.get_node(nid) and graph.get_node(nid).kind.value in shared_kinds)
                if core:
                    key = "core:" + ",".join(core[:6])
                elif c.flawed_segment:
                    key = "seg:" + ",".join(sorted(c.flawed_segment)[:6])
                else:
                    key = f"label:{c.causal_label}"
            key_for[c.finding_id] = key
            clusters.setdefault(key, []).append(c)

        result: list[RootCauseClusterV2] = []
        for key, members in clusters.items():
            segment_union: set[str] = set()
            siblings_union: set[str] = set()
            shared_obj = None
            for m in members:
                segment_union.update(m.flawed_segment)
                siblings_union.update(m.sibling_endpoint_ids)
                if m.shared_defective_objects and shared_obj is None:
                    shared_obj = m.shared_defective_objects[0]
            label = members[0].causal_label.split(":")[0]
            conf = max(m.confidence for m in members)
            result.append(RootCauseClusterV2(
                cluster_id=f"rccv2:{key}",
                causal_label=label,
                flawed_segment=tuple(sorted(segment_union))[:32],
                shared_object=shared_obj,
                member_finding_ids=tuple(sorted(m.finding_id for m in members)),
                sibling_endpoint_ids=tuple(sorted(siblings_union))[:256],
                confidence=round(conf, 4),
                remediation_hint=_remediation_for(label),
            ))
        result.sort(key=lambda c: (len(c.member_finding_ids) * c.confidence), reverse=True)
        return tuple(result)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _resolve_endpoint(self, finding: Mapping[str, Any], graph: SystemArchitectureGraph,
                          hint: str | None) -> ArchNode | None:
        if hint and graph.get_node(hint):
            return graph.get_node(hint)
        route = str(finding.get("route") or finding.get("url") or "")
        norm_route = _normalize_route(route)
        # Match by normalized route (strip method, replace params/numeric ids).
        candidates = []
        for n in graph.nodes_of_kind(NodeKind.ENDPOINT):
            norm_canon = _normalize_route(n.canonical_key)
            if norm_route and (norm_route == norm_canon or norm_route.startswith(norm_canon) or norm_canon.startswith(norm_route)):
                candidates.append(n)
        if not candidates:
            # Fallback: substring match on raw strings.
            candidates = [
                n for n in graph.nodes_of_kind(NodeKind.ENDPOINT)
                if route and (route in n.canonical_key or n.canonical_key in route)
            ]
        if not candidates:
            return None
        candidates.sort(key=lambda n: n.confidence, reverse=True)
        return candidates[0]

    def _resolve_resource(self, finding: Mapping[str, Any], graph: SystemArchitectureGraph,
                          hint: str | None) -> ArchNode | None:
        if hint and graph.get_node(hint):
            return graph.get_node(hint)
        # Heuristic: the resource touched is a DB_TABLE or RESOURCE reachable
        # from the endpoint with the highest confidence.
        ep = self._resolve_endpoint(finding, graph, None)
        if ep is None:
            return None
        reachable = graph._reachable_set(ep.node_id)
        resources = [
            graph.get_node(nid) for nid in reachable
            if graph.get_node(nid) and graph.get_node(nid).kind in (NodeKind.DB_TABLE, NodeKind.RESOURCE)
        ]
        if not resources:
            return None
        resources.sort(key=lambda n: n.confidence, reverse=True)
        return resources[0]

    def _reachable_shared_objects(self, endpoint_id: str, graph: SystemArchitectureGraph) -> tuple[ArchNode, ...]:
        reachable = graph._reachable_set(endpoint_id)
        kinds = {NodeKind.DAO, NodeKind.VERIFICATION, NodeKind.FETCH_HELPER,
                 NodeKind.ERROR_HANDLER, NodeKind.SESSION_MANAGER, NodeKind.VALIDATION}
        return tuple(graph.get_node(n) for n in sorted(reachable)
                     if graph.get_node(n) and graph.get_node(n).kind in kinds)

    def _siblings_via_object(self, object_id: str, graph: SystemArchitectureGraph) -> tuple[ArchNode, ...]:
        """Endpoints that USE the given shared object."""
        sibs: list[ArchNode] = []
        for ep in graph.nodes_of_kind(NodeKind.ENDPOINT):
            if object_id in graph._reachable_set(ep.node_id):
                sibs.append(ep)
        return tuple(sibs)

    def _passes_validation(self, path: PathTrace, graph: SystemArchitectureGraph) -> bool:
        return any(
            graph.get_node(nid) and graph.get_node(nid).kind == NodeKind.VALIDATION
            for nid in path.node_sequence
        )

    def _classify(
        self, *, verdict: VerificationVerdict, verdict_conf: float, path_conf: float,
        has_validation_on_path: bool, defective_on_segment: list[str],
        resource_kind: NodeKind,
    ) -> tuple[str, str, float]:
        """Dynamically derive causal label + rationale + confidence."""
        base_conf = min(verdict_conf, path_conf)
        if defective_on_segment:
            obj = defective_on_segment[0]
            return (
                f"shared_object_defect:{obj}",
                f"The flawed path traverses shared object {obj}, which is already "
                "corroborated as defective. Root cause localised to that object.",
                min(1.0, base_conf + 0.2),
            )
        if verdict == VerificationVerdict.AFTER_MUTATION:
            return (
                "verification_ordering_defect",
                "On the traced path, a verification node occurs AFTER the resource "
                "mutation (TOCTOU-style ordering defect). Any handler with the same "
                "call ordering shares the root cause.",
                base_conf,
            )
        if verdict == VerificationVerdict.NEVER:
            if resource_kind in (NodeKind.DB_TABLE, NodeKind.RESOURCE):
                return (
                    "scope_leak_no_verification",
                    "No verification node occurs on the path to a scoped resource. "
                    "Object resolution is unbounded by caller identity on this flow.",
                    base_conf,
                )
            return (
                "scope_leak_no_verification",
                "No verification node occurs on this path.",
                base_conf * 0.8,
            )
        if not has_validation_on_path:
            return (
                "validation_bypass",
                "Input reaches the sink without passing through any VALIDATION "
                "node. Sanitisation is absent on this flow (not merely inconsistent).",
                base_conf * 0.9,
            )
        if verdict == VerificationVerdict.BEFORE_MUTATION:
            return (
                "systemic_layer_defect",
                "Verification exists and is correctly ordered, yet the finding "
                "occurred — the defect is likely in a shared layer whose logic "
                "is wrong (correct placement, wrong enforcement).",
                base_conf * 0.6,
            )
        return ("unverifiable_structure", "Structure insufficient to localise root cause.", 0.2)


__all__ = ["RootCauseInferrer", "CausalConclusionV2", "RootCauseClusterV2"]
