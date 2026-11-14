# src/webpent/causal_reasoning_v2/architecture_graph.py
"""SystemArchitectureGraph — Phase 1 core fix.

A REAL structural model of the target's internal architecture, replacing the
v1 "text fingerprint + route glob" approach.  Nodes are architectural
elements (endpoints, handler functions, middleware, verification functions,
data-access objects, DB tables, auth policies, shared helpers).  Edges are
typed AND ORDERED where order matters (middleware wrap order, call sequence).

Every causal conclusion is DERIVED from graph structure, not looked up in a
hardcoded rule table:

  * verification_order(endpoint, resource) — trace the ordered path from
    endpoint entry to the mutation of a resource; report whether a
    verification node occurs BEFORE, AFTER, or NEVER on that path.
  * shared_flawed_segment(flawed_path) — find the minimal subpath segment
    that carries the flaw, then enumerate ALL other endpoints whose path
    contains that same segment.  These are structural siblings, NOT route-
    glob text matches.
  * common_access_object(endpoints) — do two endpoints share a DAO /
    verifier / fetch helper / error handler?  If yes, a defect in that
    shared object propagates to both.

The graph is built from observations (recon, endpoint discovery, error
signatures, framework conventions) — it is a HYPOTHESISED model, every
edge carries a confidence, and conclusions carry a confidence derived from
the product of edge confidences on the traced path.  No LLM, no network.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable, Mapping


class NodeKind(StrEnum):
    ENDPOINT = "endpoint"
    HANDLER = "handler_function"
    MIDDLEWARE = "middleware"
    VERIFICATION = "verification_function"   # authz/authn/scope check
    VALIDATION = "validation_layer"          # input sanitisation/encoding
    DAO = "data_access_object"
    DB_TABLE = "database_table"
    AUTH_POLICY = "auth_policy"
    ROLE = "role"
    SESSION_MANAGER = "session_manager"
    RENDER_LAYER = "render_layer"
    FETCH_HELPER = "fetch_helper"
    ERROR_HANDLER = "error_handler"
    SERVICE = "service"
    RESOURCE = "resource"


class EdgeKind(StrEnum):
    ROUTES_TO = "routes_to"          # endpoint -> handler
    WRAPS = "wraps"                  # middleware -> handler (ordered by wrap_order)
    CALLS = "calls"                  # function -> function (ordered by call_seq)
    VERIFIES = "verifies"            # verification -> resource/role
    MUTATES = "mutates"              # function/DAO -> db_table/resource
    READS = "reads"                  # function/DAO -> db_table/resource
    USES = "uses"                    # function -> shared object (DAO, verifier, helper)
    ENFORCES = "enforces"            # auth_policy -> endpoint
    HANDLES_ERRORS = "handles_errors"  # error_handler -> endpoint/service


@dataclass(frozen=True)
class ArchNode:
    node_id: str
    kind: NodeKind
    canonical_key: str          # e.g. "POST /api/users/{id}", "UserDAO.update", "JWTVerifier.verify"
    confidence: float = 0.5     # how sure we are this node exists & is correctly typed
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ArchEdge:
    edge_id: str
    kind: EdgeKind
    source: str
    target: str
    confidence: float = 0.5
    order: int = 0              # wrap order / call sequence (0 = first)
    metadata: dict[str, Any] = field(default_factory=dict)


class VerificationVerdict(StrEnum):
    BEFORE_MUTATION = "before_mutation"    # safe on this path
    AFTER_MUTATION = "after_mutation"      # classic TOCTOU / auth-check-after-mutate
    NEVER = "never"                        # no verification on path at all
    DIFFERENT_BRANCH = "different_branch"  # verification exists but not reachable on this path
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PathTrace:
    """Ordered trace from endpoint entry to a resource mutation/read."""
    endpoint_id: str
    resource_id: str
    node_sequence: tuple[str, ...]   # ordered node ids from entry to sink
    edge_sequence: tuple[str, ...]
    path_confidence: float           # product of edge confidences
    mutation_index: int | None       # index in node_sequence where MUTATES occurs
    verification_indices: tuple[int, ...]  # indices where VERIFICATION nodes occur

    @property
    def verdict(self) -> VerificationVerdict:
        if self.mutation_index is None:
            # read path — verification of scope still matters
            if not self.verification_indices:
                return VerificationVerdict.NEVER
            return VerificationVerdict.BEFORE_MUTATION  # any check before read is "before"
        if not self.verification_indices:
            return VerificationVerdict.NEVER
        first_verif = min(self.verification_indices)
        if first_verif < self.mutation_index:
            return VerificationVerdict.BEFORE_MUTATION
        return VerificationVerdict.AFTER_MUTATION


class SystemArchitectureGraph:
    """Hypothesised structural model of the target.  Additive, confidence-scored."""

    def __init__(self) -> None:
        self._nodes: dict[str, ArchNode] = {}
        self._out_edges: dict[str, list[ArchEdge]] = defaultdict(list)
        self._in_edges: dict[str, list[ArchEdge]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    def add_node(self, node_id: str, kind: NodeKind | str, canonical_key: str,
                 confidence: float = 0.5, metadata: Mapping[str, Any] | None = None) -> ArchNode:
        kind = NodeKind(str(kind))
        node = ArchNode(
            node_id=str(node_id)[:200], kind=kind, canonical_key=str(canonical_key)[:320],
            confidence=min(1.0, max(0.0, float(confidence))),
            metadata=dict(metadata or {}),
        )
        self._nodes[node.node_id] = node
        return node

    def add_edge(self, edge_id: str, kind: EdgeKind | str, source: str, target: str,
                 confidence: float = 0.5, order: int = 0,
                 metadata: Mapping[str, Any] | None = None) -> ArchEdge | None:
        if source not in self._nodes or target not in self._nodes:
            return None  # refuse dangling edges — graph stays consistent
        edge = ArchEdge(
            edge_id=str(edge_id)[:200], kind=EdgeKind(str(kind)),
            source=source, target=target,
            confidence=min(1.0, max(0.0, float(confidence))),
            order=int(order), metadata=dict(metadata or {}),
        )
        self._out_edges[source].append(edge)
        self._in_edges[target].append(edge)
        return edge

    def get_node(self, node_id: str) -> ArchNode | None:
        return self._nodes.get(node_id)

    def nodes_of_kind(self, kind: NodeKind | str) -> tuple[ArchNode, ...]:
        k = str(kind)
        return tuple(n for n in self._nodes.values() if n.kind.value == k)

    # ------------------------------------------------------------------
    # Path tracing — ordered walk from endpoint entry to a resource sink
    # ------------------------------------------------------------------
    def execution_order(self, endpoint_id: str, max_depth: int = 16) -> tuple[str, ...]:
        """Flatten the execution flow from an endpoint into an ordered sequence.

        Execution is SEQUENTIAL, not a branching tree:
          endpoint -> middleware[0] -> middleware[1] -> ... -> handler
          -> handler's calls in call order (each recursing into its own calls)
        A verification called later in this sequence is genuinely AFTER any
        mutation that occurred earlier.  This is the critical fix vs v1's
        branching walk: ordered calls are accumulated, not chosen between.
        """
        if endpoint_id not in self._nodes:
            return ()
        seq: list[str] = []
        seen: set[str] = set()

        def visit(node_id: str, depth: int) -> None:
            if depth > max_depth or node_id in seen:
                return
            seen.add(node_id)
            seq.append(node_id)
            node = self._nodes.get(node_id)
            # Middleware: WRAPS edges mean "this middleware wraps target"; from
            # an endpoint, follow ROUTES_TO to handler, and collect WRAPS in
            # order.  From any function node, follow CALLS in order.
            outgoing = sorted(
                [e for e in self._out_edges.get(node_id, [])
                 if e.kind in (EdgeKind.ROUTES_TO, EdgeKind.WRAPS, EdgeKind.CALLS, EdgeKind.USES)],
                key=lambda e: (e.order, e.edge_id),
            )
            for e in outgoing:
                visit(e.target, depth + 1)

        visit(endpoint_id, 0)
        return tuple(seq)

    def trace_paths(self, endpoint_id: str, resource_id: str,
                    max_paths: int = 8, max_depth: int = 12) -> tuple[PathTrace, ...]:
        """Ordered path(s) from an endpoint to a resource (read or mutate).

        Built from the flattened execution_order.  The resource is appended
        at the mutation/read point.  Path confidence = product of edge
        confidences along the sequence (min conservative).
        """
        if endpoint_id not in self._nodes or resource_id not in self._nodes:
            return ()
        seq = self.execution_order(endpoint_id, max_depth=max_depth)
        if not seq:
            return ()
        # Find the earliest node in the sequence that has a READS/MUTATES
        # edge to the resource.
        mutation_index: int | None = None
        path_conf = 1.0
        for i, nid in enumerate(seq):
            for e in self._out_edges.get(nid, []):
                if e.kind in (EdgeKind.READS, EdgeKind.MUTATES) and e.target == resource_id:
                    if mutation_index is None:
                        mutation_index = i  # resource accessed at this point
                        if e.kind == EdgeKind.READS:
                            mutation_index = None  # read path — no mutation ordering
                    path_conf = min(path_conf, e.confidence)
        # Accumulate edge confidences along the sequence.
        for i in range(len(seq) - 1):
            edges_between = [e for e in self._out_edges.get(seq[i], []) if e.target == seq[i + 1]]
            if edges_between:
                path_conf = min(path_conf, max(e.confidence for e in edges_between))
        verif_indices = tuple(
            i for i, nid in enumerate(seq)
            if self._nodes.get(nid) and self._nodes[nid].kind == NodeKind.VERIFICATION
        )
        trace = PathTrace(
            endpoint_id=endpoint_id, resource_id=resource_id,
            node_sequence=(*seq, resource_id),
            edge_sequence=(),
            path_confidence=round(path_conf, 4),
            mutation_index=mutation_index,
            verification_indices=verif_indices,
        )
        return (trace,)

    def verification_verdict(self, endpoint_id: str, resource_id: str) -> tuple[VerificationVerdict, float]:
        """Return the verification verdict + its confidence.

        Uses the flattened execution order, so a verification that exists but
        is called AFTER the mutation is correctly classified as
        AFTER_MUTATION (not NEVER).  Conservative: NEVER if no verification
        node exists anywhere in the flow.
        """
        paths = self.trace_paths(endpoint_id, resource_id)
        if not paths:
            return VerificationVerdict.UNKNOWN, 0.0
        p = paths[0]
        # If a verification node exists in the flow but after mutation -> AFTER.
        if p.mutation_index is not None and p.verification_indices:
            if min(p.verification_indices) > p.mutation_index:
                return VerificationVerdict.AFTER_MUTATION, p.path_confidence
            if min(p.verification_indices) < p.mutation_index:
                return VerificationVerdict.BEFORE_MUTATION, p.path_confidence
            return VerificationVerdict.AFTER_MUTATION, p.path_confidence
        if not p.verification_indices:
            return VerificationVerdict.NEVER, p.path_confidence
        return VerificationVerdict.BEFORE_MUTATION, p.path_confidence

    # ------------------------------------------------------------------
    # Sibling inference — STRUCTURAL, not route-glob text matching
    # ------------------------------------------------------------------
    def flawed_segment_nodes(self, path: PathTrace) -> tuple[str, ...]:
        """Return the ordered node ids that constitute the 'flawed segment'.

        For AFTER_MUTATION: from the mutation point backward to the nearest
        preceding verification (or entry if none) — the unprotected window.
        For NEVER: the entire path from entry to sink.
        For BEFORE_MUTATION: empty (no flaw).
        """
        if path.verdict == VerificationVerdict.BEFORE_MUTATION:
            return ()
        seq = path.node_sequence
        if path.verdict == VerificationVerdict.AFTER_MUTATION and path.verification_indices:
            # window = from first verification (inclusive) through mutation
            first_v = min(path.verification_indices)
            mut = path.mutation_index if path.mutation_index is not None else len(seq) - 1
            return seq[first_v:mut + 1]
        # NEVER — whole path minus endpoint entry and resource sink
        return seq[1:-1] if len(seq) > 2 else seq

    # Node kinds that are SHARED across endpoints (not endpoint-specific).
    # A flawed segment's "shared core" = its nodes of these kinds.  An
    # endpoint is a structural sibling iff it reaches any node in the shared
    # core.  Endpoint-specific nodes (handlers, endpoints) are unique and
    # must NOT be required — requiring them would make sibling detection
    # impossible by construction.
    _SHARED_OBJECT_KINDS = frozenset({
        NodeKind.DAO, NodeKind.VERIFICATION, NodeKind.FETCH_HELPER,
        NodeKind.ERROR_HANDLER, NodeKind.SESSION_MANAGER, NodeKind.VALIDATION,
        NodeKind.MIDDLEWARE, NodeKind.AUTH_POLICY, NodeKind.RENDER_LAYER,
        NodeKind.SERVICE,
    })

    def endpoints_sharing_segment(self, segment_nodes: Iterable[str]) -> tuple[ArchNode, ...]:
        """Find ALL endpoints flowing through the flawed segment's shared core.

        Structural siblings = endpoints whose execution reaches ANY node of
        the segment that is a shared object (DAO, verifier, helper, ...).
        Endpoint-specific nodes (the handler of the finding's own endpoint)
        are excluded from the requirement because by definition no other
        endpoint contains them.  If the segment has no shared-object core,
        fall back to requiring all segment nodes (degenerate case).
        """
        segment = set(segment_nodes)
        if not segment:
            return ()
        shared_core = {
            nid for nid in segment
            if self._nodes.get(nid) and self._nodes[nid].kind in self._SHARED_OBJECT_KINDS
        }
        required = shared_core if shared_core else segment
        siblings: list[ArchNode] = []
        for ep in self.nodes_of_kind(NodeKind.ENDPOINT):
            reachable = self._reachable_set(ep.node_id)
            if required & reachable == required:
                siblings.append(ep)
        return tuple(siblings)

    def _path_contains_all(self, start: str, required: set[str]) -> bool:
        """BFS reachability: can we hit every required node from start (in any order)?"""
        # We check: from start, reach each required node; and required nodes
        # are mutually reachable in a chain (they lie on one flow).
        remaining = set(required)
        cur = start
        while remaining:
            reachable = self._reachable_set(cur)
            hit = remaining & reachable
            if not hit:
                return False
            # pick one (deterministic: sorted) and continue from it
            nxt = sorted(hit)[0]
            remaining.discard(nxt)
            cur = nxt
        return True

    def _reachable_set(self, start: str, max_depth: int = 12) -> set[str]:
        seen: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        traversable = {EdgeKind.ROUTES_TO, EdgeKind.WRAPS, EdgeKind.CALLS, EdgeKind.USES,
                       EdgeKind.READS, EdgeKind.MUTATES}
        while queue:
            cur, depth = queue.popleft()
            if depth > max_depth or cur in seen:
                continue
            seen.add(cur)
            for e in self._out_edges.get(cur, []):
                if e.kind in traversable:
                    queue.append((e.target, depth + 1))
        return seen

    def shared_objects(self, endpoint_a: str, endpoint_b: str) -> tuple[ArchNode, ...]:
        """Shared DAO/verifier/helper/error-handler objects between two endpoints.

        A defect in any shared object propagates to both endpoints — this is
        the second structural sibling criterion (shared-flawed-object).
        """
        shared_kinds = {NodeKind.DAO, NodeKind.VERIFICATION, NodeKind.FETCH_HELPER,
                        NodeKind.ERROR_HANDLER, NodeKind.SESSION_MANAGER, NodeKind.VALIDATION}
        reach_a = self._reachable_set(endpoint_a)
        reach_b = self._reachable_set(endpoint_b)
        common = reach_a & reach_b
        return tuple(
            self._nodes[nid] for nid in sorted(common)
            if nid in self._nodes and self._nodes[nid].kind in shared_kinds
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(v) for v in self._out_edges.values())

    def as_dict(self) -> dict[str, Any]:
        return {
            "nodes": [
                {"node_id": n.node_id, "kind": n.kind.value, "canonical_key": n.canonical_key,
                 "confidence": n.confidence, "metadata": n.metadata}
                for n in self._nodes.values()
            ],
            "edges": [
                {"edge_id": e.edge_id, "kind": e.kind.value, "source": e.source, "target": e.target,
                 "confidence": e.confidence, "order": e.order, "metadata": e.metadata}
                for edges in self._out_edges.values() for e in edges
            ],
        }


__all__ = [
    "SystemArchitectureGraph", "ArchNode", "ArchEdge", "NodeKind", "EdgeKind",
    "PathTrace", "VerificationVerdict",
]
