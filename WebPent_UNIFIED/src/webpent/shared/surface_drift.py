"""webpent.shared.surface_drift — attack surface drift detection.

Project Zero-tier item 4: "continuous diffing — any new endpoint,
parameter, or JS file that appears, the tool knows immediately and
gives it a high scan priority."

Distinct from, and deliberately not duplicating:

  * :mod:`webpent.shared.scope_drift` — detects when a *discovered
    URL's origin* has drifted outside the declared target boundary
    (a scope-authorization concern: "are we still allowed to touch
    this?"). This module detects the opposite direction of change:
    "did the target's OWN surface change between two points in time
    we observed it?" — a coverage/freshness concern, not a scope
    concern. A drifted-in-scope new endpoint is exactly what this
    module exists to flag; a drifted-out-of-scope URL is
    ``scope_drift``'s problem, not this module's.
  * :mod:`webpent.shared.attack_graph` / :mod:`webpent.attack_graph` —
    project a single snapshot of already-collected evidence into a
    graph for relational reasoning. This module consumes TWO such
    snapshots (or, more directly, two
    :class:`~webpent.models.surface_graph.SurfaceEvidenceGraph`
    instances) and diffs them.

Deterministic and pure: no network calls, no LLM. Given a baseline
:class:`SurfaceEvidenceGraph` and a current one, :func:`detect_surface_drift`
returns which nodes are new, which disappeared, and which changed
disposition, each carrying a priority recommendation a caller (the
crawler's queue, the strategist) can act on without re-deriving the
diff itself.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from webpent.models.surface_graph import SurfaceEvidenceGraph, SurfaceNode


class DriftPriority(str, Enum):
    """Scan-priority recommendation for a drifted node.

    A closed, small vocabulary (mirrors ``DecisionType`` /
    ``PostmortemCategory``) so a caller can route on it directly
    rather than parsing free text.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Node types that represent directly-attackable surface (an endpoint
# a payload can hit) get HIGH priority on appearance. Node types that
# are supporting/contextual evidence (a service fingerprint, a browser
# context) get MEDIUM — still worth a fresh look, but not themselves
# an attack target.
_HIGH_PRIORITY_NODE_TYPES = frozenset(
    {
        "endpoint",
        "form",
        "xhr",
        "openapi_route",
        "graphql_operation",
        "multipart_field",
    }
)


@dataclass
class DriftedNode:
    """One node that appeared, disappeared, or changed disposition."""

    node_id: str
    node_type: str
    label: str
    change: str
    """One of ``"appeared"``, ``"disappeared"``, ``"disposition_changed"``."""
    priority: DriftPriority
    previous_disposition: str | None = None
    current_disposition: str | None = None
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "change": self.change,
            "priority": self.priority.value
            if hasattr(self.priority, "value")
            else str(self.priority),
            "previous_disposition": self.previous_disposition,
            "current_disposition": self.current_disposition,
            "reason": self.reason,
        }


@dataclass
class SurfaceDriftReport:
    """Result of diffing two :class:`SurfaceEvidenceGraph` snapshots."""

    baseline_node_count: int
    current_node_count: int
    appeared: list[DriftedNode] = field(default_factory=list)
    disappeared: list[DriftedNode] = field(default_factory=list)
    disposition_changed: list[DriftedNode] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return bool(self.appeared or self.disappeared or self.disposition_changed)

    @property
    def high_priority_nodes(self) -> list[DriftedNode]:
        """All drifted nodes (of any change type) flagged HIGH priority,
        in encounter order — this is the queue a crawler/strategist
        should drain first.
        """
        return [
            node
            for node in (*self.appeared, *self.disappeared, *self.disposition_changed)
            if node.priority == DriftPriority.HIGH
        ]

    def as_dict(self) -> dict[str, Any]:
        return {
            "baseline_node_count": self.baseline_node_count,
            "current_node_count": self.current_node_count,
            "has_drift": self.has_drift,
            "appeared": [n.as_dict() for n in self.appeared],
            "disappeared": [n.as_dict() for n in self.disappeared],
            "disposition_changed": [n.as_dict() for n in self.disposition_changed],
            "high_priority_count": len(self.high_priority_nodes),
        }


def _priority_for_node_type(node_type: str) -> DriftPriority:
    return (
        DriftPriority.HIGH
        if node_type in _HIGH_PRIORITY_NODE_TYPES
        else DriftPriority.MEDIUM
    )


def _index_by_id(nodes: Iterable[SurfaceNode]) -> dict[str, SurfaceNode]:
    return {node.node_id: node for node in nodes}


def detect_surface_drift(
    baseline: SurfaceEvidenceGraph,
    current: SurfaceEvidenceGraph,
) -> SurfaceDriftReport:
    """Diff two Surface Evidence Graph snapshots and recommend priority.

    A node is matched between snapshots by its ``node_id`` (the
    graph's existing deterministic hash of ``node_type|label|method``,
    per ``shared/surface_evidence_graph.py``'s ``_node_id`` helper), so
    "appeared"/"disappeared" naturally means "a genuinely new or
    removed endpoint/form/parameter", not an artifact of re-ordering.

    Args:
        baseline: An earlier snapshot (e.g. yesterday's crawl, or the
            graph state at the start of this engagement).
        current: The latest snapshot.

    Returns:
        A :class:`SurfaceDriftReport`. Newly-appeared attackable
        surface (endpoints, forms, XHR targets, API routes, GraphQL
        operations, multipart fields) is HIGH priority; everything
        else that changed is MEDIUM; nothing in this report is ever
        LOW — a node with no change simply does not appear at all
        (silence is the "unchanged" signal, consistent with this
        graph's passive-evidence posture of never asserting more than
        was observed).
    """
    baseline_by_id = _index_by_id(baseline.nodes)
    current_by_id = _index_by_id(current.nodes)

    appeared: list[DriftedNode] = []
    disappeared: list[DriftedNode] = []
    disposition_changed: list[DriftedNode] = []

    for node_id, node in current_by_id.items():
        if node_id not in baseline_by_id:
            appeared.append(
                DriftedNode(
                    node_id=node_id,
                    node_type=str(node.node_type),
                    label=node.label,
                    change="appeared",
                    priority=_priority_for_node_type(str(node.node_type)),
                    current_disposition=str(node.disposition),
                    reason=(
                        f"New {node.node_type} observed that was not present "
                        "in the baseline snapshot."
                    ),
                )
            )
            continue
        baseline_node = baseline_by_id[node_id]
        if str(baseline_node.disposition) != str(node.disposition):
            disposition_changed.append(
                DriftedNode(
                    node_id=node_id,
                    node_type=str(node.node_type),
                    label=node.label,
                    change="disposition_changed",
                    priority=_priority_for_node_type(str(node.node_type)),
                    previous_disposition=str(baseline_node.disposition),
                    current_disposition=str(node.disposition),
                    reason=(
                        f"Disposition changed from {baseline_node.disposition!s} "
                        f"to {node.disposition!s}."
                    ),
                )
            )

    for node_id, node in baseline_by_id.items():
        if node_id not in current_by_id:
            disappeared.append(
                DriftedNode(
                    node_id=node_id,
                    node_type=str(node.node_type),
                    label=node.label,
                    change="disappeared",
                    # A disappeared HIGH-priority surface is itself
                    # worth a fresh look (did it move? get retired? get
                    # hidden behind new auth?) so it keeps its type's
                    # base priority rather than being downgraded to LOW.
                    priority=_priority_for_node_type(str(node.node_type)),
                    previous_disposition=str(node.disposition),
                    reason=(
                        f"{node.node_type} present in the baseline snapshot "
                        "is no longer observed in the current snapshot."
                    ),
                )
            )

    return SurfaceDriftReport(
        baseline_node_count=len(baseline.nodes),
        current_node_count=len(current.nodes),
        appeared=appeared,
        disappeared=disappeared,
        disposition_changed=disposition_changed,
    )


__all__ = [
    "DriftedNode",
    "DriftPriority",
    "SurfaceDriftReport",
    "detect_surface_drift",
]
