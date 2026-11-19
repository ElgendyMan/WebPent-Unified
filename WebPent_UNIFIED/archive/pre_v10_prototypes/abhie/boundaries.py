"""Security boundary mapping for bounded research."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from itertools import combinations
from typing import Any

from .contracts import BoundaryCrossing, BoundaryNode, SecurityBoundaryGraph


def _get(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


class SecurityBoundaryMapper:
    NODE_KINDS = ("user", "role", "resource", "action", "workflow", "trust", "state")

    def map(
        self,
        *,
        target_ref: str,
        users: Iterable[Any] = (),
        roles: Iterable[Any] = (),
        resources: Iterable[Any] = (),
        actions: Iterable[Any] = (),
        workflows: Iterable[Any] = (),
        trust_levels: Iterable[Any] = (),
        states: Iterable[Any] = (),
    ) -> SecurityBoundaryGraph:
        raw = (
            ("user", users),
            ("role", roles),
            ("resource", resources),
            ("action", actions),
            ("workflow", workflows),
            ("trust", trust_levels),
            ("state", states),
        )
        nodes: list[BoundaryNode] = []
        for kind, values in raw:
            for index, value in enumerate(values):
                node_id = str(_get(value, "id", _get(value, "name", f"{kind}-{index}")))
                label = str(_get(value, "label", _get(value, "name", node_id)))
                trust = str(_get(value, "trust_level", _get(value, "level", "unknown")))
                nodes.append(
                    BoundaryNode(
                        node_id=f"{kind}:{node_id}", kind=kind, label=label, trust_level=trust
                    )
                )
        if not nodes:
            nodes = [
                BoundaryNode("user:unknown", "user", "unknown user"),
                BoundaryNode("resource:unknown", "resource", "unknown resource"),
            ]
        nodes = sorted(
            {node.node_id: node for node in nodes}.values(), key=lambda node: node.node_id
        )
        by_kind = {
            kind: tuple(node for node in nodes if node.kind == kind) for kind in self.NODE_KINDS
        }
        pairs = (
            ("user", "role", "user may enter role boundary"),
            ("role", "resource", "role may access resource boundary"),
            ("resource", "action", "resource may trigger sensitive action"),
            ("workflow", "state", "workflow may cross state boundary"),
            ("trust", "resource", "trust level may cross resource boundary"),
        )
        crossings: list[BoundaryCrossing] = []
        for index, (left, right, condition) in enumerate(pairs):
            for source, destination in combinations(by_kind[left] + by_kind[right], 2):
                if source.kind == right and destination.kind == left:
                    source, destination = destination, source
                if source.kind != left or destination.kind != right:
                    continue
                crossings.append(
                    BoundaryCrossing(
                        crossing_id=f"crossing-{index}-{len(crossings)}",
                        source_node=source.node_id,
                        destination_node=destination.node_id,
                        condition=condition,
                        opportunity=(
                            f"research whether {source.label} can cross into "
                            f"{destination.label}"
                        ),
                    )
                )
        crossings = sorted(crossings, key=lambda item: item.crossing_id)[:64]
        canonical = (
            "|".join(f"{node.node_id}:{node.kind}:{node.label}" for node in nodes)
            + "||"
            + "|".join(
                f"{item.source_node}>{item.destination_node}:{item.condition}" for item in crossings
            )
        )
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return SecurityBoundaryGraph(
            target_ref=target_ref, nodes=tuple(nodes), crossings=tuple(crossings), digest=digest
        )

    def dangerous_crossings(self, graph: SecurityBoundaryGraph) -> tuple[BoundaryCrossing, ...]:
        markers = ("admin", "tenant", "owner", "approved", "external")
        return tuple(
            crossing
            for crossing in graph.crossings
            if any(
                marker in crossing.condition.lower() or marker in crossing.opportunity.lower()
                for marker in markers
            )
        )
