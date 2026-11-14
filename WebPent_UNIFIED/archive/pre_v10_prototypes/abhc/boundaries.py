"""Security-boundary reasoning for ABHC v3."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .contracts import BoundaryCandidate, SecurityBoundaryMap


class SecurityBoundaryReasoner:
    """Build a fail-closed map of modeled authorization boundaries."""

    def map_boundaries(
        self,
        *,
        attack_graph: object | None = None,
        world_model: object | None = None,
        hypotheses: Sequence[object] = (),
    ) -> SecurityBoundaryMap:
        boundaries: dict[str, BoundaryCandidate] = {}
        for edge in self._items(attack_graph, "edges"):
            kind = self._text(edge, "kind", default="relationship").lower()
            source = self._text(edge, "source_id", "source", default="source")
            target = self._text(edge, "target_id", "target", default="target")
            if not self._is_boundary(kind, source, target):
                continue
            refs = self._refs(edge)
            boundary_type = self._boundary_type(kind, source, target)
            identifier = self._text(edge, "id", "edge_id", default=f"{source}->{target}")
            boundaries[identifier] = BoundaryCandidate(
                boundary_id=f"boundary:{identifier}",
                boundary_type=boundary_type,
                source_node=source,
                target_node=target,
                security_question=f"Does {boundary_type} hold between {source} and {target}?",
                evidence_refs=refs,
                confidence=self._confidence(edge),
            )
        for hypothesis in hypotheses:
            area = self._text(hypothesis, "target_area", default="unknown")
            assumption = self._text(
                hypothesis, "security_assumption", default="boundary is enforced"
            )
            identifier = f"hypothesis:{area}"
            boundaries.setdefault(
                identifier,
                BoundaryCandidate(
                    boundary_id=f"boundary:{area}",
                    boundary_type=self._boundary_type_from_assumption(assumption),
                    source_node=area,
                    target_node="protected-operation",
                    security_question=assumption,
                    evidence_refs=self._refs(hypothesis),
                    confidence=self._confidence(hypothesis),
                ),
            )
        unresolved = tuple(
            sorted(
                {
                    item.security_question
                    for item in boundaries.values()
                    if item.confidence < 0.65 or not item.evidence_refs
                }
            )
        )
        return SecurityBoundaryMap(
            boundaries=tuple(sorted(boundaries.values(), key=lambda item: item.boundary_id)),
            unresolved_questions=unresolved,
        )

    @staticmethod
    def _items(value: object | None, name: str) -> tuple[object, ...]:
        if value is None:
            return ()
        candidate = value.get(name, ()) if isinstance(value, Mapping) else getattr(value, name, ())
        if isinstance(candidate, Mapping):
            return tuple(candidate.values())
        if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes)):
            return tuple(candidate)
        return ()

    @staticmethod
    def _text(item: object, *names: str, default: str = "") -> str:
        for name in names:
            value = item.get(name) if isinstance(item, Mapping) else getattr(item, name, None)
            if value is not None:
                return str(value)
        return default

    @staticmethod
    def _refs(item: object) -> tuple[str, ...]:
        value = (
            item.get("evidence_refs", ())
            if isinstance(item, Mapping)
            else getattr(item, "evidence_refs", ())
        )
        if not value:
            value = (
                item.get("source_refs", ())
                if isinstance(item, Mapping)
                else getattr(item, "source_refs", ())
            )
        return tuple(dict.fromkeys(str(ref).strip() for ref in value if str(ref).strip()))[:32]

    @classmethod
    def _confidence(cls, item: object) -> float:
        raw = (
            item.get("confidence")
            if isinstance(item, Mapping)
            else getattr(item, "confidence", 0.0)
        )
        if isinstance(raw, (int, float)):
            return max(0.0, min(1.0, float(raw)))
        return {"high": 0.9, "medium": 0.65, "observed": 0.65}.get(str(raw).lower(), 0.35)

    @classmethod
    def _is_boundary(cls, kind: str, source: str, target: str) -> bool:
        tokens = f"{kind} {source} {target}".lower()
        return any(
            token in tokens
            for token in (
                "permission",
                "privilege",
                "identity",
                "owner",
                "tenant",
                "state",
                "role",
                "authorize",
            )
        )

    @staticmethod
    def _boundary_type(kind: str, source: str, target: str) -> str:
        tokens = f"{kind} {source} {target}".lower()
        if "tenant" in tokens:
            return "tenant_to_tenant"
        if "owner" in tokens or "object" in tokens:
            return "owner_to_non_owner"
        if "state" in tokens or "workflow" in tokens:
            return "draft_to_approved"
        if "admin" in tokens or "privilege" in tokens or "role" in tokens:
            return "user_to_admin"
        return "identity_to_protected_operation"

    @staticmethod
    def _boundary_type_from_assumption(assumption: str) -> str:
        text = assumption.lower()
        if "tenant" in text:
            return "tenant_to_tenant"
        if "owner" in text or "object" in text:
            return "owner_to_non_owner"
        if "workflow" in text or "state" in text:
            return "draft_to_approved"
        return "identity_to_protected_operation"


__all__ = ["SecurityBoundaryReasoner"]
