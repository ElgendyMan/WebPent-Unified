"""UM-DR-32 §5 — Alias and Alternate Representation Resolution.

Related to Object Identity (§4) but a distinct problem: object identity
describes the underlying RESOURCE; alias resolution discovers HOW the
application exposes that resource through different routes, parameters
and response representations (§5.1).

Contract:

  * candidates are created ONLY from evidence actually observed in the
    authorized engagement — no fabricated endpoints or object ids (§5.2);
  * explicit, reversible relationship states (§5.3): a confirmed alias
    always retains source representation, alternate representation,
    shared object identity, supporting evidence, decision method,
    confidence and the reason competing interpretations were rejected;
  * security-aware matching (§5.4): different tenants, different
    resource types, same-id-different-object, similar slugs, similar
    names, distinct-resource query variants, collections vs items and
    parent vs child are NEVER confused. String similarity may OPEN a
    candidate but can never confirm equivalence;
  * ambiguity and abstention are supported outcomes, not failures.

The resolved graph feeds stateful discovery (§5.5): linked observations,
cross-representation differentials when security-relevant, and redundant
identity-assumption avoidance — an alternate endpoint is a security
hypothesis ONLY when an observed identity or authorization boundary
supports a testable question.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from webpent.production.object_identity import (
    IdentityEvidence,
    ObjectIdentityRegistry,
    ResourceObservation,
    _looks_like_identifier,
    _object_id_from_path,
    _resource_type_from_path,
)

__all__ = [
    "AliasResolver",
    "AliasState",
    "RepresentationRelationship",
    "alias_graph_from_observations",
]


class AliasState(str, Enum):
    """§5.3 — explicit, reversible relationship states."""

    CONFIRMED_SAME_OBJECT = "confirmed_same_object"
    HIGH_CONFIDENCE_CANDIDATE = "high_confidence_candidate"
    POSSIBLE_ALTERNATE = "possible_alternate"
    RELATED_DISTINCT = "related_distinct"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    UNKNOWN = "unknown"


@dataclass
class RepresentationRelationship:
    """One resolved (or candidate) alias relationship (§5.3).

    Reversible by construction: nothing is unioned or destroyed; the
    record always carries both sides, the evidence, the method and the
    rejected interpretations.
    """

    source_repr: str
    alternate_repr: str
    state: AliasState
    shared_object_identity: str = ""   # identity_id when confirmed
    evidence: list[IdentityEvidence] = field(default_factory=list)
    decision_method: str = ""
    confidence: float = 0.0
    rejected_interpretations: list[str] = field(default_factory=list)

    def key(self) -> tuple[str, str]:
        a, b = sorted((self.source_repr, self.alternate_repr))
        return (a, b)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source_repr,
            "alternate": self.alternate_repr,
            "state": self.state.value,
            "shared_object_identity": self.shared_object_identity,
            "evidence": [e.as_dict() for e in self.evidence],
            "decision_method": self.decision_method,
            "confidence": round(self.confidence, 3),
            "rejected_interpretations": list(self.rejected_interpretations),
        }


def _query_identity(path: str) -> str:
    """The query string is identity-significant (UM-DR-31.1 F10/F11):
    ``?account=1`` and ``?account=2`` are different resources."""
    return path.split("?", 1)[1] if "?" in path else ""


def _same_path_different_query(a: str, b: str) -> bool:
    return (
        a.split("?", 1)[0] == b.split("?", 1)[0]
        and _query_identity(a) != _query_identity(b)
    )


class AliasResolver:
    """Deterministic, evidence-backed alias resolution over observations.

    The resolver never mutates the identity registry: alias decisions
    are REVERSIBLE overlays on top of it.
    """

    def __init__(self, registry: ObjectIdentityRegistry) -> None:
        self.registry = registry
        self._relationships: dict[tuple[str, str], RepresentationRelationship] = {}

    # -- candidate discovery (§5.2) ----------------------------------------

    @staticmethod
    def candidate_pairs(
        observations: list[ResourceObservation],
        *,
        max_pairs: int = 500,
    ) -> list[tuple[ResourceObservation, ResourceObservation]]:
        """Evidence-only candidate generation.

        A pair becomes a candidate when at least ONE structural signal
        is present (all from observed data, none fabricated):

          C1  two paths share the same object id in the final segment;
          C2  a Location/canonical evidence item names the other path;
          C3  an api_resource_reference evidence item names the other
              resource;
          C4  slug-form vs id-form paths whose resource types match and
              whose body evidence carries the same object id;
          C5  collection path that is the parent of an item path (the
              collection REPRESENTS the set; the item is a member).
        """
        by_endpoint: dict[str, ResourceObservation] = {}
        for obs in observations:
            if obs.endpoint:
                by_endpoint.setdefault(obs.endpoint, obs)
        endpoints = sorted(by_endpoint)
        pairs: list[tuple[ResourceObservation, ResourceObservation]] = []
        seen: set[tuple[str, str]] = set()

        def _add(a: str, b: str, ) -> None:
            if a == b:
                return
            key = tuple(sorted((a, b)))
            if key in seen:
                return
            seen.add(key)
            left, right = by_endpoint.get(key[0]), by_endpoint.get(key[1])
            if left and right and len(pairs) < max_pairs:
                pairs.append((left, right))

        # C1: same terminal object id
        by_id: dict[str, list[str]] = {}
        for ep in endpoints:
            obj_id, _src = _object_id_from_path(ep)
            if obj_id:
                by_id.setdefault(obj_id, []).append(ep)
        for obj_id, eps in sorted(by_id.items()):
            if len(eps) > 1:
                for i in range(len(eps)):
                    for j in range(i + 1, len(eps)):
                        _add(eps[i], eps[j])

        # C2/C3: evidence-named references
        for ep in endpoints:
            obs = by_endpoint[ep]
            for ev in obs.evidence:
                if ev.kind in {"location_header", "canonical_link"}:
                    target = ev.value
                    for other in endpoints:
                        if other.split("?")[0].endswith(
                            target.split("?")[0].rstrip("/")
                        ) and target.split("?")[0].rstrip("/"):
                            _add(ep, other)
                elif ev.kind == "api_resource_reference":
                    # references carry "type:id"; pair with same-type paths
                    _type, _, _id = ev.value.partition(":")
                    if _id:
                        for other in endpoints:
                            other_id, _ = _object_id_from_path(other)
                            other_type = _resource_type_from_path(other)
                            if other_id == _id and (
                                not _type or other_type == _type.lower()
                            ):
                                _add(ep, other)

        # C4: slug-form vs id-form under the same resource type with
        # matching in-body object ids (body evidence required)
        body_ids: dict[str, list[str]] = {}
        for ep in endpoints:
            obs = by_endpoint[ep]
            if obs.object_id_source == "response_body" and obs.object_id:
                body_ids.setdefault(obs.object_id, []).append(ep)
        for eps in body_ids.values():
            if len(eps) > 1:
                for i in range(len(eps)):
                    for j in range(i + 1, len(eps)):
                        _add(eps[i], eps[j])

        # C5: collection -> item (parent path exactly one segment above)
        for ep in endpoints:
            base = ep.split("?", 1)[0].rstrip("/")
            for other in endpoints:
                obase = other.split("?", 1)[0].rstrip("/")
                if base and obase != base and obase.startswith(base + "/"):
                    tail = obase[len(base) + 1:]
                    if "/" not in tail and _looks_like_identifier(tail):
                        _add(ep, other)
        return pairs

    # -- classification (§5.3/§5.4) ----------------------------------------

    def classify_pair(
        self,
        left: ResourceObservation,
        right: ResourceObservation,
    ) -> RepresentationRelationship:
        """Classify one candidate pair. Deterministic; never merges the
        registry; string similarity alone can never confirm."""
        rejected: list[str] = []
        lpath, rpath = left.endpoint, right.endpoint

        # security-aware guards FIRST (§5.4)
        if left.tenant and right.tenant and left.tenant != right.tenant:
            return self._record(RepresentationRelationship(
                source_repr=lpath, alternate_repr=rpath,
                state=AliasState.RELATED_DISTINCT,
                evidence=list(left.evidence) + list(right.evidence),
                decision_method="tenant_boundary",
                confidence=0.95,
                rejected_interpretations=[
                    "alias_rejected:cross_tenant — never merged without tenant evidence"],
            ))
        if left.resource_type and right.resource_type and \
                left.resource_type != right.resource_type:
            return self._record(RepresentationRelationship(
                source_repr=lpath, alternate_repr=rpath,
                state=AliasState.RELATED_DISTINCT,
                evidence=list(left.evidence) + list(right.evidence),
                decision_method="resource_type_boundary",
                confidence=0.9,
                rejected_interpretations=[
                    f"alias_rejected:different_resource_type "
                    f"({left.resource_type} vs {right.resource_type})"],
            ))
        if _same_path_different_query(lpath, rpath):
            # query values encode DISTINCT resources (F10/F11): distinct
            # unless a body-equality observation proves otherwise
            if not (
                left.object_id_source == "response_body"
                and right.object_id_source == "response_body"
                and left.object_id == right.object_id
            ):
                return self._record(RepresentationRelationship(
                    source_repr=lpath, alternate_repr=rpath,
                    state=AliasState.RELATED_DISTINCT,
                    evidence=list(left.evidence) + list(right.evidence),
                    decision_method="query_identity_preserved",
                    confidence=0.9,
                    rejected_interpretations=[
                        "alias_rejected:distinct_query_values — query params "
                        "are identity-significant (UM-DR-31.1 F10)"],
                ))
            rejected.append("query_distinctness overridden by equal in-body object ids")

        # the identity registry already decided the underlying relationship
        identity_rel = self.registry.relate(left, right)
        left_ident = self.registry.identity_for_endpoint(lpath)
        right_ident = self.registry.identity_for_endpoint(rpath)
        shared_id = ""
        if (
            left_ident is not None and right_ident is not None
            and left_ident.identity_id == right_ident.identity_id
        ):
            shared_id = left_ident.identity_id

        # classification ladder
        if identity_rel.kind.value == "alternate_representation":
            state = AliasState.CONFIRMED_SAME_OBJECT
            conf = 0.9
            method = "registry:anchor_equality+corroboration"
        elif identity_rel.kind.value == "same_object":
            state = AliasState.HIGH_CONFIDENCE_CANDIDATE
            conf = 0.7
            method = "registry:anchor_equality (no corroboration — candidate, not confirmed)"
            rejected.append(
                "confirmation_rejected:missing_corroborating_evidence")
        elif identity_rel.kind.value == "ambiguous_identity":
            state = AliasState.POSSIBLE_ALTERNATE
            conf = 0.3
            method = "registry:abstention — evidence insufficient"
        elif identity_rel.kind.value == "related_object":
            state = AliasState.RELATED_DISTINCT
            conf = identity_rel.confidence
            method = "registry:related_but_distinct"
        else:
            state = AliasState.CONFLICTING_EVIDENCE if (
                identity_rel.note.startswith("conflicting")
            ) else AliasState.UNKNOWN
            conf = 0.2
            method = "registry:unresolved"

        return self._record(RepresentationRelationship(
            source_repr=lpath, alternate_repr=rpath,
            state=state,
            shared_object_identity=shared_id if state in (
                AliasState.CONFIRMED_SAME_OBJECT,
                AliasState.HIGH_CONFIDENCE_CANDIDATE,
            ) else "",
            evidence=list(identity_rel.evidence) or (
                list(left.evidence) + list(right.evidence)),
            decision_method=method,
            confidence=conf,
            rejected_interpretations=[
                *rejected, f"registry_note:{identity_rel.note}",
            ] if identity_rel.note else rejected,
        ))

    def _record(self, rel: RepresentationRelationship) -> RepresentationRelationship:
        key = rel.key()
        existing = self._relationships.get(key)
        if existing is not None and existing.state != rel.state:
            # preserve the conflict instead of overwriting (reversible)
            self._relationships[key] = RepresentationRelationship(
                source_repr=rel.source_repr,
                alternate_repr=rel.alternate_repr,
                state=AliasState.CONFLICTING_EVIDENCE,
                evidence=list(rel.evidence) + list(existing.evidence),
                decision_method="conflict_preserved:"
                                f"{existing.decision_method}|{rel.decision_method}",
                confidence=0.2,
                rejected_interpretations=[
                    f"prior_state:{existing.state.value}",
                    *rel.rejected_interpretations],
            )
            return self._relationships[key]
        self._relationships[key] = rel
        return rel

    # -- public API ---------------------------------------------------------

    def resolve(
        self, observations: list[ResourceObservation],
        *, max_pairs: int = 500,
    ) -> list[RepresentationRelationship]:
        pairs = self.candidate_pairs(observations, max_pairs=max_pairs)
        for left, right in pairs:
            self.classify_pair(left, right)
        return self.relationships()

    def relationships(self) -> list[RepresentationRelationship]:
        return [self._relationships[k] for k in sorted(self._relationships)]

    def confirmed(self) -> list[RepresentationRelationship]:
        return [
            r for r in self._relationships.values()
            if r.state is AliasState.CONFIRMED_SAME_OBJECT
        ]

    def stats(self) -> dict[str, Any]:
        by_state: dict[str, int] = {}
        for rel in self._relationships.values():
            by_state[rel.state.value] = by_state.get(rel.state.value, 0) + 1
        return {
            "pairs_classified": len(self._relationships),
            "by_state": dict(sorted(by_state.items())),
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "relationships": [r.as_dict() for r in self.relationships()],
            "stats": self.stats(),
        }


def alias_graph_from_observations(
    observations: list[ResourceObservation],
    registry: ObjectIdentityRegistry,
) -> AliasResolver:
    """Convenience: ingest observations into the registry, then resolve
    the alias overlay over the same observation set."""
    for obs in observations:
        registry.ingest(obs)
    resolver = AliasResolver(registry)
    resolver.resolve(observations)
    return resolver
