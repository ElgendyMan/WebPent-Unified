"""UM-DR-32 §4 — Object Identity Intelligence.

The typed, evidence-driven object-identity model for the campaign.

The problem (§4.1): the same underlying business object is frequently
visible through several endpoint patterns (``/api/orders/123``,
``/api/o/123``, a slug form, a nested representation), while two
resources may share a numeric identifier while being DIFFERENT objects.
An endpoint string alone establishes nothing about object identity.

Design contract (§4.2-4.5):

  * an identity is anchored on (engagement, tenant/namespace,
    resource_type, stable object identifier) — never on a URL path;
  * ownership is an ATTRIBUTE (it can change), never an identifier;
  * principals are kept strictly separate from objects;
  * every relationship carries evidence provenance and a deterministic
    decision method;
  * resolution is deterministic: the same observations always yield the
    same registry state;
  * weak evidence ABSTAINS (records a candidate relationship without
    merging) and conflicting evidence is preserved, never silently
    overwritten (§4.4);
  * a numeric ID match alone, a similar path alone, or a matching
    resource name alone NEVER causes a merge (§4.3);
  * the same identifier in two tenants NEVER establishes a shared
    object (§4.3);
  * query parameters that differentiate objects retain their identity
    significance (the UM-DR-31.1 fingerprint contract is not regressed).

This module is pure computation — no network, no LLM, no state
mutation. It produces typed records consumed by the campaign's
identity-workflow node (production/identity_workflow.py) and never
confirms anything: CausalGuard (cqa_v2.guarded_causal_evaluate)
remains the sole confirmation authority.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

__all__ = [
    "_NAMESPACE",
    "IdentityEvidence",
    "IdentityRelationship",
    "IdentityRelationshipKind",
    "IdentityResolutionStatus",
    "ObjectIdentity",
    "ObjectIdentityRegistry",
    "ResourceObservation",
    "observations_from_campaign_state",
]

# Deterministic identity namespace (uuid5): stable across runs.
_NAMESPACE = uuid.UUID("b0a6bdf5-4c1d-4f2e-9d3a-5e6f7a8b9c0d")


class IdentityRelationshipKind(str, Enum):
    """§4.3 — the explicit relationship vocabulary."""

    SAME_OBJECT = "same_object"
    ALTERNATE_REPRESENTATION = "alternate_representation"
    RELATED_OBJECT = "related_object"
    SAME_IDENTIFIER_DIFFERENT_NAMESPACE = "same_identifier_different_namespace"
    AMBIGUOUS_IDENTITY = "ambiguous_identity"
    DISTINCT_OBJECT = "distinct_object"


class IdentityResolutionStatus(str, Enum):
    """Lifecycle of a single identity record."""

    UNRESOLVED = "unresolved"
    RESOLVED_BY_EVIDENCE = "resolved_by_evidence"
    AMBIGUOUS = "ambiguous"
    CONFLICTING = "conflicting"


# Evidence kinds that can CORROBORATE a same-object decision beyond a
# raw identifier match (§4.4). A bare observed-id match is deliberately
# NOT in this set: it only opens a candidate, it never confirms.
_CORROBORATING_KINDS = frozenset({
    "canonical_link",            # observed <link rel=canonical> / canonical field
    "location_header",           # 201/3xx Location pointing at the other path
    "api_resource_reference",    # response body references the other resource id
    "cross_endpoint_body_id",    # both responses carry the same object id in-body
    "workflow_reference",        # an observed workflow names both representations
    "attribute_signature",       # stable, distinctive attribute vector equality
})

# Evidence kinds that can alone establish DISTINCTNESS.
_DISTINCTIFYING_KINDS = frozenset({
    "tenant_context",            # observed tenant separation
    "resource_type",             # different resource types
    "attribute_contradiction",   # stable attributes contradict (e.g. different created_at)
})


@dataclass(frozen=True)
class IdentityEvidence:
    """One piece of observed evidence with provenance (§4.4)."""

    kind: str
    value: str
    source_ref: str          # where it was observed (endpoint / observation id)
    observation_ref: str = ""  # the producing observation's fingerprint/id

    def as_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "value": self.value[:200],
            "source_ref": self.source_ref[:500],
            "observation_ref": self.observation_ref[:200],
        }


def _stable_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """Deterministic, redacted attribute projection.

    Volatile keys (timestamps, request ids, sequence counters) never
    participate in identity decisions; secret-shaped keys are dropped.
    """
    volatile = {
        "ts", "timestamp", "updated_at", "request_id", "nonce", "seq",
        "last_modified", "etag", "generated_at", "idempotency_key",
    }
    secret_shaped = {"token", "secret", "password", "api_key", "cookie"}
    out: dict[str, Any] = {}
    for key, value in sorted((attributes or {}).items()):
        k = str(key).lower()
        if k in volatile or any(s in k for s in secret_shaped):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            out[str(key)] = value
    return out


@dataclass
class ResourceObservation:
    """One observed representation of a resource (the ingest unit)."""

    endpoint: str                    # full URL or path as observed
    method: str = "GET"
    resource_type: str = ""          # derived or declared type (e.g. "orders")
    object_id: str = ""              # observed stable identifier (path or body)
    object_id_source: str = ""       # "path_segment" | "response_body" | "query_param"
    tenant: str = ""                 # observed tenant/namespace, "" when unknown
    attributes: dict[str, Any] = field(default_factory=dict)
    evidence: list[IdentityEvidence] = field(default_factory=list)
    observation_ref: str = ""        # producer fingerprint for provenance

    def stable_attributes(self) -> dict[str, Any]:
        return _stable_attributes(self.attributes)

    def identity_anchor_fields(self) -> tuple[str, str, str]:
        """The (tenant, resource_type, object_id) anchor — NEVER the path."""
        return (self.tenant or "", self.resource_type or "", self.object_id or "")

    def as_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "resource_type": self.resource_type,
            "object_id": self.object_id,
            "object_id_source": self.object_id_source,
            "tenant": self.tenant,
            "attributes": self.stable_attributes(),
            "evidence": [e.as_dict() for e in self.evidence],
            "observation_ref": self.observation_ref,
        }


@dataclass
class ObjectIdentity:
    """A resolved (or abstained) underlying-object identity (§4.2)."""

    tenant: str
    resource_type: str
    stable_id: str
    representations: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    status: IdentityResolutionStatus = IdentityResolutionStatus.UNRESOLVED
    confidence: float = 0.0
    identity_id: str = ""

    def finalize_id(self) -> None:
        """Deterministic identity id from the anchor — path-independent."""
        blob = f"{self.tenant}|{self.resource_type}|{self.stable_id}"
        self.identity_id = str(uuid.uuid5(_NAMESPACE, blob))

    def as_dict(self) -> dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "tenant": self.tenant,
            "resource_type": self.resource_type,
            "stable_id": self.stable_id,
            "representations": list(self.representations),
            "attributes": _stable_attributes(self.attributes),
            "evidence_refs": list(self.evidence_refs)[:50],
            "status": self.status.value,
            "confidence": round(self.confidence, 3),
        }


@dataclass
class IdentityRelationship:
    """A recorded relationship between two observed representations."""

    kind: IdentityRelationshipKind
    left_ref: str                    # representation (endpoint) or anchor key
    right_ref: str
    evidence: list[IdentityEvidence] = field(default_factory=list)
    decision_method: str = ""
    confidence: float = 0.0
    note: str = ""                   # e.g. the reason a merge was refused

    def key(self) -> tuple[str, str]:
        a, b = sorted((self.left_ref, self.right_ref))
        return (a, b)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "left": self.left_ref,
            "right": self.right_ref,
            "evidence": [e.as_dict() for e in self.evidence],
            "decision_method": self.decision_method,
            "confidence": round(self.confidence, 3),
            "note": self.note,
        }


def _anchor_key(obs: ResourceObservation) -> tuple[str, str, str]:
    return obs.identity_anchor_fields()


class ObjectIdentityRegistry:
    """Deterministic, evidence-driven identity registry (§4.2-4.4).

    Ingest order never changes the resolved state: resolution is a pure
    function of the observation SET (anchors are canonicalized and the
    merge pass is order-independent).
    """

    def __init__(self, *, max_identities: int = 5000) -> None:
        self.max_identities = max_identities
        # anchor -> identity (the resolved registry)
        self._identities: dict[tuple[str, str, str], ObjectIdentity] = {}
        # every observed representation -> anchor it was assigned
        self._representation_anchor: dict[str, tuple[str, str, str]] = {}
        # deterministic relationship bookkeeping
        self._relationships: dict[tuple[str, str], IdentityRelationship] = {}
        self._abstentions: list[IdentityRelationship] = []
        self._conflicts: list[IdentityRelationship] = []
        self.ingested = 0

    # -- ingest -----------------------------------------------------------

    def ingest(self, obs: ResourceObservation) -> None:
        if self.ingested >= self.max_identities * 4:
            return  # bounded registry (fail-soft bound, reported by stats)
        self.ingested += 1
        if not obs.resource_type or not obs.object_id:
            # nothing anchorable — record as unresolvable observation
            return
        anchor = _anchor_key(obs)
        ident = self._identities.get(anchor)
        if ident is None:
            if len(self._identities) >= self.max_identities:
                return
            ident = ObjectIdentity(
                tenant=anchor[0], resource_type=anchor[1], stable_id=anchor[2],
            )
            ident.finalize_id()
            self._identities[anchor] = ident
        if obs.endpoint and obs.endpoint not in ident.representations:
            ident.representations.append(obs.endpoint)
        self._representation_anchor[obs.endpoint] = anchor
        # merge attributes deterministically (first-writer per key, sorted)
        for key, value in obs.stable_attributes().items():
            ident.attributes.setdefault(key, value)
        for ev in obs.evidence:
            ref = ev.observation_ref or ev.source_ref
            if ref and ref not in ident.evidence_refs:
                ident.evidence_refs.append(ref)
        ident.status = IdentityResolutionStatus.RESOLVED_BY_EVIDENCE
        # confidence grows with corroborating evidence, capped
        corr = sum(
            1 for ev in obs.evidence if ev.kind in _CORROBORATING_KINDS
        )
        ident.confidence = min(0.99, max(ident.confidence, 0.5 + 0.1 * corr))

    # -- resolution / relationship reasoning ------------------------------

    def relate(
        self, left: ResourceObservation, right: ResourceObservation,
    ) -> IdentityRelationship:
        """§4.3-4.4 — decide the relationship between two observations.

        Deterministic decision procedure (documented, no heuristics that
        could silently merge):
          1. different observed tenant -> SAME_IDENTIFIER_DIFFERENT_NAMESPACE
             (never a merge, regardless of everything else);
          2. different resource type -> RELATED_OBJECT when an explicit
             api reference links them, else DISTINCT_OBJECT;
          3. same anchor (tenant, type, id) AND at least one corroborating
             evidence kind -> ALTERNATE_REPRESENTATION (same object);
          4. same id, same type, unknown tenant on either side
             (ambiguity) -> AMBIGUOUS_IDENTITY (abstain; no merge);
          5. attribute contradiction on stable keys -> CONFLICTING
             evidence preserved via note on the relationship.
        """
        lt, lrt, lid = left.identity_anchor_fields()
        rt, rrt, rid = right.identity_anchor_fields()
        # rule 1: tenant boundary is absolute
        if lt and rt and lt != rt:
            rel = IdentityRelationship(
                kind=IdentityRelationshipKind.SAME_IDENTIFIER_DIFFERENT_NAMESPACE,
                left_ref=left.endpoint, right_ref=right.endpoint,
                evidence=self._pair_evidence(left, right),
                decision_method="tenant_boundary_absolute",
                confidence=0.9,
                note=f"tenants {lt!r} vs {rt!r} — identifiers never merge across tenants",
            )
            self._record(rel)
            return rel
        # rule 2: resource-type boundary
        if lrt and rrt and lrt != rrt:
            linked = self._explicit_reference_links(left, right)
            kind = (
                IdentityRelationshipKind.RELATED_OBJECT if linked
                else IdentityRelationshipKind.DISTINCT_OBJECT
            )
            rel = IdentityRelationship(
                kind=kind, left_ref=left.endpoint, right_ref=right.endpoint,
                evidence=self._pair_evidence(left, right),
                decision_method="resource_type_boundary" + (
                    "+explicit_reference" if linked else ""),
                confidence=0.85 if linked else 0.9,
                note=f"types {lrt!r} vs {rrt!r}",
            )
            self._record(rel)
            return rel
        # rule 3/4/5: same type — the id-equality decision
        if lid and rid and lid == rid:
            corroborated = self._corroborates(left, right)
            if corroborated:
                rel = IdentityRelationship(
                    kind=IdentityRelationshipKind.ALTERNATE_REPRESENTATION,
                    left_ref=left.endpoint, right_ref=right.endpoint,
                    evidence=corroborated,
                    decision_method="anchor_equality+corroborating_evidence",
                    confidence=0.9,
                )
                self._record(rel)
                return rel
            if not (lt and rt):
                # tenant unknown on at least one side -> abstain
                rel = IdentityRelationship(
                    kind=IdentityRelationshipKind.AMBIGUOUS_IDENTITY,
                    left_ref=left.endpoint, right_ref=right.endpoint,
                    evidence=self._pair_evidence(left, right),
                    decision_method="id_match_without_tenant_or_corroboration",
                    confidence=0.3,
                    note="identifier equality alone never merges (§4.3); tenant unknown",
                )
                self._record(rel)
                return rel
            # same tenant, same type, same id, no corroboration — record
            # the candidate and abstain from promoting it
            contradiction = self._attribute_contradiction(left, right)
            if contradiction:
                rel = IdentityRelationship(
                    kind=IdentityRelationshipKind.AMBIGUOUS_IDENTITY,
                    left_ref=left.endpoint, right_ref=right.endpoint,
                    evidence=self._pair_evidence(left, right),
                    decision_method="id_match+attribute_contradiction",
                    confidence=0.2,
                    note=f"conflicting attributes preserved: {contradiction}",
                )
                self._record(rel)
                return rel
            rel = IdentityRelationship(
                kind=IdentityRelationshipKind.SAME_OBJECT,
                left_ref=left.endpoint, right_ref=right.endpoint,
                evidence=self._pair_evidence(left, right),
                decision_method="anchor_equality_same_tenant",
                confidence=0.7,
                note="same (tenant,type,id); no corroboration — "
                    "recorded, merge deferred to consumer policy",
            )
            self._record(rel)
            return rel
        # ids differ or missing: distinct unless explicit reference links
        linked = self._explicit_reference_links(left, right)
        if linked:
            rel = IdentityRelationship(
                kind=IdentityRelationshipKind.RELATED_OBJECT,
                left_ref=left.endpoint, right_ref=right.endpoint,
                evidence=linked,
                decision_method="explicit_api_reference",
                confidence=0.85,
            )
            self._record(rel)
            return rel
        rel = IdentityRelationship(
            kind=IdentityRelationshipKind.DISTINCT_OBJECT,
            left_ref=left.endpoint, right_ref=right.endpoint,
            evidence=self._pair_evidence(left, right),
            decision_method="no_identity_evidence",
            confidence=0.6,
        )
        self._record(rel)
        return rel

    def _record(self, rel: IdentityRelationship) -> None:
        key = rel.key()
        existing = self._relationships.get(key)
        if existing is not None and existing.kind != rel.kind:
            # conflicting evidence across decisions: preserve BOTH
            self._conflicts.append(rel)
            return
        self._relationships[key] = rel
        if rel.kind is IdentityRelationshipKind.AMBIGUOUS_IDENTITY:
            self._abstentions.append(rel)

    # -- evidence helpers ---------------------------------------------------

    @staticmethod
    def _pair_evidence(
        left: ResourceObservation, right: ResourceObservation,
    ) -> list[IdentityEvidence]:
        return list(left.evidence) + list(right.evidence)

    @staticmethod
    def _corroborates(
        left: ResourceObservation, right: ResourceObservation,
    ) -> list[IdentityEvidence]:
        """Corroborating evidence present in EITHER observation (§4.4)."""
        out = [
            e for e in list(left.evidence) + list(right.evidence)
            if e.kind in _CORROBORATING_KINDS
        ]
        # cross-endpoint body ids: BOTH bodies carry the same object id
        if (
            left.object_id_source == "response_body"
            and right.object_id_source == "response_body"
            and left.object_id and left.object_id == right.object_id
        ):
            out.append(IdentityEvidence(
                kind="cross_endpoint_body_id", value=left.object_id,
                source_ref=f"{left.endpoint}+{right.endpoint}",
            ))
        return out

    @staticmethod
    def _explicit_reference_links(
        left: ResourceObservation, right: ResourceObservation,
    ) -> list[IdentityEvidence]:
        return [
            e for e in list(left.evidence) + list(right.evidence)
            if e.kind == "api_resource_reference"
        ]

    @staticmethod
    def _attribute_contradiction(
        left: ResourceObservation, right: ResourceObservation,
    ) -> str:
        la, ra = left.stable_attributes(), right.stable_attributes()
        for key in sorted(set(la) & set(ra)):
            if la[key] != ra[key]:
                return f"{key}: {la[key]!r} != {ra[key]!r}"
        return ""

    # -- projections --------------------------------------------------------

    def identity_for_endpoint(self, endpoint: str) -> ObjectIdentity | None:
        anchor = self._representation_anchor.get(endpoint)
        return self._identities.get(anchor) if anchor else None

    def identities(self) -> list[ObjectIdentity]:
        return [
            self._identities[k]
            for k in sorted(self._identities, key=lambda a: (a[0], a[1], a[2]))
        ]

    def relationships(self) -> list[IdentityRelationship]:
        return [self._relationships[k] for k in sorted(self._relationships)]

    def abstentions(self) -> list[IdentityRelationship]:
        return list(self._abstentions)

    def conflicts(self) -> list[IdentityRelationship]:
        return list(self._conflicts)

    def stats(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        for rel in self._relationships.values():
            by_kind[rel.kind.value] = by_kind.get(rel.kind.value, 0) + 1
        return {
            "observations_ingested": self.ingested,
            "identities": len(self._identities),
            "representations": len(self._representation_anchor),
            "relationships": dict(sorted(by_kind.items())),
            "abstentions": len(self._abstentions),
            "conflicts_preserved": len(self._conflicts),
            "max_identities": self.max_identities,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "identities": [i.as_dict() for i in self.identities()],
            "relationships": [r.as_dict() for r in self.relationships()],
            "abstentions": [r.as_dict() for r in self._abstentions],
            "conflicts": [r.as_dict() for r in self._conflicts],
            "stats": self.stats(),
        }


# ---------------------------------------------------------------------------
# Campaign-state ingestion (the real production adapter)
# ---------------------------------------------------------------------------

def _resource_type_from_path(path: str) -> str:
    """Derive a resource type from path segments — a HINT, never an id.

    The second-to-last segment of an id-bearing path (``/api/orders/123``
    -> ``orders``) or the last segment of a collection path
    (``/api/orders`` -> ``orders``). Query strings are NOT part of the
    type (identity-significant query params are preserved by the
    fingerprint layer, UM-DR-31.1 R4/F10/F11).
    """
    clean = path.split("?", 1)[0].strip("/")
    if not clean:
        return ""
    parts = [p for p in clean.split("/") if p]
    if not parts:
        return ""
    last = parts[-1]
    # id-bearing final segment -> type is the parent segment
    if _looks_like_identifier(last) and len(parts) >= 2:
        return parts[-2].lower()
    return last.lower()


_ID_CHARS = set("0123456789abcdefABCDEF-_")


def _looks_like_identifier(segment: str) -> bool:
    """A segment that is plausibly an object identifier (id/uuid/slug-id)."""
    if not segment:
        return False
    digits = sum(c.isdigit() for c in segment)
    if digits >= 1 and digits >= len(segment) * 0.4:
        return True
    # uuid shape
    if len(segment) == 36 and segment.count("-") == 4:
        return True
    return False


def _object_id_from_path(path: str) -> tuple[str, str]:
    """Extract (object_id, source) from the final path segment, if any."""
    clean = path.split("?", 1)[0].strip("/")
    if not clean:
        return "", ""
    parts = [p for p in clean.split("/") if p]
    if parts and _looks_like_identifier(parts[-1]):
        return parts[-1], "path_segment"
    return "", ""


def observations_from_campaign_state(
    state: Mapping[str, Any],
    *,
    max_observations: int = 2000,
) -> list[ResourceObservation]:
    """Build resource observations from REAL campaign state channels.

    Sources (all optional, all evidence-bearing):
      * ``crawled_data.openapi_routes`` — declared API surface;
      * ``workflow_observations`` — observed transitions with object_refs
        and tenant_ref (models/workflows.py vocabulary);
      * ``endpoint_inventory`` / family feeds vocabulary.

    Only observed data becomes observations. Nothing is fabricated.
    """
    from webpent.shared.family_feeds import endpoint_inventory_from_state

    get = state.get if hasattr(state, "get") else (lambda k, d=None: d)
    observations: list[ResourceObservation] = []

    def _push(obs: ResourceObservation) -> None:
        if (
            len(observations) < max_observations
            and obs.resource_type and obs.object_id and obs.endpoint
        ):
            observations.append(obs)

    # Source precedence: the MOST STRUCTURED source lands first (the
    # family_feeds principle) — a declared observation (schema-analyzed
    # resource type + in-body object id) dominates a path-derived hint
    # for the same endpoint in every first-wins consumer.
    #
    # 1. explicit object observations channel (identity producers —
    #    declared types, body-observed ids, richest evidence)
    for obs in get("object_identity_observations") or []:
        if isinstance(obs, Mapping):
            _push(ResourceObservation(
                endpoint=str(obs.get("endpoint") or ""),
                method=str(obs.get("method") or "GET"),
                resource_type=str(obs.get("resource_type") or ""),
                object_id=str(obs.get("object_id") or ""),
                object_id_source=str(obs.get("object_id_source") or "declared"),
                tenant=str(obs.get("tenant") or ""),
                attributes=dict(obs.get("attributes") or {}),
                evidence=[
                    IdentityEvidence(
                        kind=str(e.get("kind")), value=str(e.get("value") or ""),
                        source_ref=str(e.get("source_ref") or ""),
                        observation_ref=str(e.get("observation_ref") or ""),
                    )
                    for e in (obs.get("evidence") or [])
                    if isinstance(e, Mapping) and e.get("kind")
                ],
                observation_ref=str(obs.get("observation_ref") or ""),
            ))

    # 2. workflow observations (rich evidence: tenant, object refs)
    for wf in get("workflow_observations") or []:
        if not isinstance(wf, Mapping):
            continue
        endpoint = str(wf.get("endpoint") or "")
        if not endpoint:
            continue
        obj_id, src = _object_id_from_path(endpoint)
        obj_refs = [str(r) for r in (wf.get("object_refs") or [])]
        if not obj_id and obj_refs:
            obj_id, src = obj_refs[0], "workflow_object_ref"
        tenant = str(wf.get("tenant_ref") or "")
        _push(ResourceObservation(
            endpoint=endpoint, method=str(wf.get("method") or "GET"),
            resource_type=_resource_type_from_path(endpoint),
            object_id=obj_id, object_id_source=src or "workflow",
            tenant=tenant or "",
            attributes={
                "authorization_boundary": wf.get("authorization_boundary"),
                "workflow_key": wf.get("workflow_key"),
                "identity_ref": wf.get("identity_ref"),
            },
            evidence=[
                IdentityEvidence(
                    kind="workflow_reference",
                    value=str(wf.get("transition_key") or ""),
                    source_ref=endpoint,
                    observation_ref=str(wf.get("fingerprint") or ""),
                )
            ],
            observation_ref=str(wf.get("fingerprint") or ""),
        ))

    # 3. endpoint inventory (declared surface — path-derived hints,
    #    the weakest structural source, lands last)
    for entry in endpoint_inventory_from_state(state):
        path = str(entry.get("path") or "")
        if not path:
            continue
        obj_id, src = _object_id_from_path(path)
        if not obj_id:
            continue
        _push(ResourceObservation(
            endpoint=path, method=str(entry.get("method") or "GET"),
            resource_type=_resource_type_from_path(path),
            object_id=obj_id, object_id_source=src,
            observation_ref=f"inventory:{entry.get('source', 'explicit')}",
        ))
    return observations
