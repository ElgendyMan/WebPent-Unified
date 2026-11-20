"""UM-DR-43 Workstream B — identity-aware hypothesis intelligence.

AUDIT (directive §13). Where the engine currently merges or splits
hypotheses:

  * ``InvestigationState.add_hypothesis`` (schemas.py) appends WITHOUT
    any deduplication — every intake lands, duplicates included.
  * Findings are keyed by ``case_id`` = the ``hypothesis_id`` half of
    ``{hypothesis_id}/{family}`` (finding_bridge.py), so all identity
    distinctions live entirely in how the proposer mints hypothesis
    ids. There is no deterministic identity-scope mechanism, and
    nothing prevents two security-DISTINCT investigations from
    collapsing onto one id, or two logically IDENTICAL ones from
    duplicating because a harmless representation detail changed.

This module supplies the missing mechanism as pure, deterministic,
explainable functions:

  * ``IdentityContext`` — the security-relevant dimensions the
    directive lists (actor/role/tenant/namespace/resource ownership/
    object identity/operation/workflow state/session/auth strength/
    method/preconditions). Presence vs absence of a dimension is
    itself a distinction (unauthenticated vs authenticated contexts
    must never merge), so every field always contributes to the
    fingerprint — empty string included.
  * ``identity_scope_key`` — a stable sha256 fingerprint over the
    canonical form. Harmless representation details (request ids,
    idempotency tokens, nonces, timestamps, query order) are stripped
    at construction (``from_params``) and can NEVER split hypotheses.
  * ``compare_identity_scope`` / ``explain`` — every merge or
    keep-separate decision carries a reason and the exact differing
    fields (directive: "Every merge or deduplication decision must be
    explainable").
  * ``deduplicate_hypotheses`` — groups records by
    ``(family, scope_key)``: logically identical hypotheses merge
    (the lexicographically smallest id is kept, for determinism);
    security-distinct ones stay separate with an explanation.
    The report is bounded, so deduplication cannot explode.

State semantics are deliberately untouched: deduplication is an
explicit, reportable operation — never a silent loss mid-investigation.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace

from webpent.egaie.schemas import HypothesisRecord

__all__ = [
    "IDENTITY_CONTEXT_FIELDS",
    "REPRESENTATION_ONLY_FIELDS",
    "PARAM_ALIASES",
    "IdentityContext",
    "MergeDecision",
    "DedupReport",
    "identity_scope_key",
    "compare_identity_scope",
    "explain",
    "from_params",
    "deduplicate_hypotheses",
]

# Directive §13: the dimensions two otherwise similar hypotheses may
# legitimately differ by. Fixed order — the canonical form (and hence
# the fingerprint) is stable across runs and processes.
IDENTITY_CONTEXT_FIELDS: tuple[str, ...] = (
    "actor",            # user / principal identity
    "role",             # role the principal holds
    "tenant",           # tenant or namespace boundary
    "namespace",
    "resource_owner",   # object ownership
    "object_id",        # object identity the operation targets
    "operation",        # operation (distinct from HTTP method)
    "workflow_state",
    "session",
    "auth_strength",    # authentication strength class
    "method",           # HTTP method (case-insensitive)
    "preconditions",    # sorted tuple of required preconditions
)

# Harmless request-representation details: stripped at construction so
# they can never split two logically identical hypotheses (directive:
# "Do not duplicate logically identical hypotheses merely because
# harmless request representation details changed").
REPRESENTATION_ONLY_FIELDS: frozenset[str] = frozenset({
    "request_id", "idempotency_key", "idem", "nonce", "csrf",
    "csrf_token", "timestamp", "ts", "correlation_id", "trace_id",
    "span_id", "token", "access_token", "request_uri_reference",
    "query_order", "user_agent", "referer", "epoch",
})

# Common observation-param spellings mapped onto identity dimensions.
PARAM_ALIASES: Mapping[str, str] = {
    "actor": "actor", "user": "actor", "username": "actor",
    "principal": "actor",
    "role": "role",
    "tenant": "tenant", "tenant_id": "tenant",
    "namespace": "namespace", "ns": "namespace",
    "owner": "resource_owner", "resource_owner": "resource_owner",
    "object_id": "object_id", "resource_id": "object_id",
    "object": "object_id",
    "operation": "operation", "op": "operation",
    "workflow_state": "workflow_state", "state": "workflow_state",
    "session": "session", "session_id": "session",
    "auth_strength": "auth_strength", "auth_level": "auth_strength",
    "authentication_strength": "auth_strength",
    "method": "method",
}


@dataclass(frozen=True)
class IdentityContext:
    """The security-relevant identity scope of one hypothesis."""

    actor: str = ""
    role: str = ""
    tenant: str = ""
    namespace: str = ""
    resource_owner: str = ""
    object_id: str = ""
    operation: str = ""
    workflow_state: str = ""
    session: str = ""
    auth_strength: str = ""
    method: str = ""
    preconditions: tuple[str, ...] = ()

    def normalized(self) -> IdentityContext:
        """Canonical form: trimmed fields, uppercased HTTP method
        (methods are case-insensitive), sorted preconditions. Case of
        identity-bearing values (actor, tenant, ...) is PRESERVED —
        ``User`` and ``user`` may be distinct principals."""
        return replace(
            self,
            **{
                name: str(getattr(self, name)).strip()
                for name in IDENTITY_CONTEXT_FIELDS
                if name not in ("method", "preconditions")
            },
            method=str(self.method).strip().upper(),
            preconditions=tuple(sorted(
                p.strip() for p in self.preconditions if str(p).strip())),
        )

    def canonical_form(self) -> str:
        """Deterministic multi-line ``field=value`` rendering over ALL
        dimensions in fixed order (absence contributes ``field=`` —
        absence is itself a security distinction)."""
        ctx = self.normalized()
        lines = []
        for name in IDENTITY_CONTEXT_FIELDS:
            if name == "preconditions":
                value = ",".join(ctx.preconditions)
            else:
                value = str(getattr(ctx, name))
            lines.append(f"{name}={value}")
        return "\n".join(lines)


def identity_scope_key(context: IdentityContext) -> str:
    """Stable deterministic fingerprint (sha256, 16 hex chars)."""
    return hashlib.sha256(
        context.canonical_form().encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class MergeDecision:
    """An explainable merge / keep-separate decision."""

    verdict: str                 # "merge" | "keep_separate"
    reason: str
    differing_fields: tuple[str, ...] = ()
    a_key: str = ""
    b_key: str = ""

    @property
    def merge(self) -> bool:
        return self.verdict == "merge"


def compare_identity_scope(
    a: IdentityContext, b: IdentityContext,
) -> MergeDecision:
    """Compare two identity scopes. Equal scopes MERGE (any harmless
    representation difference was already stripped at construction);
    differing scopes stay separate with the exact differing fields."""
    a_key, b_key = identity_scope_key(a), identity_scope_key(b)
    if a_key == b_key:
        return MergeDecision(
            verdict="merge",
            reason="identity scopes identical; representation-only "
                   "differences are not part of the fingerprint",
            a_key=a_key, b_key=b_key,
        )
    a_n, b_n = a.normalized(), b.normalized()
    differing = tuple(
        name for name in IDENTITY_CONTEXT_FIELDS
        if (",".join(a_n.preconditions) if name == "preconditions"
            else str(getattr(a_n, name)))
        != (",".join(b_n.preconditions) if name == "preconditions"
            else str(getattr(b_n, name)))
    )
    return MergeDecision(
        verdict="keep_separate",
        reason="security contexts differ on: " + ", ".join(differing),
        differing_fields=differing,
        a_key=a_key, b_key=b_key,
    )


def explain(a: IdentityContext, b: IdentityContext) -> MergeDecision:
    """Alias kept for readability at call sites that audit decisions."""
    return compare_identity_scope(a, b)


def from_params(params: Mapping[str, object]) -> IdentityContext:
    """Build a context from raw observation parameters: representation-
    only keys are dropped, alias spellings are mapped onto identity
    dimensions, anything unmapped is ignored (never guessed into an
    identity dimension)."""
    kwargs: dict[str, object] = {}
    preconditions: list[str] = []
    for key, value in params.items():
        name = str(key).strip().lower()
        if name in REPRESENTATION_ONLY_FIELDS:
            continue
        if name == "preconditions":
            if isinstance(value, (list, tuple, set)):
                preconditions.extend(str(v) for v in value)
            else:
                preconditions.append(str(value))
            continue
        field_name = PARAM_ALIASES.get(name)
        if field_name is None:
            continue
        kwargs[field_name] = str(value)
    if preconditions:
        kwargs["preconditions"] = tuple(preconditions)
    return IdentityContext(**kwargs).normalized()  # type: ignore[arg-type]


@dataclass(frozen=True)
class DedupReport:
    """Bounded, explainable result of a deduplication pass."""

    kept: tuple[str, ...] = ()
    merged_into: Mapping[str, str] = field(default_factory=dict)
    groups: int = 0
    kept_separate: tuple[Mapping[str, object], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "groups": self.groups,
            "kept_count": len(self.kept),
            "merged_count": len(self.merged_into),
            "merged_into": dict(self.merged_into),
            "kept_separate": list(self.kept_separate),
        }


_MERGE_REASON = ("logically identical: same family and identical "
                 "identity scope; representation-only deltas ignored")
_MAX_REPORTED = 50


def deduplicate_hypotheses(
    records: Sequence[HypothesisRecord],
    contexts: Mapping[str, IdentityContext],
) -> DedupReport:
    """Group hypothesis records by (family, identity scope).

    Records whose context is unknown are never merged (absence of
    evidence is not evidence of equality). Within a group the
    lexicographically smallest hypothesis_id is kept — a deterministic
    choice that does not depend on intake order.
    """
    groups: dict[tuple[str, str], list[HypothesisRecord]] = {}
    context_by_key: dict[tuple[str, str], IdentityContext] = {}
    unkeyed: list[str] = []
    for record in records:
        context = contexts.get(record.hypothesis_id)
        if context is None:
            unkeyed.append(record.hypothesis_id)
            continue
        key = (record.family, identity_scope_key(context))
        groups.setdefault(key, []).append(record)
        context_by_key.setdefault(key, context)

    kept: list[str] = []
    merged_into: dict[str, str] = {}
    for group_key in sorted(groups):
        members = sorted(
            groups[group_key], key=lambda r: r.hypothesis_id)
        kept.append(members[0].hypothesis_id)
        for extra in members[1:]:
            merged_into[extra.hypothesis_id] = members[0].hypothesis_id

    # Explainability for kept-separate pairs: within a family, contrast
    # each additional group's scope against the family's first group —
    # bounded so a report can never explode.
    kept_separate: list[Mapping[str, object]] = []
    by_family: dict[str, list[tuple[str, str]]] = {}
    for family, scope in sorted(groups):
        by_family.setdefault(family, []).append(scope)
    for family, scopes in sorted(by_family.items()):
        if len(scopes) < 2:
            continue
        first = context_by_key[(family, scopes[0])]
        for scope in scopes[1:_MAX_REPORTED]:
            decision = compare_identity_scope(
                first, context_by_key[(family, scope)])
            kept_separate.append({
                "family": family,
                "reason": decision.reason,
                "differing_fields": list(decision.differing_fields),
            })
    return DedupReport(
        kept=tuple(kept),
        merged_into=dict(merged_into),
        groups=len(groups) + len(unkeyed),
        kept_separate=tuple(kept_separate),
    )
