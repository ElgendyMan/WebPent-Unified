"""UM-DR-43C — versioned identity-safe hypothesis identity contract.

PROBLEM (directive §4.2, verified by the §4 audit):

  * RC-5 production dedup (``hypothesis_dedup.py``) fingerprinted only
    ``(normalized target_url, vuln_class)`` and lower-cased the WHOLE
    URL — merging case-sensitive paths and query values that differ
    security-relevantly, while never distinguishing principal/tenant/
    object/operation contexts.
  * The UMDR-32 identity workflow (``identity_workflow.py``) already
    fingerprints (target, class, objective, principals, preconditions,
    state keys) — a richer convention — but under a DIFFERENT id
    namespace (``webpent:umdr31:…``), so the same investigation
    arriving from the two producers NEVER merges (cross-producer
    dedup is impossible by construction).
  * ``egaie/identity_scope.py`` holds pure, explainable identity-scope
    logic but operates on the EGAIE ``HypothesisRecord`` model —
    isolated from the production hunt path.

CONTRACT (this module — pure functions, no I/O, no network, no LLM):

  1. ``canonical_target_key`` — HTTP-semantics-aware URL
     canonicalization (RFC 3986 authority + path case PRESERVED,
     default ports stripped, fragment dropped, query preserved as an
     ordered pair list — order is behaviorally significant for many
     applications, so it is NOT sorted away blindly).
  2. ``HypothesisIdentityContext`` — the security-relevant identity
     dimensions of §5.1, each carrying a provenance tier:
     ``observed`` (evidence-backed structured channel) > ``declared``
     (producer-stated) > ``inferred`` (deterministic derivation, never
     from free text) > ``unknown`` (absent).  Unknown NEVER upgrades.
  3. ``identity_fingerprint`` — versioned (``umdr43c:v1``) sha256 over
     the canonical (target key, class, objective key, identity scope).
     Two hypotheses merge only when target, class, objective AND the
     full identity scope agree.
  4. ``legacy_fingerprint`` — byte-compatible re-implementation of the
     RC-5 fingerprint: hypotheses WITHOUT any identity context keep
     their historical ids, so old checkpoints replay unchanged
     (directive §13 — no gratuitous id churn).
  5. ``decide`` — an explainable merge / keep-separate / legacy-merge
     decision implementing the §5.3 unknown-identity policy: known +
     same scope may merge; known + differing principal/object/tenant/
     operation/workflow stays separate; known vs unknown NEVER merges
     on the unknown's word alone; unknown vs unknown merges only under
     the legacy contract, flagged as not proving security-identity
     equality.

Layering: this module imports NOTHING from ``webpent.egaie`` or
``webpent.graph`` (no circular dependency); ``webpent.models`` is
imported lazily inside functions only for type extraction, never at
module import time.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

__all__ = [
    "IDENTITY_CONTRACT_VERSION",
    "FINGERPRINT_NAMESPACES",
    "PROVENANCE_TIERS",
    "canonical_target_key",
    "HypothesisIdentityContext",
    "identity_fingerprint",
    "legacy_fingerprint",
    "identity_from_hypothesis",
    "decide",
    "MergeDecision43C",
    "IdentityTelemetry",
]

# The versioned identity contract stamp: every fingerprint derived
# under this contract carries it, so a future v2 can distinguish its
# ids from v1 ids without rewriting history.
IDENTITY_CONTRACT_VERSION = "umdr43c:v1"

# Deterministic uuid5 namespaces. The LEGACY namespace reproduces the
# RC-5 id convention EXACTLY (byte-for-byte) so pre-43C checkpoints
# replay with identical ids; the v2 namespace mints new ids only for
# hypotheses that actually carry identity context.
FINGERPRINT_NAMESPACES = {
    "legacy": "webpent:umdr40:",
    "v2": "webpent:umdr43c:",
}

# Provenance tiers, strongest first. A dimension may only be cited at
# the tier its evidence channel actually provides; ``unknown`` is a
# first-class value (absence of context is itself a distinction) and
# can never be upgraded by a weaker tier.
PROVENANCE_TIERS = ("observed", "declared", "inferred", "unknown")

# Representation-only request attributes (§5.5): stripped from the
# fingerprint input because they never change the security identity of
# an investigation. Session/auth context and preconditions are
# DELIBERATELY absent from this set — they are identity-bearing.
REPRESENTATION_ONLY_ATTRIBUTES = frozenset({
    "request_id", "trace_id", "span_id", "correlation_id", "nonce",
    "idempotency_key", "timestamp", "user_agent", "referer",
})

_DEFAULT_PORTS = {"http": 80, "https": 443}


def canonical_target_key(url: str) -> str:
    """HTTP-semantics canonical form of a target URL (§5.4).

    * scheme and host: lower-cased (DNS + scheme are case-insensitive);
    * default port for the scheme: stripped (``:443`` on https adds
      nothing to origin identity);
    * path: PRESERVED verbatim except the trailing slash, which is
      STRIPPED (only a lone ``/`` remains) — this has been the actual
      behavior since the function's birth (every checkpoint id was
      minted with the strip); UM-DR-44 A6 corrected this docstring to
      match the code, never the reverse;
    * query: PRESERVED as the raw ordered string — parameter order is
      behaviorally significant for many applications (§5.4: never sort
      blindly); duplicate parameters therefore stay distinct;
    * fragment: dropped (never reaches the server);
    * IPv6 literal hosts keep their brackets and are unified through
      ``ipaddress.IPv6Address`` (compressed + lowercase — hex case and
      zero-compression spellings of the same literal share one key);
    * IDN hosts are punycoded (``xn--``) so the unicode and ASCII
      spellings of the same registrable host share one key; malformed
      hosts fall back verbatim (never raise);
    * non-http(s) schemes and relative references: returned trimmed
      unchanged (the honest fallback — same as the frozen
      ``_normalize_url`` contract for those inputs).

    Idempotent and deterministic; never raises on malformed input
    (returns the stripped input).
    """
    raw = str(url or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return raw
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    host = host.strip().rstrip(".").lower()
    if not host:
        return raw
    # UM-DR-44 A6: IPv6 literals — urlsplit returns the hostname WITHOUT
    # brackets, so rebuilding the netloc plainly produced an INVALID
    # "https://::1:8443" form. Unify through ipaddress.IPv6Address
    # (compressed + lowercase: hex case AND zero-compression spellings
    # of the same literal become one key) and restore the brackets.
    is_ipv6 = ":" in host
    if is_ipv6:
        try:
            import ipaddress

            host = str(ipaddress.IPv6Address(host))
        except ValueError:
            return raw  # malformed literal — honest fallback
    elif not host.isascii():
        # UM-DR-44 A6: IDN — punycode the unicode spelling so it shares
        # one key with the xn-- spelling of the same registrable host.
        try:
            host = host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            pass  # un-encodable host — keep verbatim (honest fallback)
    try:
        port = parts.port
    except ValueError:
        return raw
    if port is None or port == _DEFAULT_PORTS[scheme]:
        netloc = f"[{host}]" if is_ipv6 else host
    else:
        netloc = f"[{host}]:{port}" if is_ipv6 else f"{host}:{port}"
    path = parts.path or ""
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


# -- §5.1 identity context -------------------------------------------------

@dataclass(frozen=True)
class HypothesisIdentityContext:
    """The security-relevant identity scope of a production hypothesis.

    Every dimension records (value, provenance tier).  ``unknown``
    dimensions (empty value) are load-bearing: they distinguish an
    unauthenticated context from an authenticated one and are compared
    as-is — absence is a distinction, never a wildcard.
    """

    actor: str = ""            # principal (user) identity
    role: str = ""             # role the principal holds
    tenant: str = ""           # tenant / namespace boundary
    namespace: str = ""
    resource_owner: str = ""   # ownership of the target object
    object_id: str = ""        # object identity under investigation
    operation: str = ""        # application operation (≠ HTTP method)
    workflow_state: str = ""   # observed workflow state key
    session: str = ""          # session/auth context (hashed if secret)
    auth_strength: str = ""    # authentication strength class
    http_method: str = ""      # HTTP method (case-insensitive → upper)
    preconditions: tuple[str, ...] = ()  # sorted observable preconditions

    provenance: Mapping[str, str] = field(default_factory=dict)

    def normalized(self) -> "HypothesisIdentityContext":
        return HypothesisIdentityContext(
            actor=self.actor.strip(),
            role=self.role.strip(),
            tenant=self.tenant.strip(),
            namespace=self.namespace.strip(),
            resource_owner=self.resource_owner.strip(),
            object_id=self.object_id.strip(),
            operation=self.operation.strip(),
            workflow_state=self.workflow_state.strip(),
            session=self.session.strip(),
            auth_strength=self.auth_strength.strip(),
            http_method=self.http_method.strip().upper(),
            preconditions=tuple(sorted(
                p.strip() for p in self.preconditions if str(p).strip())),
            provenance=dict(self.provenance),
        )

    def is_empty(self) -> bool:
        """True when NO dimension carries a value — the legacy case.

        UM-DR-44 A1: ``preconditions`` now count toward emptiness (a
        context carrying only observable preconditions is NOT the
        legacy case).  ``http_method`` counts only when NON-DEFAULT:
        the Hypothesis model's ``request_method`` defaults to "GET"
        for every checkpoint-era hypothesis, so a bare GET carries no
        identity signal — treating it as one would collapse the entire
        legacy corpus into "contextual".  A declared non-default
        method (POST/PUT/DELETE/…) IS an identity distinction (the
        same method-constraint semantics as the scope authority).
        Kept dimension-consistent with ``canonical_form()`` by
        tests/test_umdr44_a1_is_empty_dimensions.py (structural
        contract, with the documented default-method exception).
        """
        n = self.normalized()
        return not (
            n.actor or n.role or n.tenant or n.namespace
            or n.resource_owner or n.object_id or n.operation
            or n.workflow_state or n.session or n.auth_strength
            or n.preconditions
            or (n.http_method and n.http_method != "GET")
        )

    def canonical_form(self) -> str:
        n = self.normalized()
        lines = [
            f"actor={n.actor}",
            f"role={n.role}",
            f"tenant={n.tenant}",
            f"namespace={n.namespace}",
            f"resource_owner={n.resource_owner}",
            f"object_id={n.object_id}",
            f"operation={n.operation}",
            f"workflow_state={n.workflow_state}",
            f"session={n.session}",
            f"auth_strength={n.auth_strength}",
            f"http_method={n.http_method}",
            f"preconditions={','.join(n.preconditions)}",
        ]
        return "\n".join(lines)

    # Static dimension access (no dynamic resolution — the direct-I/O
    # inventory gates getattr-style access inside identity paths).
    _DIMENSION_ACCESSORS = {
        "actor": lambda c: c.actor,
        "role": lambda c: c.role,
        "tenant": lambda c: c.tenant,
        "namespace": lambda c: c.namespace,
        "resource_owner": lambda c: c.resource_owner,
        "object_id": lambda c: c.object_id,
        "operation": lambda c: c.operation,
        "workflow_state": lambda c: c.workflow_state,
        "session": lambda c: c.session,
        "auth_strength": lambda c: c.auth_strength,
        "http_method": lambda c: c.http_method,
        "preconditions": lambda c: c.preconditions,
    }

    def differing_dimensions(self, other: "HypothesisIdentityContext",
                             ) -> tuple[str, ...]:
        a, b = self.normalized(), other.normalized()
        return tuple(
            name for name, accessor in self._DIMENSION_ACCESSORS.items()
            if accessor(a) != accessor(b))


def _tier_of(context: HypothesisIdentityContext, dimension: str) -> str:
    return context.provenance.get(dimension, "unknown")


def identity_fingerprint(
    *,
    target_url: str,
    vuln_class: str,
    objective_key: str = "",
    identity: HypothesisIdentityContext | None = None,
) -> str:
    """Versioned v2 fingerprint: target + class + objective + scope.

    ``objective_key`` generalizes the UMDR-31 notion ("what the
    hypothesis is about", e.g. ``differential:<object>`` or
    ``invariant:<id>``); the generic producer leaves it empty, which is
    itself a deterministic value.
    """
    identity = (identity or HypothesisIdentityContext()).normalized()
    canonical = {
        "v": IDENTITY_CONTRACT_VERSION,
        "t": canonical_target_key(target_url),
        "c": str(vuln_class or "").strip().lower(),
        "o": str(objective_key or "").strip(),
        "i": identity.canonical_form(),
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:40]


def legacy_fingerprint(target_url: str, vuln_class: str) -> str:
    """Byte-compatible RC-5 fingerprint (kept for replay compat §13).

    Reproduces ``hypothesis_dedup.hypothesis_content_fingerprint``
    exactly — including its whole-URL lower-casing — because
    hypotheses WITHOUT identity context must keep their pre-43C ids.
    """
    canonical = json.dumps(
        {"t": str(target_url or "").strip().rstrip("/").lower(),
         "v": str(vuln_class or "").strip().lower()},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:40]


# -- §5.2 evidence-driven context extraction -------------------------------

def identity_from_hypothesis(
    hypothesis: Any,
    *,
    identity_profiles: Mapping[str, Any] | None = None,
    object_identity_registry: Mapping[str, Any] | None = None,
) -> HypothesisIdentityContext:
    """Extract the identity context from STRUCTURED channels only.

    Sources (in strength order — a dimension keeps the STRONGEST tier
    it receives, and never downgrades):

    * ``hypothesis.preconditions`` / ``origin_detail`` structured
      prefixes (``umdr32_identity_workflow fp=…``, declared producer
      fields) → ``declared``;
    * ``identity_profiles`` (observed principal/role/tenant facts
      gathered during recon) → ``observed``;
    * ``object_identity_registry`` (observed object ownership) →
      ``observed``;
    * ``request_data`` identity keys (actor/user/role/tenant/…),
      representation-only keys stripped → ``declared``;
    * ``request_method`` → ``declared``.

    NOTHING is extracted from the free-text ``statement`` and no
    tenant/object is inferred from URL substrings (§5.2: no inference
    from prose, no path-shape guesses).
    """
    profiles = identity_profiles or {}
    registry = object_identity_registry or {}

    values: dict[str, str] = {}
    tiers: dict[str, str] = {}

    def _set(dim: str, value: str, tier: str) -> None:
        value = str(value or "").strip()
        if not value:
            return
        current = tiers.get(dim)
        if current is None or PROVENANCE_TIERS.index(tier) < PROVENANCE_TIERS.index(current):
            values[dim] = value
            tiers[dim] = tier

    # --- declared: structured producer fields on the hypothesis ---
    # Static field table (no dynamic resolution — the direct-I/O
    # inventory gates getattr-style access inside identity paths).
    def _field(name: str, default: Any = "") -> Any:
        if isinstance(hypothesis, Mapping):
            return hypothesis.get(name, default)
        # Pydantic model with extra="forbid": the field set is static,
        # so direct attribute access is the honest, non-dynamic form.
        try:
            return hypothesis.__getattribute__(name)
        except AttributeError:
            return default

    preconditions: list[str] = [
        str(p) for p in (_field("preconditions", ()) or [])]
    method = str(_field("request_method", "") or "").strip()
    if method:
        _set("http_method", method, "declared")

    request_data = _field("request_data", None)
    if isinstance(request_data, Mapping):
        for key, value in request_data.items():
            name = str(key).strip().lower()
            if name in REPRESENTATION_ONLY_ATTRIBUTES:
                continue
            if name in _REQUEST_DATA_IDENTITY_KEYS:
                _set(_REQUEST_DATA_IDENTITY_KEYS[name], value, "declared")

    # --- declared: origin_detail structured provenance lines ---
    detail = str(_field("origin_detail", "") or "")
    for line in detail.split():
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip().lower()
            if key in _ORIGIN_DETAIL_IDENTITY_KEYS and value.strip():
                _set(_ORIGIN_DETAIL_IDENTITY_KEYS[key], value.strip(),
                     "declared")

    # --- observed: identity profiles / object registry (evidence) ---
    target = str(_field("target_url", "") or "")
    canon = canonical_target_key(target)
    profile = profiles.get(canon) or profiles.get(target)
    if isinstance(profile, Mapping):
        for key, value in profile.items():
            name = str(key).strip().lower()
            if name in _PROFILE_IDENTITY_KEYS and str(value or "").strip():
                _set(_PROFILE_IDENTITY_KEYS[name], value, "observed")
    if isinstance(registry, Mapping):
        obj = values.get("object_id", "")
        record = registry.get(obj) or (
            registry.get(canon) if not obj else None)
        if isinstance(record, Mapping):
            for key, value in record.items():
                name = str(key).strip().lower()
                if name in _PROFILE_IDENTITY_KEYS and str(value or "").strip():
                    _set(_PROFILE_IDENTITY_KEYS[name], value, "observed")

    return HypothesisIdentityContext(
        preconditions=tuple(preconditions),
        provenance=dict(tiers),
        **values,
    ).normalized()


_REQUEST_DATA_IDENTITY_KEYS: Mapping[str, str] = {
    "actor": "actor", "user": "actor", "username": "actor",
    "principal": "actor",
    "role": "role",
    "tenant": "tenant", "tenant_id": "tenant",
    "namespace": "namespace",
    "owner": "resource_owner", "resource_owner": "resource_owner",
    "object_id": "object_id", "resource_id": "object_id",
    "object": "object_id",
    "operation": "operation", "op": "operation",
    "workflow_state": "workflow_state", "state": "workflow_state",
    "session": "session", "session_id": "session",
    "auth_strength": "auth_strength", "auth_level": "auth_strength",
}

_ORIGIN_DETAIL_IDENTITY_KEYS: Mapping[str, str] = {
    "principal": "actor",
    "role": "role",
    "tenant": "tenant",
    "object": "object_id",
    "operation": "operation",
}

_PROFILE_IDENTITY_KEYS: Mapping[str, str] = {
    "actor": "actor", "principal": "actor", "user": "actor",
    "role": "role",
    "tenant": "tenant", "tenant_id": "tenant",
    "namespace": "namespace",
    "owner": "resource_owner", "resource_owner": "resource_owner",
    "object_id": "object_id", "resource_id": "object_id",
    "operation": "operation",
    "workflow_state": "workflow_state",
    "session": "session",
    "auth_strength": "auth_strength",
}


# -- §5.3 merge policy ------------------------------------------------------

@dataclass(frozen=True)
class MergeDecision43C:
    verdict: str            # "merge" | "keep_separate" | "legacy_merge"
    reason: str
    differing_dimensions: tuple[str, ...] = ()
    fingerprint_a: str = ""
    fingerprint_b: str = ""
    identity_involved: bool = False

    @property
    def merge(self) -> bool:
        return self.verdict != "keep_separate"


def decide(
    *,
    target_a: str, class_a: str, objective_a: str,
    identity_a: HypothesisIdentityContext | None,
    target_b: str, class_b: str, objective_b: str,
    identity_b: HypothesisIdentityContext | None,
) -> MergeDecision43C:
    """The §5.3 unknown-identity merge policy as one explainable call."""
    fa = identity_fingerprint(target_url=target_a, vuln_class=class_a,
                              objective_key=objective_a, identity=identity_a)
    fb = identity_fingerprint(target_url=target_b, vuln_class=class_b,
                              objective_key=objective_b, identity=identity_b)
    if fa == fb:
        return MergeDecision43C(
            verdict="merge",
            reason="target, class, objective and identity scope all "
                   "agree (contract umdr43c:v1)",
            fingerprint_a=fa, fingerprint_b=fb, identity_involved=True)
    known_a = bool(identity_a and not identity_a.is_empty())
    known_b = bool(identity_b and not identity_b.is_empty())
    # Fingerprint differs. If BOTH sides carry a real identity context,
    # the difference is identity-relevant → keep separate, explained.
    if known_a and known_b:
        diff = (identity_a or HypothesisIdentityContext()).differing_dimensions(
            identity_b or HypothesisIdentityContext())
        return MergeDecision43C(
            verdict="keep_separate",
            reason="identity scopes differ on: " + (
                ", ".join(diff) if diff else "objective or target"),
            differing_dimensions=diff,
            fingerprint_a=fa, fingerprint_b=fb, identity_involved=True)
    # One or both unknown: fall back to the legacy pair, but the merge
    # it produces is EXPLICITLY marked as not proving identity equality.
    # The legacy fingerprint lower-cases the whole URL and keeps the
    # default port — which merges case-sensitive paths AND splits
    # default-port spellings — so the fallback compares the legacy
    # fingerprints OF THE CANONICAL v2 TARGET KEYS: same-origin intent
    # as RC-5 (scheme/host case-insensitive), none of its false
    # merges/splits. The legacy fingerprint alone only governs which id
    # a context-free hypothesis keeps for checkpoint compatibility.
    key_a, key_b = canonical_target_key(target_a), canonical_target_key(
        target_b)
    legacy = (key_a == key_b
              and legacy_fingerprint(key_a, class_a)
              == legacy_fingerprint(key_b, class_b))
    if legacy and class_a.strip().lower() == class_b.strip().lower():
        if known_a or known_b:
            return MergeDecision43C(
                verdict="keep_separate",
                reason="one side carries identity context and the other "
                       "does not — unknown identity never silently "
                       "equals known identity",
                fingerprint_a=fa, fingerprint_b=fb, identity_involved=True)
        return MergeDecision43C(
            verdict="legacy_merge",
            reason="legacy (url, class) pair matches with no identity "
                   "context on either side — merged under the RC-5 "
                   "compatibility contract; this does not prove "
                   "security-identity equality",
            fingerprint_a=fa, fingerprint_b=fb, identity_involved=False)
    return MergeDecision43C(
        verdict="keep_separate",
        reason="target or vulnerability class differs",
        fingerprint_a=fa, fingerprint_b=fb, identity_involved=False)


# -- §8 telemetry -----------------------------------------------------------

@dataclass
class IdentityTelemetry:
    """Bounded, deterministic, secret-free dedup telemetry (§8).

    Counters only — no hypothesis text, no URLs, no principals.  Safe
    to embed in campaign state and existing reporting surfaces.
    """

    hypotheses_emitted: int = 0
    unique_after_dedup: int = 0
    exact_duplicates_merged: int = 0
    representation_only_merged: int = 0
    identity_distinct_retained: int = 0
    unknown_context_retained: int = 0
    legacy_matches: int = 0
    lifecycle_conflicts_detected: int = 0
    evidence_refs_preserved: int = 0
    separation_dimensions: dict[str, int] = field(default_factory=dict)

    _MAX_DIMENSION_ENTRIES = 32

    def record_separation(self, dimension: str) -> None:
        key = str(dimension)[:40] or "unknown"
        if (len(self.separation_dimensions) < self._MAX_DIMENSION_ENTRIES
                or key in self.separation_dimensions):
            self.separation_dimensions[key] = (
                self.separation_dimensions.get(key, 0) + 1)

    def to_dict(self) -> dict[str, Any]:
        out = {
            "contract_version": IDENTITY_CONTRACT_VERSION,
            "hypotheses_emitted": self.hypotheses_emitted,
            "unique_after_dedup": self.unique_after_dedup,
            "exact_duplicates_merged": self.exact_duplicates_merged,
            "representation_only_merged": self.representation_only_merged,
            "identity_distinct_retained": self.identity_distinct_retained,
            "unknown_context_retained": self.unknown_context_retained,
            "legacy_matches": self.legacy_matches,
            "lifecycle_conflicts_detected": (
                self.lifecycle_conflicts_detected),
            "evidence_refs_preserved": self.evidence_refs_preserved,
        }
        if self.separation_dimensions:
            out["separation_dimensions"] = dict(sorted(
                self.separation_dimensions.items()))
        return out
