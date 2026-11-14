"""webpent.cqa_v2.representation_oracle — semantic representation
equivalence for the causal guard's observation model.

UM-DR-28 (the representation-equivalence repair window, 2026-11-07).
The M10 recall forensics (docs/engineering/M10_RECALL_RCA.md §2.4)
root-caused 15 of the 63 recorded blind_v3 false negatives as
COMPARATOR-ORACLE misses: the authorization differential existed
read-only, but the target represented it in the response BODY under
field names the observation model never read — the guard's context
extraction (``causal_guard._extract_context``) consults X-* headers
and top-level observation fields only, so ``_authorization_mismatch``
returned None and the verdict collapsed to INCONCLUSIVE.

This module closes that gap WITHOUT touching the frozen guard: it
recognizes the SAME authorization semantics across different
representations (headers, flat JSON fields, nested JSON objects) and
surfaces them through the channels the guard already reads.

Design contract (directive §6.2 — defensible, not over-normalizing):

* **Deterministic** — no randomness, no LLM, no similarity scores.
* **Fail-safe** — any parse failure yields no enrichment; the
  observation keeps its exact pre-oracle behavior (byte-compatible
  fallback, verified by regression).
* **Headers win** — enrichment only fills context channels that are
  ABSENT in the header/observation layer; it never overrides an
  explicitly observed value.
* **Explainable** — every enrichment records which rules fired
  (``representation_rules``), so evidence can say WHERE each semantic
  fact came from.
* **Never the authority** — the oracle only MANUFACTURES observables
  for ``guarded_causal_evaluate``; the causal guard stays the sole
  confirmation authority. An inconclusive comparison is never turned
  into a confirmation here.
* **No over-normalization** — the volatile-field rule set is a fixed,
  documented, tested list of non-semantic churn keys (timestamps,
  request ids). Security-relevant fields (owner, outcome, privilege,
  alias, tenant) are NEVER normalized away; the adversarial test
  pins that a one-character owner difference still breaks canonical
  equivalence.

Normalization rules (frozen vocabulary, tested):

* ``VOLATILE_KEYS`` — response churn that carries no authorization
  semantics (``timestamp``-like and request/trace id keys). Dropped
  from the CANONICAL form only (the raw evidence is preserved
  untouched on the observation).
* ``OUTCOME_GRANTED`` / ``OUTCOME_DENIED`` — body values that mean
  the same as the header grammar's ``granted_full`` / ``denied``.
* ``FIELD_ALIASES`` — body field names that carry the same semantic
  fact as a context channel (``owner`` ≡ ``resource_owner`` ≡
  ``owned_by`` …). Alias resolution is one level deep: a nested
  object under a known container key (``resource``, ``authorization``,
  ``acl``, ``actor``) is flattened once.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

__all__ = [
    "VOLATILE_KEYS",
    "authorization_semantics",
    "canonical_representation",
    "enrich_observation",
]

#: Response-churn keys that carry NO authorization semantics. These are
#: the ONLY keys the canonical form drops — the list is deliberately
#: minimal and tested; anything security-relevant is absent by design.
VOLATILE_KEYS: frozenset[str] = frozenset({
    "timestamp", "ts", "time", "generated_at", "generated", "server_time",
    "requested_at", "request_id", "req_id", "trace_id", "traceparent",
    "span_id", "nonce", "etag", "x_request_id", "correlation_id", "seq",
})

#: Body values equivalent to the header grammar's granted outcome.
OUTCOME_GRANTED: frozenset[str] = frozenset({
    "granted", "granted_full", "allowed", "permit", "permitted",
    "authorized", "ok", "success",
})

#: Body values equivalent to the header grammar's denied outcome.
OUTCOME_DENIED: frozenset[str] = frozenset({
    "denied", "forbidden", "deny", "refused", "unauthorized",
    "not_permitted", "blocked",
})

#: Body field names carrying the same semantic fact as a context
#: channel. Maps body key → context channel name.
FIELD_ALIASES: dict[str, str] = {
    # resource ownership
    "owner": "resource_owner",
    "owned_by": "resource_owner",
    "resource_owner": "resource_owner",
    "owner_id": "resource_owner",
    # authorization outcome
    "outcome": "authorization_outcome",
    "authorization": "authorization_outcome",   # scalar use only
    "authorization_outcome": "authorization_outcome",
    "access": "authorization_outcome",          # scalar use only
    "granted": "authorization_outcome",         # boolean → granted/denied
    "permission": "authorization_outcome",      # scalar use only
    # actor identity
    "actor": "actor_id",                        # scalar use only
    "actor_id": "actor_id",
    "requested_by": "actor_id",
    "on_behalf_of": "actor_id",
    # actor role / effective privilege
    "role": "actor_role",
    "actor_role": "actor_role",
    "effective_as": "effective_privilege_granted",
    "acting_as": "effective_privilege_granted",
    "alias": "effective_privilege_granted",     # the alias_bypass shape
    "elevated_to": "effective_privilege_granted",
    # privilege requirements
    "requires": "privilege_required",
    "privilege_required": "privilege_required",
    "required_role": "privilege_required",
    "min_role": "privilege_required",
    # tenants
    "tenant": "resource_tenant",
    "resource_tenant": "resource_tenant",
    # resource typing ("type" deliberately NOT aliased — MIME-style
    # values would pollute the resource-type analogy channel)
    "kind": "resource_type",
    "resource_type": "resource_type",
}

#: Container keys whose nested objects are flattened ONE level deep.
_CONTAINER_KEYS: frozenset[str] = frozenset({
    "resource", "authorization", "acl", "actor", "data", "meta", "result",
})

#: The context channels the causal guard reads (subset — the ones a
#: body can legitimately carry). Everything else stays header-only.
_GUARD_CHANNELS: frozenset[str] = frozenset({
    "actor_id", "actor_role", "actor_tenant", "authorization_outcome",
    "effective_privilege_granted", "resource_owner", "resource_tenant",
    "resource_type", "resource_id", "privilege_required",
})

_MAX_BODY_FIELDS = 64
_MAX_DEPTH = 4
#: The body size the oracle will even attempt to parse (bytes) — an
#: oversized body falls back to raw-digest semantics (fail-safe).
_MAX_BODY_BYTES = 65_536


# ---------------------------------------------------------------------------
# canonical representation
# ---------------------------------------------------------------------------

def _canonical(value: Any, depth: int) -> Any:
    """Deterministic canonical form: sorted keys, volatile keys dropped."""
    if depth > _MAX_DEPTH:
        return "<max-depth>"
    if isinstance(value, Mapping):
        return {
            str(k): _canonical(v, depth + 1)
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
            if str(k) not in VOLATILE_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_canonical(v, depth + 1) for v in value]
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if value is None:
        return None
    return str(value)


def canonical_representation(body_text: str) -> tuple[str | None, list[str]]:
    """The canonical form of a response body (JSON only).

    Returns ``(canonical_json_string_or_None, applied_rules)``. A parse
    failure, a non-object/array root, or an oversized body returns
    ``(None, [])`` — the caller falls back to the raw digest (fail-safe).
    """
    text = str(body_text or "").strip()
    if len(text) > _MAX_BODY_BYTES:
        return None, []
    if not text.startswith("{") and not text.startswith("["):
        return None, []
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return None, []
    if not isinstance(parsed, (dict, list)):
        return None, []
    if isinstance(parsed, dict) and len(parsed) > _MAX_BODY_FIELDS:
        return None, ["oversized"]
    dropped = sorted(
        k for k in parsed if isinstance(k, str) and k in VOLATILE_KEYS
    ) if isinstance(parsed, dict) else []
    rules = ["json_sorted_keys"] + ([f"volatile_dropped:{k}" for k in dropped])
    try:
        return json.dumps(_canonical(parsed, 0), sort_keys=True), rules
    except (ValueError, TypeError):  # non-serializable content — fail safe
        return None, []


# ---------------------------------------------------------------------------
# authorization semantics from structured bodies
# ---------------------------------------------------------------------------

def _flatten(body: Mapping[str, Any]) -> dict[str, Any]:
    """One-level flatten of known container keys (``resource.owner`` →
    ``owner``). Outer keys win on conflict — the outermost expression
    is the most explicit."""
    flat: dict[str, Any] = {}
    for key, value in body.items():
        if isinstance(value, Mapping) and str(key) in _CONTAINER_KEYS:
            for inner_key, inner_value in value.items():
                if isinstance(inner_value, (str, int, float, bool)) or inner_value is None:
                    flat.setdefault(str(inner_key), inner_value)
    for key, value in body.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            flat[str(key)] = value
    return flat


def _normalize_outcome(value: Any) -> str | None:
    """Map a body value onto the header grammar's outcome vocabulary."""
    if value is True:
        return "granted_full"
    if value is False:
        return "denied"
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text in OUTCOME_GRANTED:
        return "granted_full"
    if text in OUTCOME_DENIED or text.isdigit() and text in {"401", "403"}:
        return "denied"
    return None


def authorization_semantics(body_text: str) -> tuple[dict[str, str], list[str]]:
    """Extract the authorization semantics a structured body carries.

    Returns ``(context_fields, applied_rules)`` — only channels the
    causal guard reads, only from the documented alias vocabulary.
    Ambiguous or non-scalar values are ignored (never guessed).
    """
    text = str(body_text or "").strip()
    if len(text) > _MAX_BODY_BYTES or not text.startswith("{"):
        return {}, []
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return {}, []
    if not isinstance(parsed, dict):
        return {}, []
    flat = _flatten(parsed)
    if len(flat) > _MAX_BODY_FIELDS:
        return {}, []
    context: dict[str, str] = {}
    rules: list[str] = []
    for key, value in flat.items():
        channel = FIELD_ALIASES.get(str(key))
        if channel is None or channel not in _GUARD_CHANNELS:
            continue
        if value is None or isinstance(value, (dict, list)):
            continue  # nested value under an alias key — not a scalar fact
        if channel == "authorization_outcome":
            outcome = _normalize_outcome(value)
            if outcome is not None:
                context.setdefault(channel, outcome)
                rules.append(f"body:{key}->{outcome}")
        elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
            text_value = str(value).strip()
            if text_value:
                context.setdefault(channel, text_value)
                rules.append(f"body:{key}->{channel}")
    return context, rules


#: The context channel → its header counterpart (the guard reads the
#: header FIRST; enrichment must not fill a channel whose header the
#: response already carried — the header is the more explicit
#: representation and always wins).
_CHANNEL_HEADERS: dict[str, str] = {
    "actor_id": "x-actor-echo",
    "actor_role": "x-actor-role",
    "actor_tenant": "x-actor-tenant",
    "authorization_outcome": "x-authorization-outcome",
    "effective_privilege_granted": "x-effective-privilege-granted",
    "resource_owner": "x-resource-owner",
    "resource_tenant": "x-resource-tenant",
    "resource_type": "x-resource-type",
    "resource_id": "x-resource-id",
    "privilege_required": "x-privilege-required",
}


# ---------------------------------------------------------------------------
# observation enrichment — the integration seam
# ---------------------------------------------------------------------------

def enrich_observation(
    observation: dict[str, Any], *, body_text: str | None = None
) -> dict[str, Any]:
    """Return an enriched copy of an observation.

    Adds (never overrides — headers and explicit fields win):

    * ``canonical_digest``   — sha256 of the canonical body form, when
      the body parses as JSON (else absent → raw digest semantics).
    * ``representation_rules`` — the normalization rules that fired
      (evidence explainability).
    * the guard-readable context channels (``resource_owner``,
      ``authorization_outcome``, …) derived from the body, ONLY for
      channels the observation does not already carry.

    ``body_text`` — the FULL response body when the caller holds it
    (the observation's ``body_preview`` is a 200-char projection and
    is used only as the fallback). The original evidence (raw body
    preview, raw digest, headers) is preserved untouched —
    normalization never destroys evidence.
    """
    out = dict(observation)
    if body_text is None:
        body_text = str(observation.get("body_preview") or "")
    canonical, canonical_rules = canonical_representation(body_text)
    if canonical is not None:
        out["canonical_digest"] = hashlib.sha256(canonical.encode()).hexdigest()
        out["canonical_rules"] = canonical_rules
    context, semantic_rules = authorization_semantics(body_text)
    if context:
        headers = {
            str(k).lower() for k in (observation.get("headers") or {})
        }
        # headers/explicit fields win — only fill channels whose header
        # counterpart is ABSENT and that the observation does not carry
        filled = {
            channel: value
            for channel, value in context.items()
            if observation.get(channel) is None
            and _CHANNEL_HEADERS.get(channel, f"{channel}") not in headers
        }
        if filled:
            out.update(filled)
            out["representation_rules"] = [
                *semantic_rules,
                *(observation.get("representation_rules") or []),
            ]
    return out


def semantic_digest(observation: Mapping[str, Any]) -> str:
    """The observation's semantic digest: canonical when available,
    raw otherwise (the guard's comparison key)."""
    return str(
        observation.get("canonical_digest")
        or observation.get("semantic_digest")
        or ""
    )
