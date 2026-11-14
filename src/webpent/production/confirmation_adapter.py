"""UM-DR-35 corrective closure — the universal CausalGuard confirmation adapter.

Mission contract (UM-DR-35 §1):
    CausalGuard (``webpent.cqa_v2.causal_guard.guarded_causal_evaluate``) is
    the SOLE technical confirmation authority. No validator, scanner, LLM, or
    graph node may mark a finding ``Tool-Confirmed`` / ``Confidence.CONFIRMED``
    / ``PROMOTED`` unless this authority actually adjudicated the exact
    experiment evidence being promoted.

This module is the single adapter every finding-producing route converges on:

    real triple (baseline / candidate / negative control)
        → evidence-grounded guard-observation construction (role ablation)
        → ``guarded_causal_evaluate`` adjudication
        → typed ``GuardedCausalResult`` bound to the exact evidence digests
        → (caller) ProofBundle + replay via ``shared.verifier``

Design rules enforced here:
1.  Every guard-observation field is DERIVED FROM REAL EVIDENCE (recorded
    HTTP response status, response body JSON, response digests, request
    headers, principal binding, identity context). Nothing is fixed or
    caller-asserted. In particular the per-role technical signals for
    baseline, candidate and negative control are computed from the actual
    observations (UM-DR-35 §1.4 role-ablation requirement) — the baseline
    and control signals are NEVER hardcoded to ``False``/``True``.
2.  Fail-closed: missing evidence, missing actor/resource context, or a
    non-CONFIRMED guard verdict yields an explicit blocked/inconclusive
    decision. Uncertainty is never converted into confirmation.
3.  Same-evidence binding: the ``GuardedAdjudication`` records the digest of
    each observation it adjudicated, so the promotion boundary can prove the
    CausalGuard result refers to the exact evidence being promoted (a guard
    verdict for one experiment can never promote a different finding).

The adapter never performs network I/O, never decides authorization, and
never mutates findings. It only adjudicates already-collected, redacted
observations (the executor and scope gates remain the only components
allowed to perform actions).
"""
from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from webpent.cqa_v2.causal_guard import (
    GuardedCausalResult,
    Verdict,
    guarded_causal_evaluate,
)
from webpent.models.evidence import redact_sensitive

__all__ = [
    "GuardedAdjudication",
    "ConfirmationOutcome",
    "ConfirmationDecision",
    "adjudicate_with_causal_guard",
    "role_technical_signals",
    "confirmation_gate",
]

_AUTHORIZATION_DIFFERENTIAL_FAMILIES: frozenset[str] = frozenset({
    "IDOR", "BOLA", "AUTH_BYPASS", "PRIVILEGE_DIFFERENTIAL", "TENANT_ISOLATION",
    "MASS_ASSIGNMENT", "JWT_MANIPULATION", "JWT_KEY_CONFUSION",
})

_ADVISORY = "advisory_only_not_a_confirmation_authority"


# ---------------------------------------------------------------------------
# Evidence-grounded context derivation (Gate: real evidence only)
# ---------------------------------------------------------------------------

def _observation_mapping(observation: Any) -> dict[str, Any]:
    if isinstance(observation, dict):
        return observation
    if hasattr(observation, "__dict__"):
        return dict(getattr(observation, "__dict__"))
    return {}


def _safe_headers(observation: dict[str, Any]) -> dict[str, str]:
    headers = observation.get("headers")
    if not isinstance(headers, dict):
        return {}
    return {str(k): str(v) for k, v in headers.items() if v is not None}


def _header(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _json_body(observation: dict[str, Any]) -> dict[str, Any]:
    """Parse the recorded (already redacted) response body as JSON, if possible."""
    for key in ("response_body", "body", "redacted_body"):
        raw = observation.get(key)
        if isinstance(raw, (str, bytes)) and raw:
            try:
                parsed = json.loads(str(raw))
            except (TypeError, ValueError):
                return {}
            if isinstance(parsed, dict):
                redacted, _ = redact_sensitive(parsed)
                return redacted if isinstance(redacted, dict) else {}
    return {}


def _observation_url(observation: dict[str, Any]) -> str:
    for key in ("request_url", "url", "url_shape"):
        value = observation.get(key)
        if isinstance(value, str) and value:
            return value
    request = observation.get("request")
    if isinstance(request, dict) and isinstance(request.get("url"), str):
        return request["url"]
    return ""


def _observation_path(observation: dict[str, Any]) -> str:
    request = observation.get("request")
    if isinstance(request, dict) and isinstance(request.get("path"), str):
        return request["path"]
    url = _observation_url(observation)
    if url:
        return urlsplit(url).path or "/"
    return ""


def _identity_role_context(
    observation: dict[str, Any],
    role: str,
    identity_context: dict[str, Any] | None,
) -> dict[str, str | None]:
    """Derive the REAL actor context for one observation.

    Sources, in evidence priority order (first wins, all are real evidence):
    1. The observation's own recorded request headers (``X-User`` is the
       vault-resolved M4 principal alias attached by ContextAuthority at
       the single authorize_execution choke point — a forged caller value
       is stripped before the request leaves the executor).
    2. Explicit actor-context headers the target echoed (X-Actor-Echo,
       X-Actor-Role, X-Auth-State ...).
    3. Per-role identity context supplied by the caller
       (``baseline_identity`` / ``candidate_identity`` /
       ``negative_control_identity`` — typed governed identities).
    4. The recorded principal context of the observation
       (``principal_context`` / ``actor_id`` top-level fields).
    """
    headers = _safe_headers(observation)
    actor_id = _header(headers, "X-User") or observation.get("actor_id")
    if not actor_id and isinstance(observation.get("principal_context"), str):
        actor_id = observation["principal_context"]
    actor_role = _header(headers, "X-Actor-Role") or observation.get("actor_role")
    actor_tenant = _header(headers, "X-Actor-Tenant") or observation.get("actor_tenant")
    auth_state = _header(headers, "X-Auth-State") or observation.get("auth_state")

    if not (actor_id or actor_role or auth_state):
        per_role = (identity_context or {}).get(f"{role}_identity")
        if isinstance(per_role, dict):
            actor_id = actor_id or per_role.get("identity_id") or per_role.get("principal")
            actor_role = actor_role or per_role.get("role")
            actor_tenant = actor_tenant or per_role.get("tenant")
            auth_state = auth_state or per_role.get("auth_state")
        elif isinstance(per_role, str):
            actor_id = actor_id or per_role

    return {
        "actor_id": str(actor_id) if actor_id else None,
        "actor_role": str(actor_role) if actor_role else None,
        "actor_tenant": str(actor_tenant) if actor_tenant else None,
        "auth_state": str(auth_state) if auth_state else (
            "authenticated" if actor_id else None
        ),
    }


def _resource_context(observation: dict[str, Any]) -> dict[str, str | None]:
    """Derive the REAL resource context from the recorded response evidence.

    The response body of an authorization-bound resource carries its owner and
    identity fields (e.g. an invoice object includes ``owner``). Those are
    actual observations — never hypothesis assertions. Path segments are used
    only as a last-resort resource-type hint.
    """
    body = _json_body(observation)
    resource_owner = (
        body.get("owner") or body.get("owner_id") or body.get("resource_owner")
        or observation.get("resource_owner")
    )
    resource_id = (
        body.get("id") or body.get("resource_id") or body.get("resourceId")
        or observation.get("resource_id") or observation.get("target_resource")
    )
    resource_type = body.get("resource_type") or body.get("type")
    resource_tenant = body.get("tenant") or body.get("tenant_id") or observation.get("resource_tenant")

    if not resource_type:
        path = _observation_path(observation)
        segments = [segment for segment in path.strip("/").split("/") if segment]
        if len(segments) >= 2 and not str(resource_id or "").startswith("http"):
            # e.g. "/api/invoices/INV-1" -> resource type "invoices"
            resource_type = segments[-2]
        elif segments:
            resource_type = segments[-1]
    # Recorded top-level resource_type on the observation (e.g. the takeover
    # experiment's subdomain_cname / the desync experiment's http_origin —
    # the validator's declared resource identity) as the fallback for
    # root-path observations whose path yields no segments: it is a
    # RECORDED fact of the experiment, never a guess.
    if not resource_type and isinstance(observation.get("resource_type"), str) and observation.get("resource_type"):
        resource_type = str(observation["resource_type"])
    return {
        "resource_type": str(resource_type) if resource_type else None,
        "resource_id": str(resource_id) if resource_id else None,
        "resource_owner": str(resource_owner) if resource_owner else None,
        "resource_tenant": str(resource_tenant) if resource_tenant else None,
    }


def _authorization_outcome(observation: dict[str, Any]) -> str | None:
    """Derive the observed authorization outcome from REAL HTTP evidence.

    ``denied`` for recorded 401/403 responses; ``granted_full`` for a recorded
    2xx response that returned a resource body (non-empty body is the observed
    full grant); ``None`` when the observation does not establish an outcome.
    This is a deterministic mapping of the recorded evidence, not an opinion.
    """
    status = observation.get("status_code", observation.get("status"))
    if status is None:
        return None
    try:
        status = int(status)
    except (TypeError, ValueError):
        return None
    if status in (401, 403):
        return "denied"
    if 200 <= status < 300:
        body = _json_body(observation)
        has_body = bool(body) or bool(
            observation.get("response_digest") or observation.get("body_digest")
        )
        return "granted_full" if has_body else None
    return None


# ---------------------------------------------------------------------------
# Guard-observation construction + role ablation (UM-DR-35 §1.4)
# ---------------------------------------------------------------------------

def build_guard_observation(
    observation: Any,
    role: str,
    *,
    identity_context: dict[str, Any] | None = None,
    extra_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one CausalGuard-shaped observation from the REAL recorded evidence.

    Only recorded evidence is used: the real status code, the real response
    digest (as the semantic digest the guard compares), the real request path,
    the real actor/resource context derived above. The function never invents
    values and never fixes a signal to satisfy an expected verdict.
    """
    obs = _observation_mapping(observation)
    if not obs:
        return {}

    status = obs.get("status_code", obs.get("status"))
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = None

    semantic_digest = None
    for key in ("response_digest", "semantic_digest", "body_digest"):
        value = obs.get(key)
        if isinstance(value, str) and value:
            semantic_digest = value
            break
    if semantic_digest is None:
        structured = obs.get("structured_fields")
        if isinstance(structured, dict):
            value = structured.get("_body_fingerprint")
            if isinstance(value, str) and value:
                semantic_digest = value
    if semantic_digest is not None and not semantic_digest.startswith("sha256:"):
        semantic_digest = f"sha256:{semantic_digest}"

    body_length = obs.get("body_length")
    if body_length is None:
        body_length = obs.get("body_size")
    if body_length is None and isinstance(obs.get("structured_fields"), dict):
        body_length = obs["structured_fields"].get("_body_size")

    actor = _identity_role_context(obs, role, identity_context)
    resource = _resource_context(obs)
    extra = extra_context or {}

    guard_observation: dict[str, Any] = {
        "observation_role": role,
        "status_code": status,
        "semantic_digest": semantic_digest,
        "body_length": int(body_length) if body_length is not None else None,
        "request": {"path": _observation_path(obs), "method": obs.get("request_method", "GET")},
        "actor_id": actor["actor_id"],
        "actor_role": actor["actor_role"],
        "actor_tenant": actor["actor_tenant"],
        "auth_state": actor["auth_state"],
        "resource_type": resource["resource_type"],
        "resource_id": resource["resource_id"],
        "resource_owner": resource["resource_owner"] or extra.get("resource_owner"),
        "resource_tenant": resource["resource_tenant"],
    }
    outcome = _authorization_outcome(obs)
    if outcome:
        guard_observation["authorization_outcome"] = outcome
    if semantic_digest:
        guard_observation["response_digest"] = semantic_digest
    # UM-DR-35 §2 (offline-crypto domain): a RECORDED offline
    # cryptographic verification experiment carries its recorded outcome
    # channel (crypto_verified) and its domain marker; the guard's
    # offline completeness branch reads both. Strict pass-through —
    # absent channels stay absent (fail-closed).
    experiment_domain = obs.get("experiment_domain")
    if experiment_domain:
        guard_observation["experiment_domain"] = str(experiment_domain)[:64]
    crypto_verified = obs.get("crypto_verified")
    if crypto_verified is not None:
        guard_observation["crypto_verified"] = bool(crypto_verified)
    # UM-DR-35 §1.3 condition 8 — the class-specific validator's RECORDED
    # technical signal for this experiment's candidate response (e.g. the
    # deterministic dalfox/sqlmap marker recorded when the validating tool
    # analysed the actual candidate request). Strict pass-through: absent
    # channel stays absent (None downstream — fail-closed); the adapter
    # never invents, upgrades, or broadens it to any other role.
    technical_signal = obs.get("validator_technical_signal")
    if technical_signal is None:
        technical_signal = obs.get("technical_signal")
    if technical_signal is not None:
        guard_observation["validator_technical_signal"] = bool(technical_signal)
    return guard_observation


def _semantic_digest_of(observation: Any) -> str | None:
    obs = _observation_mapping(observation)
    for key in ("response_digest", "semantic_digest", "body_digest"):
        value = obs.get(key)
        if isinstance(value, str) and value:
            return value if value.startswith("sha256:") else f"sha256:{value}"
    structured = obs.get("structured_fields")
    if isinstance(structured, dict):
        value = structured.get("_body_fingerprint")
        if isinstance(value, str) and value:
            return value if value.startswith("sha256:") else f"sha256:{value}"
    return None


def role_technical_signals(
    baseline: Any,
    candidate: Any,
    negative_control: Any,
    *,
    vulnerability_class: str,
    identity_context: dict[str, Any] | None = None,
    extra_context: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """UM-DR-35 §1.4 role ablation — per-role technical signals from ACTUAL evidence.

    Each role's signal is derived from that role's own recorded observation
    (and, where the semantics are comparative, the recorded sibling
    observations). No signal is fixed to ``True``/``False`` because a caller
    expects a particular verdict:
    - ``baseline``: the recorded baseline behavior — expected-state signal
      (e.g. a granted own-resource access, a clean input response).
    - ``candidate``: the recorded candidate exhibits the class-specific
      differential vs the recorded baseline (status and/or semantic digest).
    - ``negative_control``: the recorded control exhibits the enforced /
      independent behavior (denial status, or a distinct semantic digest).
    """
    vuln = str(vulnerability_class or "").upper()
    observations = {
        "baseline": _observation_mapping(baseline),
        "candidate": _observation_mapping(candidate),
        "negative_control": _observation_mapping(negative_control),
    }

    def _status(obs: dict[str, Any]) -> int | None:
        try:
            return int(obs.get("status_code", obs.get("status")))
        except (TypeError, ValueError):
            return None

    def _granted(obs: dict[str, Any]) -> bool:
        status = _status(obs)
        return status is not None and 200 <= status < 300 and bool(
            _json_body(obs) or _semantic_digest_of(obs)
        )

    def _denied(obs: dict[str, Any]) -> bool:
        return _status(obs) in (401, 403)

    b_digest = _semantic_digest_of(observations["baseline"])
    c_digest = _semantic_digest_of(observations["candidate"])
    nc_digest = _semantic_digest_of(observations["negative_control"])

    base_status = _status(observations["baseline"])
    cand_status = _status(observations["candidate"])
    nc_status = _status(observations["negative_control"])

    # Baseline signal: the recorded baseline shows the expected pre-state.
    if vuln in _AUTHORIZATION_DIFFERENTIAL_FAMILIES:
        baseline_expected = _granted(observations["baseline"])
        baseline_basis = "baseline_owner_or_self_access_granted"
    else:
        baseline_expected = base_status is not None and base_status < 500 and bool(b_digest)
        baseline_basis = "baseline_clean_input_response_recorded"

    # Candidate signal: the recorded candidate differs from the recorded baseline.
    candidate_differs = bool(
        (c_digest is not None and b_digest is not None and c_digest != b_digest)
        or (cand_status is not None and base_status is not None and cand_status != base_status)
    )
    if vuln in _AUTHORIZATION_DIFFERENTIAL_FAMILIES:
        candidate_expected = candidate_differs and _granted(observations["candidate"])
        candidate_basis = "candidate_foreign_principal_granted_and_semantically_differs"
    else:
        candidate_expected = candidate_differs
        candidate_basis = "candidate_differential_vs_baseline_recorded"

    # Negative-control signal: the recorded control is independent and enforced
    # (denied) or semantically distinct from both baseline and candidate.
    # UM-DR-35 §1.5: the control completes the experiment when it does
    # not reproduce the CANDIDATE's recorded semantics (its digest
    # differs from the candidate's). For persistence re-probes where the
    # baseline equals the candidate, the distinct-set shrinks to two —
    # completeness is candidate-vs-control, never a 3-way distinctness.
    control_digest_distinct = bool(
        nc_digest and c_digest and nc_digest != c_digest
    )
    # UM-DR-35 §1.5 control-completion semantics (content classes): an
    # inert-value control on the SAME parameter that does NOT reproduce
    # the candidate's differential (it matches the recorded baseline
    # semantics) has COMPLETED the experiment — the divergence is
    # attributable to the candidate input alone. Denied/4xx controls and
    # fully-distinct digests also complete it. Only a control that
    # reproduces the candidate's signal leaves it incomplete.
    control_matches_baseline = bool(
        nc_digest is not None and b_digest is not None and nc_digest == b_digest
    )
    # Authorization-differential families keep the STRICT control
    # contract (denied / 4xx boundary / fully-distinct semantics): an
    # owner-access body re-used as the control is a CONTAMINATED control
    # (§1.5 negative matrix), never a completed one. The inert-baseline
    # relaxation applies ONLY to content classes, whose baseline is a
    # same-parameter inert re-probe.
    # Object-authorization subfamilies (IDOR/BOLA/tenant isolation and
    # their bypass classes) keep the STRICT boundary contract: the
    # control completes ONLY as an enforced boundary — a recorded
    # denial (401/403) or resource boundary (404/400). Digest
    # distinctness alone is NOT completion for these (a contaminated
    # control re-playing any non-candidate body must not count as an
    # enforced boundary). MASS_ASSIGNMENT (an authorization-family
    # class whose control is a same-endpoint inert-field probe) and
    # JWT manipulation classes complete on denied/4xx OR a digest
    # distinct from the candidate (the control did not reproduce the
    # acceptance/verification differential).
    _OBJECT_AUTHORIZATION_FAMILIES = {
        "IDOR", "BOLA", "AUTH_BYPASS", "PRIVILEGE_DIFFERENTIAL",
        "TENANT_ISOLATION",
    }
    if vuln in _OBJECT_AUTHORIZATION_FAMILIES:
        control_expected = _denied(observations["negative_control"]) or (
            nc_status is not None and nc_status in (404, 400)
        )
    else:
        control_expected = (
            _denied(observations["negative_control"])
            or (nc_status is not None and nc_status in (404, 400))
            or control_digest_distinct
            or (control_matches_baseline and candidate_differs)
        )
    control_basis = "negative_control_denied_or_independent_digest"

    signals = {
        "baseline": {
            "signal": baseline_expected,
            "basis": baseline_basis,
            "status_code": base_status,
            "semantic_digest": b_digest,
            "derived_from": "recorded_baseline_observation",
        },
        "candidate": {
            "signal": candidate_expected,
            "basis": candidate_basis,
            "status_code": cand_status,
            "semantic_digest": c_digest,
            "differs_from_baseline": candidate_differs,
            "derived_from": "recorded_candidate_observation",
        },
        "negative_control": {
            "signal": control_expected,
            "basis": control_basis,
            "status_code": nc_status,
            "semantic_digest": nc_digest,
            "distinct_digest": control_digest_distinct,
            "derived_from": "recorded_negative_control_observation",
        },
    }
    # Record explicitly when a role's evidence was absent (never guessed).
    for role, payload in signals.items():
        if not observations[role]:
            payload["signal"] = None
            payload["basis"] = "observation_absent"
    return signals


# ---------------------------------------------------------------------------
# Adjudication — the single authority call
# ---------------------------------------------------------------------------

def _digest_of_observation(observation: Any) -> str:
    """Canonical digest binding an adjudication to its exact input evidence."""
    obs = _observation_mapping(observation)
    material = {
        key: obs.get(key)
        for key in sorted(obs)
        if key in {
            "status_code", "status", "response_digest", "body_digest",
            "request_digest", "semantic_digest", "body_length", "body_size",
            "request_url", "url", "url_shape", "request_method",
            "principal_context", "resource_owner", "resource_id",
            "response_body", "body", "redacted_body",
        }
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(encoded.encode('utf-8', 'replace')).hexdigest()}"


@dataclass(frozen=True)
class GuardedAdjudication:
    """Typed CausalGuard adjudication bound to the exact adjudicated evidence."""

    guard_result: GuardedCausalResult
    guard_module: str
    vulnerability_class: str
    role_signals: dict[str, dict[str, Any]]
    guard_observation_digests: dict[str, str]
    evidence_digests: dict[str, str]
    derived_context: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        return self.guard_result.verdict is Verdict.CONFIRMED

    def to_dict(self) -> dict[str, Any]:
        result = self.guard_result
        return {
            "authority": "webpent.cqa_v2.causal_guard.guarded_causal_evaluate",
            "adjudicated_by": "webpent.production.confirmation_adapter",
            "verdict": str(result.verdict.value),
            "causal_signal": result.causal_signal,
            "authorization_differential": result.authorization_differential,
            "confidence": result.confidence,
            "confidence_factors": dict(result.confidence_factors or {}),
            "block_reason": result.block_reason,
            "vulnerability_class": self.vulnerability_class,
            "role_technical_signals": self.role_signals,
            "guard_observation_digests": dict(self.guard_observation_digests),
            "evidence_digests": dict(self.evidence_digests),
            "derived_context": self.derived_context,
        }


def adjudicate_with_causal_guard(
    baseline: Any,
    candidate: Any,
    negative_control: Any,
    *,
    vulnerability_class: str,
    identity_context: dict[str, Any] | None = None,
    extra_context: dict[str, Any] | None = None,
    safe_precondition: str = "read_only_no_state_mutation",
) -> GuardedAdjudication:
    """Run the CausalGuard authority over the REAL recorded triple.

    The triple is reshaped into guard observations strictly from recorded
    evidence (status, digests, response-body identity fields, request-header
    actor binding, typed identity context). The authority's verdict is
    returned unmodified — this adapter never overrides, upgrades, or
    fabricates a verdict (fail-closed on any non-CONFIRMED outcome).
    """
    guard_baseline = build_guard_observation(
        baseline, "baseline",
        identity_context=identity_context, extra_context=extra_context,
    )
    guard_candidate = build_guard_observation(
        candidate, "candidate",
        identity_context=identity_context, extra_context=extra_context,
    )
    guard_control = build_guard_observation(
        negative_control, "negative_control",
        identity_context=identity_context, extra_context=extra_context,
    )

    guard_result = guarded_causal_evaluate(
        baseline=guard_baseline,
        candidate=guard_candidate,
        control=guard_control,
        safe_precondition=safe_precondition,
    )
    role_signals = role_technical_signals(
        baseline, candidate, negative_control,
        vulnerability_class=vulnerability_class,
        identity_context=identity_context,
        extra_context=extra_context,
    )
    return GuardedAdjudication(
        guard_result=guard_result,
        guard_module="webpent.cqa_v2.causal_guard.guarded_causal_evaluate",
        vulnerability_class=str(vulnerability_class or "UNKNOWN").upper(),
        role_signals=role_signals,
        guard_observation_digests={
            role: _digest_of_observation(obs)
            for role, obs in (
                ("baseline", guard_baseline),
                ("candidate", guard_candidate),
                ("negative_control", guard_control),
            )
        },
        evidence_digests={
            role: _digest_of_observation(obs)
            for role, obs in (
                ("baseline", baseline),
                ("candidate", candidate),
                ("negative_control", negative_control),
            )
        },
        derived_context={
            "baseline": {k: v for k, v in guard_baseline.items() if k in {
                "actor_id", "actor_role", "resource_type", "resource_id",
                "resource_owner", "authorization_outcome", "status_code",
            }},
            "candidate": {k: v for k, v in guard_candidate.items() if k in {
                "actor_id", "actor_role", "resource_type", "resource_id",
                "resource_owner", "authorization_outcome", "status_code",
            }},
            "negative_control": {k: v for k, v in guard_control.items() if k in {
                "actor_id", "actor_role", "resource_type", "resource_id",
                "resource_owner", "authorization_outcome", "status_code",
            }},
        },
    )


# ---------------------------------------------------------------------------
# The universal confirmation gate (used by graph/AVI paths)
# ---------------------------------------------------------------------------

class ConfirmationOutcome(str, enum.Enum):
    CONFIRMED = "CONFIRMED"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"
    CLEAN = "CLEAN"


@dataclass(frozen=True)
class ConfirmationDecision:
    """Outcome of the universal confirmation gate (never a raw boolean)."""

    outcome: ConfirmationOutcome
    reason: str
    adjudication: GuardedAdjudication | None
    provenance: dict[str, Any] = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        return self.outcome is ConfirmationOutcome.CONFIRMED

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": str(self.outcome.value),
            "reason": self.reason,
            "confirmation_authority": "causal_guard_universal_boundary",
            "adjudication": self.adjudication.to_dict() if self.adjudication else None,
            "provenance": dict(self.provenance),
        }


def confirmation_gate(
    baseline: Any,
    candidate: Any,
    negative_control: Any,
    *,
    vulnerability_class: str,
    validator_outcome: str | None,
    validator_id: str,
    identity_context: dict[str, Any] | None = None,
    scope_context: dict[str, Any] | None = None,
    extra_context: dict[str, Any] | None = None,
) -> ConfirmationDecision:
    """The one universal confirmation boundary for graph/AVI promotion routes.

    Order of authority (UM-DR-35 §1.3):
      1. scope/authorization context must be present (fail-closed),
      2. a class-specific validator must have supplied its technical outcome
         (advisory scanners and LLMs never satisfy this),
      3. CausalGuard must adjudicate the exact evidence CONFIRMED,
      4. the per-role technical signals must be evidence-derived (recorded).

    This gate does NOT build the ProofBundle or run replay itself — those stay
    in ``shared.verifier.verify_replay_evidence`` (the bundle/replay authority),
    which independently re-runs this same CausalGuard adjudication. Promotion
    requires BOTH (defense in depth at the same boundary).
    """
    provenance: dict[str, Any] = {
        "gate": "webpent.production.confirmation_adapter.confirmation_gate",
        "validator_id": str(validator_id)[:120],
        "validator_outcome": validator_outcome,
        "vulnerability_class": str(vulnerability_class or "UNKNOWN").upper(),
    }

    if not scope_context:
        return ConfirmationDecision(
            ConfirmationOutcome.BLOCKED, "scope_context_required", None, provenance,
        )

    adjudication = adjudicate_with_causal_guard(
        baseline, candidate, negative_control,
        vulnerability_class=vulnerability_class,
        identity_context=identity_context,
        extra_context=extra_context,
    )
    provenance["adjudication"] = adjudication.to_dict()

    if adjudication.guard_result.verdict is Verdict.BLOCKED:
        return ConfirmationDecision(
            ConfirmationOutcome.BLOCKED,
            f"causal_guard_blocked:{adjudication.guard_result.block_reason}",
            adjudication, provenance,
        )
    if adjudication.guard_result.verdict is Verdict.CLEAN:
        return ConfirmationDecision(
            ConfirmationOutcome.CLEAN, "causal_guard_clean", adjudication, provenance,
        )
    if adjudication.guard_result.verdict is Verdict.INCONCLUSIVE:
        # UM-DR-35 §1.5 failure attribution: an inconclusive guard with
        # a control that failed the completion contract (its own signal
        # is False — e.g. a control that merely re-plays the baseline)
        # is attributed to the CONTROL: BLOCKED, never "unknown". Only
        # a guard that is inconclusive with a completed control stays
        # genuinely INCONCLUSIVE.
        if adjudication.role_signals.get("negative_control", {}).get("signal") is False:
            return ConfirmationDecision(
                ConfirmationOutcome.BLOCKED,
                "negative_control_technical_signal_absent",
                adjudication, provenance,
            )
        return ConfirmationDecision(
            ConfirmationOutcome.INCONCLUSIVE,
            f"causal_guard_inconclusive:{adjudication.guard_result.raw_decision}",
            adjudication, provenance,
        )
    if adjudication.guard_result.verdict is not Verdict.CONFIRMED:
        return ConfirmationDecision(
            ConfirmationOutcome.BLOCKED, "causal_guard_unexpected_verdict",
            adjudication, provenance,
        )

    # CONFIRMED — require the validator's own technical signal to be present
    # as well (class-specific evidence + CausalGuard authority, UM-DR-35 §1.3
    # conditions 8 and 9 together).
    validator_confirmed = str(validator_outcome or "").upper() == "CONFIRMED"
    if not validator_confirmed:
        return ConfirmationDecision(
            ConfirmationOutcome.BLOCKED,
            "class_validator_outcome_not_confirmed",
            adjudication, provenance,
        )

    # Role signals must be recorded (evidence-derived), with the candidate
    # differential and the independent negative control actually observed.
    signals = adjudication.role_signals
    if signals.get("candidate", {}).get("signal") is not True:
        return ConfirmationDecision(
            ConfirmationOutcome.BLOCKED, "candidate_technical_signal_absent",
            adjudication, provenance,
        )
    if signals.get("negative_control", {}).get("signal") is not True:
        return ConfirmationDecision(
            ConfirmationOutcome.BLOCKED, "negative_control_technical_signal_absent",
            adjudication, provenance,
        )

    return ConfirmationDecision(
        ConfirmationOutcome.CONFIRMED,
        "causal_guard_confirmed_with_validator_signal",
        adjudication, provenance,
    )
