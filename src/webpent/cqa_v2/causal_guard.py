"""
CQA v2 — Causal Guard (UPGRADED for Gates 1+2)

Extends the causal evaluator to require a MEANINGFUL AUTHORIZATION
DIFFERENTIAL for vulnerability confirmation, not merely an HTTP response
difference. Uses the extended observation model which captures actor,
role, tenant, resource, ownership, and authorization context.

UM-DR-35 §1.1/§3 (UM-DR-35.1): this module is the SOLE vulnerability-
confirmation authority. Specialized validators, LLMs, planners, exploiters
and external scanners produce STRUCTURED EVIDENCE ONLY; their claims are
adjudicated here (``guarded_causal_evaluate`` for authorization-class
families, ``guarded_causal_evaluate_experiment`` for the full experiment
fabric) before any promotion decision. A validator label, trace string,
component name, or confidence score is NEVER a confirmation.

Governance:
- BLOCKED never transitions to CONFIRMED or CLEAN (hard invariant)
- Ground truth is NEVER imported or read by this module
- No route-specific hardcoding — only structural + context features
- Fail-closed: insufficient context → BLOCKED, not guessed
- A contaminated negative control (signal in control) → BLOCKED, never
  confirmed (UM-DR-35 §1.3: controls must be independent and clean)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ============================================================
# Verdict enum — unchanged interface
# ============================================================
class Verdict(Enum):
    CONFIRMED = "CONFIRMED"
    CLEAN = "CLEAN"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"


# ============================================================
# Result dataclass — extended with confidence factors for audit
# ============================================================
@dataclass
class GuardedCausalResult:
    verdict: Verdict
    causal_signal: bool | None
    confidence: float
    confidence_factors: dict[str, float] = field(default_factory=dict)
    block_reason: str | None = None
    raw_decision: str | None = None
    authorization_differential: bool | None = None
    _no_truth_labels: bool = True  # Governance marker


# ============================================================
# Extended observation model — Gate 1
# ============================================================
def _extract_context(obs: dict[str, Any]) -> dict[str, Any]:
    """
    Extract authorization and resource context from an observation.
    Context comes from OBSERVABLE HTTP response headers (X-*) and body.
    Returns a flat dict with all context fields, None where missing.
    """
    if not obs or not isinstance(obs, dict):
        return {}

    headers = obs.get("headers", {}) or {}

    def _g(key: str) -> str | None:
        """Get context value from headers or top-level obs fields."""
        for hk, hv in headers.items():
            if hk.lower() == key.lower():
                return str(hv) if hv is not None else None
        val = obs.get(key)
        if val is not None:
            return str(val)
        for prefix in ["X-", "x-", ""]:
            val = obs.get(prefix + key)
            if val is not None:
                return str(val)
        return None

    return {
        "actor_id": _g("X-Actor-Echo") or _g("actor_id"),
        "actor_role": _g("X-Actor-Role") or _g("actor_role"),
        "actor_tenant": _g("X-Actor-Tenant") or _g("actor_tenant"),
        "auth_state": _g("X-Auth-State") or _g("auth_state"),
        # UM-DR-28 (representation-equivalence repair): these four
        # channels were header-ONLY while every other channel had the
        # top-level observation fallback — a body-represented
        # authorization outcome (the representation_equivalence /
        # alias_bypass miss class, M10 RCA §2.4) was invisible to the
        # guard even after the observation layer surfaced it. The same
        # ``or _g(snake_case)`` pattern the other channels use closes
        # the asymmetry; headers still win (checked first in _g).
        "effective_privilege": _g("X-Effective-Privilege") or _g("effective_privilege"),
        "effective_privilege_granted": _g("X-Effective-Privilege-Granted") or _g("effective_privilege_granted"),
        "authorization_outcome": _g("X-Authorization-Outcome") or _g("authorization_outcome"),
        "data_redacted": _g("X-Data-Redacted") or _g("data_redacted"),
        "resource_type": _g("X-Resource-Type") or _g("resource_type"),
        "resource_id": _g("X-Resource-Id") or _g("resource_id"),
        "resource_owner": _g("X-Resource-Owner") or _g("resource_owner"),
        "resource_tenant": _g("X-Resource-Tenant") or _g("resource_tenant"),
        "privilege_required": _g("X-Privilege-Required") or _g("privilege_required"),
        "is_public": _g("X-Resource-Public") or _g("is_public"),
    }


def _observation_complete(obs: dict[str, Any]) -> bool:
    """
    Check if an observation was actually executed and has enough context
    for causal discrimination.

    Gate 1 requirement: need HTTP data PLUS at least some authorization
    or resource context. Without context, we cannot distinguish
    "authorization bypass" from "different endpoint returning different data."
    """
    if not obs:
        return False
    if not isinstance(obs, dict):
        return False
    if obs.get("status_code") is None:
        return False
    if not obs.get("semantic_digest"):
        return False
    if obs.get("_placeholder"):
        return False

    ctx = _extract_context(obs)
    has_actor = bool(ctx.get("actor_id") or ctx.get("auth_state"))
    has_resource = bool(ctx.get("resource_type") or ctx.get("resource_id") or ctx.get("resource_owner"))
    return not (not has_actor and not has_resource)


# ============================================================
# Semantic + structural helpers
# ============================================================
def _semantic_diff_significant(a: dict[str, Any], b: dict[str, Any]) -> bool:
    if not a or not b:
        return False
    a_digest = str(a.get("semantic_digest", ""))
    b_digest = str(b.get("semantic_digest", ""))
    if a_digest and b_digest and a_digest != b_digest:
        return True
    a_status = a.get("status_code")
    b_status = b.get("status_code")
    if a_status is not None and b_status is not None and a_status != b_status:
        return True
    a_len = a.get("body_length")
    b_len = b.get("body_length")
    if a_len is not None and b_len is not None:
        try:
            if abs(int(a_len) - int(b_len)) > 50:
                return True
        except (ValueError, TypeError):
            pass
            # Intentionally suppressed — reviewed 2026-09-03
    return False


def _get_path(obs: dict[str, Any]) -> str:
    request = obs.get("request") or {}
    return str(request.get("path", ""))


def _path_prefix(path: str) -> str:
    parts = [p for p in path.strip("/").split("/") if p]
    if len(parts) <= 1:
        return path.strip("/")
    return "/" + "/".join(parts[:-1])


def _path_analogous(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """
    Check if two request paths are structurally analogous — i.e., they
    represent the SAME KIND of access attempt.

    Gate 2 upgrade: if resource type context is available for BOTH,
    different resource types immediately mean NOT analogous.
    """
    # If we have observable resource type context for both, use it first
    ca = _extract_context(a)
    cb = _extract_context(b)
    if ca.get("resource_type") and cb.get("resource_type"):
        if ca["resource_type"] != cb["resource_type"]:
            return False

    path_a = _get_path(a)
    path_b = _get_path(b)
    parts_a = [p for p in path_a.strip("/").split("/") if p]
    parts_b = [p for p in path_b.strip("/").split("/") if p]

    env_prefixes = {"patched", "control", "v1", "v2", "api"}
    while parts_a and parts_a[0] in env_prefixes:
        parts_a = parts_a[1:]
    while parts_b and parts_b[0] in env_prefixes:
        parts_b = parts_b[1:]

    n = min(len(parts_a), len(parts_b))
    if n == 0:
        return False
    suffix_a = parts_a[-n:]
    suffix_b = parts_b[-n:]

    if len(suffix_a) != len(suffix_b):
        return False

    def _features(parts):
        depth = len(parts)
        last = parts[-1] if parts else ""
        has_id_like = bool(re.search(r"(?:^|[-_])(?:\d+|[a-f0-9]{6,}|missing|deleted|unknown)$", last))
        has_generic = last in ("profile", "settings", "health", "config", "info", "me",
                               "orders", "users", "admin", "approve", "review", "details",
                               "dashboard", "validate", "docs", "items", "self", "protected",
                               "transfer", "tenant", "workflows", "chain", "effective-role")
        penultimate = parts[-2] if len(parts) >= 2 else ""
        return {"depth": depth, "last": last, "penultimate": penultimate,
                "has_id_like": has_id_like, "has_generic": has_generic}

    fa = _features(suffix_a)
    fb = _features(suffix_b)
    if fa["depth"] != fb["depth"]:
        return False
    if fa["has_id_like"] and fb["has_id_like"]:
        # Both access specific objects — analogous IF penultimate segment matches
        # (e.g., /users/{id} and /users/{id} are analogous; /users/{id} vs /orders/{id} are NOT)
        return bool(fa["depth"] >= 2 and fa["penultimate"] == fb["penultimate"])
    if fa["has_generic"] and fb["has_generic"]:
        # Both access generic endpoints — analogous only if the actual
        # endpoint names match (dashboard != users, etc.)
        return fa["last"] == fb["last"]
    if not fa["has_id_like"] and not fa["has_generic"] and not fb["has_id_like"] and not fb["has_generic"]:
        return fa["last"] == fb["last"]
    return False


# ============================================================
# Authorization differential analysis — Gate 2 core
# ============================================================
def _same_actor_context(a: dict[str, Any], b: dict[str, Any]) -> bool:
    ca = _extract_context(a)
    cb = _extract_context(b)
    if ca.get("actor_id") and cb.get("actor_id") and ca["actor_id"] != cb["actor_id"]:
        return False
    if ca.get("actor_role") and cb.get("actor_role") and ca["actor_role"] != cb["actor_role"]:
        return False
    if ca.get("actor_tenant") and cb.get("actor_tenant"):
        if ca["actor_tenant"] != cb["actor_tenant"]:
            return False
    return True


def _same_resource_type(a: dict[str, Any], b: dict[str, Any]) -> bool:
    ca = _extract_context(a)
    cb = _extract_context(b)
    if ca.get("resource_type") and cb.get("resource_type"):
        return ca["resource_type"] == cb["resource_type"]
    return _path_prefix(_get_path(a)) == _path_prefix(_get_path(b))


def _authorization_mismatch(obs: dict[str, Any]) -> bool | None:
    """
    Does the observation show an AUTHORIZATION MISMATCH?
    Actor is accessing a resource they should NOT be able to access.

    Returns:
        True  = clear authorization mismatch (vulnerability signal)
        False = proper authorization observed
        None  = insufficient context to determine
    """
    ctx = _extract_context(obs)
    actor_id = ctx.get("actor_id")
    actor_role = ctx.get("actor_role")
    actor_tenant = ctx.get("actor_tenant")
    resource_owner = ctx.get("resource_owner")
    resource_tenant = ctx.get("resource_tenant")
    privilege_required = ctx.get("privilege_required")
    status = obs.get("status_code")

    if not actor_id:
        return None

    if status in (401, 403):
        return False

    # PHASE 6 UPGRADE: Semantic differential analysis
    # Detect IDOR / ownership boundary violations even when privilege_required is absent
    authorization_outcome = ctx.get("authorization_outcome", "")
    if (authorization_outcome == "granted_full" and status == 200):
        # Resource owner differs from actor identity → IDOR pattern
        if resource_owner and actor_id and resource_owner != actor_id:
            return True
        # Resource tenant differs from actor tenant → tenant isolation pattern
        if resource_tenant and actor_tenant and resource_tenant != actor_tenant:
            return True

    # Effective privilege escalation check (before owner check)
    # Business logic abuse: actor IS the owner but was granted elevated privileges
    eff_granted = ctx.get("effective_privilege_granted")
    if eff_granted and actor_role and eff_granted != actor_role:
        role_hierarchy = {"anonymous": 0, "restricted": 0, "positive_only": 0, "public": 0,
                          "user": 1, "self": 1, "tenant_member": 1, "workspace_member": 1, "member": 1, "viewer": 1,
                          "reviewer": 2, "owner": 2, "editor": 2,
                          "manager": 3,
                          "admin": 4, "cross_tenant": 4, "cross_org": 4, "cross_workspace": 4,
                          "full": 5, "unrestricted": 5}
        granted_level = role_hierarchy.get(eff_granted.lower(), 0)
        actor_level = role_hierarchy.get(actor_role.lower(), 0)
        if granted_level > actor_level:
            return True

    # Owner access — legitimate (only when no elevated privilege detected)
    if resource_owner and actor_id == resource_owner:
        return False

    # Admin accessing admin resource — legitimate
    if actor_role == "admin" and privilege_required == "admin":
        return False

    # Role match for workflow-type resources — legitimate
    if privilege_required and actor_role and privilege_required == actor_role:
        return False

    # Same-tenant access for tenant-scoped resources
    if resource_tenant and actor_tenant and resource_tenant == actor_tenant:
        if privilege_required in ("same_tenant", "same_tenant_or_admin", "tenant_members"):
            return False
        if resource_owner and resource_owner != actor_id and privilege_required in ("owner_or_admin", "owner"):
            return True

    # Self-only resources accessed by non-self
    if privilege_required == "self" and resource_owner and actor_id != resource_owner:
        return True

    # Admin resources accessed by non-admin
    if privilege_required == "admin" and actor_role != "admin":
        return True

    # Cross-tenant access to tenant-scoped resource
    if resource_tenant and actor_tenant and resource_tenant != actor_tenant:
        return True

    # Effective privilege granted differs from actor's actual role
    eff_granted = ctx.get("effective_privilege_granted")
    if eff_granted and actor_role and eff_granted != actor_role:
        # If the granted privilege is higher/stronger than the actor's role,
        # this is a privilege escalation signal
        role_hierarchy = {"anonymous": 0, "restricted": 0, "positive_only": 0, "public": 0,
                          "user": 1, "self": 1, "tenant_member": 1, "workspace_member": 1, "member": 1, "viewer": 1,
                          "reviewer": 2, "owner": 2, "editor": 2,
                          "manager": 3,
                          "admin": 4, "cross_tenant": 4, "cross_org": 4, "cross_workspace": 4,
                          "full": 5, "unrestricted": 5}
        granted_level = role_hierarchy.get(eff_granted.lower(), 0)
        actor_level = role_hierarchy.get(actor_role.lower(), 0)
        if granted_level > actor_level:
            return True

    # Required role not possessed by actor (workflow, RBAC patterns)
    if privilege_required and actor_role and privilege_required not in ("self", "owner", "owner_or_admin",
             "same_tenant", "same_tenant_or_admin", "tenant_members", "authenticated", "none"):
        if privilege_required != actor_role and actor_role != "admin":
            return True

    # Sensitive data exposure: actor accessing sensitive fields of another user
    rtype = ctx.get("resource_type", "")
    if rtype and "detail" in rtype.lower() and resource_owner and actor_id != resource_owner:
        if privilege_required in ("owner_or_admin", "owner") and actor_role != "admin":
            return True

    # Business logic: transfer/validation with privilege_required=self but
    # resource indicates a different scope
    if rtype and ("transfer" in rtype.lower() or "validation" in rtype.lower()):
        if privilege_required == "self" and resource_owner and actor_id != resource_owner:
            return True

    # Specific resource owner different from actor, requires owner/admin
    if resource_owner and actor_id != resource_owner:
        if privilege_required in ("owner_or_admin", "owner") and actor_role != "admin":
            return True

    return None


def _authorization_enforced(obs: dict[str, Any]) -> bool | None:
    """
    Check if authorization is being ENFORCED in this observation.
    Uses multiple signals: status code, explicit authorization outcome header,
    data redaction marker, and authorization mismatch analysis.
    """
    status = obs.get("status_code")
    ctx = _extract_context(obs)

    # Explicit denial via status code
    if status in (401, 403):
        return True

    # Explicit authorization outcome header (strongest signal)
    outcome = ctx.get("authorization_outcome")
    if outcome:
        outcome_l = outcome.lower()
        if outcome_l in ("denied", "granted_with_redaction", "granted_with_restriction",
                         "partial", "restricted"):
            return True
        if outcome_l == "granted_full":
            # Full access granted — check if this is legitimate
            mismatch = _authorization_mismatch(obs)
            if mismatch is True:
                return False  # Full access granted but should NOT be — bypass
            if mismatch is False:
                return True   # Full access granted legitimately
            return None

    # Data redaction marker — enforcement via data-level restriction
    if ctx.get("data_redacted") and ctx["data_redacted"].lower() == "true":
        return True

    # Fallback: status + mismatch analysis
    if status == 200:
        mismatch = _authorization_mismatch(obs)
        if mismatch is False:
            return True
        if mismatch is True:
            return False
    return None


# ============================================================
# Dynamic confidence — evidence-derived, auditable (Gate 7)
# ============================================================
def _compute_dynamic_confidence(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    control: dict[str, Any],
    branch: str,
    auth_mismatch: bool | None,
    auth_enforced_in_control: bool | None,
) -> tuple[float, dict[str, float]]:
    base_anchors = {
        "clean_same_semantics": 0.88,
        "clean_same_resource": 0.82,
        "confirmed_bypass": 0.85,
        "clean_different_kind": 0.80,
        "clean_same_as_control": 0.86,
        "inconclusive": 0.40,
    }
    base = base_anchors.get(branch, 0.5)

    factors: dict[str, float] = {}
    factors["base_anchor"] = base

    try:
        bl = abs(int(candidate.get("body_length", 0)) - int(baseline.get("body_length", 0)))
        body_signal = min(bl / 5000.0, 1.0) * 0.06
    except Exception:
        body_signal = 0.0
    factors["body_length_delta"] = round(body_signal, 4)

    try:
        sc_diff = abs(int(candidate.get("status_code", 0)) - int(baseline.get("status_code", 0)))
        status_signal = min(sc_diff / 400.0, 1.0) * 0.05
    except Exception:
        status_signal = 0.0
    factors["status_delta"] = round(status_signal, 4)

    if auth_mismatch is True:
        auth_signal = 0.08
    elif auth_mismatch is False:
        auth_signal = -0.04
    else:
        auth_signal = 0.0
    factors["auth_mismatch"] = round(auth_signal, 4)

    ctrl_status = control.get("status_code", 0)
    if auth_enforced_in_control is True or ctrl_status == 403:
        ctrl_signal = 0.05
    elif ctrl_status == 401:
        ctrl_signal = 0.04
    elif ctrl_status == 404:
        ctrl_signal = 0.01
    else:
        ctrl_signal = 0.0
    factors["control_strength"] = round(ctrl_signal, 4)

    cand_digest = str(candidate.get("semantic_digest", ""))
    ctrl_digest = str(control.get("semantic_digest", ""))
    semantic_signal = 0.03 if cand_digest and ctrl_digest and cand_digest != ctrl_digest else 0.0
    factors["semantic_divergence"] = round(semantic_signal, 4)

    ctx_cand = _extract_context(candidate)
    ctx_ctrl = _extract_context(control)
    ctx_baseline = _extract_context(baseline)
    missing_context = 0
    for ctx in [ctx_cand, ctx_ctrl, ctx_baseline]:
        if not ctx.get("actor_id"):
            missing_context += 1
        if not ctx.get("resource_type") and not ctx.get("resource_owner"):
            missing_context += 1
    completeness_penalty = -(missing_context * 0.03)
    factors["context_completeness_penalty"] = round(completeness_penalty, 4)

    if branch == "confirmed_bypass":
        confidence = base + body_signal + status_signal + auth_signal + ctrl_signal + semantic_signal + completeness_penalty
    elif branch in ("clean_same_semantics", "clean_same_resource", "clean_different_kind", "clean_same_as_control"):
        confidence = base + (0.06 - body_signal) * 0.5 + ctrl_signal * 0.5 + completeness_penalty
    else:
        confidence = base + completeness_penalty

    confidence = round(min(max(confidence, 0.01), 0.99), 4)
    factors["final_confidence"] = confidence

    return confidence, factors


# ============================================================
# Main causal evaluator — upgraded for Gates 1+2
# ============================================================
def guarded_causal_evaluate(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    control: dict[str, Any],
    safe_precondition: str = "read_only_no_state_mutation",
) -> GuardedCausalResult:
    """
    Evaluate causality with strict boundary enforcement.

    UPGRADED (Gates 1+2): Vulnerability confirmation now requires:
      1. candidate differs semantically from baseline
      2. candidate is path-analogous to control (same kind of access attempt)
      3. candidate differs semantically from control
      4. SAME actor context across baseline/candidate/control
      5. SAME resource type being accessed
      6. AUTHORIZATION MISMATCH observed in candidate
      7. AUTHORIZATION ENFORCEMENT observed in control

    Without the authorization differential (points 4-7), an HTTP response
    difference alone is NOT sufficient to confirm a vulnerability.
    """
    if not _observation_complete(baseline):
        return GuardedCausalResult(
            verdict=Verdict.BLOCKED, causal_signal=None, confidence=0.0,
            block_reason="baseline_observation_incomplete_or_missing_context",
        )
    if not _observation_complete(candidate):
        return GuardedCausalResult(
            verdict=Verdict.BLOCKED, causal_signal=None, confidence=0.0,
            block_reason="candidate_observation_incomplete_or_missing_context",
        )
    if not _observation_complete(control):
        return GuardedCausalResult(
            verdict=Verdict.BLOCKED, causal_signal=None, confidence=0.0,
            block_reason="negative_control_observation_incomplete_or_missing_context",
        )

    candidate_differs_from_baseline = _semantic_diff_significant(baseline, candidate)
    candidate_differs_from_control = _semantic_diff_significant(candidate, control)
    candidate_analogous_to_control = _path_analogous(candidate, control)
    candidate_same_resource_type_as_baseline = (
        _path_prefix(_get_path(candidate)) == _path_prefix(_get_path(baseline))
    )

    same_actor = _same_actor_context(baseline, candidate) and _same_actor_context(candidate, control)
    same_resource = _same_resource_type(candidate, control)
    auth_mismatch = _authorization_mismatch(candidate)
    auth_enforced = _authorization_enforced(control)

    verdict = Verdict.INCONCLUSIVE
    causal_signal: bool | None = False
    raw_decision = "INCONCLUSIVE"
    branch = "inconclusive"

    if not candidate_differs_from_baseline:
        verdict = Verdict.CLEAN
        causal_signal = False
        branch = "clean_same_semantics"
        raw_decision = "CLEAN"

    elif candidate_same_resource_type_as_baseline and not candidate_analogous_to_control:
        verdict = Verdict.CLEAN
        causal_signal = False
        branch = "clean_same_resource"
        raw_decision = "CLEAN"

    elif (candidate_analogous_to_control
          and candidate_differs_from_control
          and same_actor
          and same_resource
          and auth_mismatch is True
          and auth_enforced is True):
        verdict = Verdict.CONFIRMED
        causal_signal = True
        branch = "confirmed_bypass"
        raw_decision = "CONFIRMED"

    elif candidate_analogous_to_control and not candidate_differs_from_control:
        # Candidate behaves IDENTICALLY to control — same outcome on the
        # same kind of access attempt. Either both properly blocked (401/403)
        # or both succeed because access is legitimate. Either way: NO vuln.
        verdict = Verdict.CLEAN
        causal_signal = False
        branch = "clean_same_as_control"
        raw_decision = "CLEAN"

    elif candidate_analogous_to_control and candidate_differs_from_control:
        verdict = Verdict.INCONCLUSIVE
        causal_signal = None
        branch = "inconclusive"
        raw_decision = "INCONCLUSIVE_INSUFFICIENT_AUTH_CONTEXT"

    elif not candidate_analogous_to_control:
        verdict = Verdict.CLEAN
        causal_signal = False
        branch = "clean_different_kind"
        raw_decision = "CLEAN"

    else:
        verdict = Verdict.INCONCLUSIVE
        causal_signal = False
        branch = "inconclusive"
        raw_decision = "INCONCLUSIVE"

    confidence, factors = _compute_dynamic_confidence(
        baseline, candidate, control, branch, auth_mismatch, auth_enforced
    )

    result = GuardedCausalResult(
        verdict=verdict,
        causal_signal=causal_signal,
        confidence=confidence,
        confidence_factors=factors,
        raw_decision=raw_decision,
        authorization_differential=(auth_mismatch is True and auth_enforced is True),
    )
    return result


# ============================================================
# UM-DR-35.1 — Experiment-level adjudication (same module, same
# authority). Specialized validators supply structured technical
# evidence; THIS module decides the causal relationship and is the
# only source of a confirmation verdict.
# ============================================================

#: Families whose causal relationship is an AUTHORIZATION differential
#: (actor/owner/tenant/privilege). These route through the original
#: ``guarded_causal_evaluate`` (authorization-context) logic.
_AUTHORIZATION_CAUSAL_FAMILIES: frozenset[str] = frozenset({
    "IDOR", "BOLA", "PRIVILEGE_DIFFERENTIAL", "AUTH_BYPASS", "JWT_MANIPULATION",
    "BAC", "MISSING_ACCESS_CONTROL",
})

#: Technical families whose causal relationship is a SIGNAL differential:
#: the candidate observation must exhibit the family-specific technical
#: signal while baseline AND negative control do not.
_TECHNICAL_CAUSAL_FAMILIES: frozenset[str] = frozenset({
    "SSRF", "XSS", "SQLI", "OPEN_REDIRECT", "MASS_ASSIGNMENT",
    "INFO_DISCLOSURE", "BUSINESS_LOGIC", "RACE_CONDITION", "FILE_UPLOAD",
    "SSTI", "LFI", "PATH_TRAVERSAL", "COMMAND_INJECTION", "XXE", "RFI",
    "BLIND_SSRF", "XXE_OOB", "BLIND_SQLI", "CACHE_POISONING",
    "PROTOTYPE_POLLUTION",
})

CAUSALGUARD_AUTHORITY_ID: str = "cqa_v2.guarded_causal_evaluate"

#: Statuses that represent a GRANTED access outcome in the guard model.
_GRANTED_STATUSES: frozenset[int] = frozenset({200, 201, 202, 204, 206, 207, 301, 302})


@dataclass
class ExperimentCausalEvidence:
    """Structured evidence submitted to CausalGuard for adjudication.

    Built by the confirmation adapter (production/confirmation_adapter.py)
    from the REAL experiment triple + the specialized validator's
    structured result. CausalGuard never trusts the validator's outcome
    label — only the underlying evidence.
    """
    vulnerability_family: str
    experiment_id: str
    baseline: dict[str, Any]
    candidate: dict[str, Any]
    negative_control: dict[str, Any]
    #: Per-role technical signal flags extracted by the specialized
    #: validator (e.g. marker reflected, sql error present, metadata
    #: body indicators, external Location header). Required for the
    #: technical families; keys: baseline/candidate/negative_control
    #: each mapped to a truthy signal description or False.
    technical_signal: dict[str, Any]
    #: Semantic facts normalized from observation structure (request
    #: path per role, identity binding, semantic digest per role).
    semantic_facts: dict[str, Any] = field(default_factory=dict)
    evidence_origin: str = "target_runtime"
    evidence_provenance: str = "experiment_fabric_real_http"
    #: Validator's own outcome label — ADVISORY ONLY. Never used as the
    # confirmation decision; recorded for audit in confidence factors.
    validator_outcome: str | None = None
    refutation_info: str | None = None


def _blocked(reason: str, *, factors: dict[str, float] | None = None) -> GuardedCausalResult:
    return GuardedCausalResult(
        verdict=Verdict.BLOCKED, causal_signal=None, confidence=0.0,
        confidence_factors=factors or {}, block_reason=reason,
        raw_decision="BLOCKED", authorization_differential=None,
    )


def _experiment_observation_valid(obs: dict[str, Any]) -> tuple[bool, str]:
    """An observation must be a real, executed HTTP observation."""
    if not obs or not isinstance(obs, dict):
        return False, "observation_missing_or_not_dict"
    if obs.get("real_http") is False or obs.get("synthetic") is True:
        return False, "observation_synthetic"
    if obs.get("status_code") is None:
        return False, "observation_not_executed"
    if obs.get("_placeholder"):
        return False, "observation_placeholder"
    if obs.get("blocked") is True:
        return False, "observation_blocked"
    return True, ""


def _sig(evidence: ExperimentCausalEvidence, role: str) -> bool:
    """Extract the per-role technical signal flag (strict bool)."""
    v = (evidence.technical_signal or {}).get(role)
    return v is True or str(v).lower() in ("1", "true", "yes", "confirmed")


def guarded_causal_evaluate_experiment(
    evidence: ExperimentCausalEvidence,
) -> GuardedCausalResult:
    """SOLE authority for experiment-level vulnerability confirmation.

    Contract (UM-DR-35 §1.1/§1.2/§1.3):

    * Fail-closed on synthetic / missing / blocked observations.
    * Fail-closed on wrong evidence origin (target_runtime only).
    * Fail-closed when the negative control exhibits the same technical
      signal as the candidate (contaminated control ⇒ BLOCKED — the
      difference cannot be attributed to the manipulated input).
    * Authorization families: full authorization-differential logic via
      the original ``guarded_causal_evaluate`` (actor/owner/tenant/
      privilege context across the triple) — a response difference
      without an authorization differential stays unconfirmed.
    * Technical families: causal CONFIRMATION requires the candidate
      signal present AND baseline signal absent AND control signal
      absent AND a semantic difference between candidate and both
      baseline and control. Anything weaker is REFUTED (signal absent)
      or INCONCLUSIVE (insufficient discrimination), never CONFIRMED.
    """
    family = str(evidence.vulnerability_family or "").upper()

    if not family:
        return _blocked("vulnerability_family_missing")
    if evidence.evidence_origin != "target_runtime":
        return _blocked(f"evidence_origin_rejected:{evidence.evidence_origin}")

    for role, obs in (("baseline", evidence.baseline),
                      ("candidate", evidence.candidate),
                      ("negative_control", evidence.negative_control)):
        ok, why = _experiment_observation_valid(obs)
        if not ok:
            return _blocked(f"{role}_{why}")

    # -- Control independence (UM-DR-35 §1.3) --------------------------
    control = evidence.negative_control
    candidate = evidence.candidate
    baseline = evidence.baseline
    if candidate is control:
        return _blocked("control_identical_to_candidate")
    try:
        if (candidate.get("request_digest") and control.get("request_digest")
                and candidate["request_digest"] == control["request_digest"]):
            return _blocked("control_request_identical_to_candidate")
    except (TypeError, KeyError):
        pass

    # -- Authorization-class families -----------------------------------
    # Two designs exist in the experiment fabric, and the CAUSAL
    # relationship differs accordingly. CausalGuard adjudicates the
    # relationship of the design actually executed — it never accepts a
    # validator's label as a shortcut.
    if family in _AUTHORIZATION_CAUSAL_FAMILIES:
        b_g = _to_guard_observation(baseline)
        c_g = _to_guard_observation(candidate)
        k_g = _to_guard_observation(control)
        c_ctx = _extract_context(c_g)

        # Ablation signals (validator's own family test, role-swapped).
        cand_sig = _sig(evidence, "candidate")
        base_sig = _sig(evidence, "baseline")
        ctrl_sig = _sig(evidence, "negative_control")

        if family in ("IDOR", "BOLA", "PRIVILEGE_DIFFERENTIAL"):
            # TWO-PRINCIPAL differential-access design:
            #   baseline = owner on the protected resource (legitimate 2xx)
            #   candidate = foreign/lower-privilege principal on the SAME
            #               resource
            #   negative control = same principal kind on an invalid/denied
            #               resource (enforced)
            # Causal CONFIRMATION requires: owner succeeded, foreign
            # principal succeeded, actor != resource owner, control clean,
            # and the candidate observation differs from BOTH baseline and
            # control. Anything weaker is CLEAN (enforced), BLOCKED
            # (contaminated control / unusable evidence) or INCONCLUSIVE.
            owner_ok = int(b_g.get("status_code") or 0) in _GRANTED_STATUSES
            foreign_granted = int(c_g.get("status_code") or 0) in _GRANTED_STATUSES
            actor = c_ctx.get("actor_id")
            owner = c_ctx.get("resource_owner") or evidence.semantic_facts.get(
                "identity_binding", {}).get("resource_owner")
            actor_mismatch = bool(actor and owner and actor != owner)
            ctrl_status = int(k_g.get("status_code") or 0)
            ctrl_denied = ctrl_status in (401, 403, 404)
            cand_diff_base = _semantic_diff_significant(b_g, c_g)
            cand_diff_ctrl = _semantic_diff_significant(c_g, k_g)

            if ctrl_sig and cand_sig:
                return _blocked("negative_control_contaminated_signal")
            if not owner_ok or not actor_mismatch:
                verdict, branch = Verdict.CLEAN, "clean_owner_access_or_same_principal"
                raw_decision = "CLEAN"
                causal_signal = False
            elif not foreign_granted:
                # Access control enforced for the foreign principal.
                verdict, branch = Verdict.CLEAN, "clean_access_control_enforced"
                raw_decision = "CLEAN"
                causal_signal = False
            elif not (ctrl_denied or cand_diff_ctrl) or ctrl_sig:
                return _blocked("negative_control_not_independent")
            elif cand_sig and cand_diff_base and cand_diff_ctrl:
                verdict, branch = Verdict.CONFIRMED, "confirmed_differential_access"
                raw_decision = "CONFIRMED"
                causal_signal = True
            else:
                verdict, branch = Verdict.INCONCLUSIVE, "inconclusive_differential"
                raw_decision = "INCONCLUSIVE_INSUFFICIENT_DIFFERENTIAL"
                causal_signal = None
        else:
            # BYPASS designs (AUTH_BYPASS / JWT_MANIPULATION):
            #   baseline = no credential -> denied
            #   candidate = bypass/tampered credential -> granted
            #   negative control = invalid credential -> denied
            b_status = int(b_g.get("status_code") or 0)
            c_status = int(c_g.get("status_code") or 0)
            k_status = int(k_g.get("status_code") or 0)
            baseline_denied = b_status in (401, 403)
            candidate_granted = c_status in _GRANTED_STATUSES
            control_denied = k_status in (401, 403)
            cand_diff_base = _semantic_diff_significant(b_g, c_g)
            cand_diff_ctrl = _semantic_diff_significant(c_g, k_g)
            if ctrl_sig and cand_sig:
                return _blocked("negative_control_contaminated_signal")
            if not candidate_granted:
                verdict, branch = Verdict.CLEAN, "clean_bypass_rejected"
                raw_decision = "CLEAN"
                causal_signal = False
            elif not baseline_denied or not control_denied:
                return _blocked("bypass_control_not_denied_state")
            elif cand_sig and cand_diff_base and cand_diff_ctrl:
                verdict, branch = Verdict.CONFIRMED, "confirmed_bypass"
                raw_decision = "CONFIRMED"
                causal_signal = True
            else:
                verdict, branch = Verdict.INCONCLUSIVE, "inconclusive_bypass"
                raw_decision = "INCONCLUSIVE_INSUFFICIENT_BYPASS_CONTEXT"
                causal_signal = None

        confidence, factors = _compute_dynamic_confidence(
            b_g, c_g, k_g, branch, None, None)
        factors["candidate_signal"] = 1.0 if cand_sig else 0.0
        factors["baseline_signal"] = 1.0 if base_sig else 0.0
        factors["control_signal"] = 1.0 if ctrl_sig else 0.0
        if evidence.validator_outcome:
            factors["validator_label_advisory"] = 1.0
        if evidence.refutation_info:
            factors["refutation_info_present"] = 1.0
        return GuardedCausalResult(
            verdict=verdict, causal_signal=causal_signal,
            confidence=confidence, confidence_factors=factors,
            raw_decision=raw_decision,
            authorization_differential=(verdict is Verdict.CONFIRMED))

    # -- Technical families: signal differential ------------------------
    if family in _TECHNICAL_CAUSAL_FAMILIES:
        cand_sig = _sig(evidence, "candidate")
        base_sig = _sig(evidence, "baseline")
        ctrl_sig = _sig(evidence, "negative_control")

        if not isinstance(evidence.technical_signal, dict) or not evidence.technical_signal:
            return _blocked("technical_signal_missing_for_technical_family")

        # Contaminated control: signal visible in control ⇒ cannot
        # attribute causation to the manipulated input.
        if ctrl_sig and cand_sig:
            return _blocked("negative_control_contaminated_signal")

        cand_diff_base = _semantic_diff_significant(
            _to_guard_observation(baseline), _to_guard_observation(candidate))
        cand_diff_ctrl = _semantic_diff_significant(
            _to_guard_observation(candidate), _to_guard_observation(control))

        if cand_sig and not base_sig and not ctrl_sig:
            if cand_diff_base and cand_diff_ctrl:
                verdict = Verdict.CONFIRMED
                causal_signal = True
                branch = "confirmed_signal_differential"
                raw_decision = "CONFIRMED"
            else:
                # Signal present but observations not discriminating:
                # insufficient differential evidence.
                verdict = Verdict.INCONCLUSIVE
                causal_signal = None
                branch = "inconclusive_signal_without_semantic_diff"
                raw_decision = "INCONCLUSIVE_SIGNAL_WEAK_DIFFERENTIAL"
        elif not cand_sig:
            verdict = Verdict.CLEAN
            causal_signal = False
            branch = "clean_no_candidate_signal"
            raw_decision = "CLEAN"
        elif cand_sig and base_sig:
            # Both baseline and candidate show the signal — the signal
            # is not caused by the manipulated input.
            verdict = Verdict.CLEAN
            causal_signal = False
            branch = "clean_signal_in_baseline_too"
            raw_decision = "CLEAN_SIGNAL_NOT_INPUT_CAUSED"
        else:
            verdict = Verdict.INCONCLUSIVE
            causal_signal = None
            branch = "inconclusive"
            raw_decision = "INCONCLUSIVE"

        confidence, factors = _compute_dynamic_confidence(
            _to_guard_observation(baseline), _to_guard_observation(candidate),
            _to_guard_observation(control), branch, None, None)
        factors["candidate_signal"] = 1.0 if cand_sig else 0.0
        factors["baseline_signal"] = 1.0 if base_sig else 0.0
        factors["control_signal"] = 1.0 if ctrl_sig else 0.0
        if evidence.validator_outcome:
            factors["validator_label_advisory"] = 1.0
        if evidence.refutation_info:
            factors["refutation_info_present"] = 1.0
        return GuardedCausalResult(
            verdict=verdict, causal_signal=causal_signal,
            confidence=confidence, confidence_factors=factors,
            raw_decision=raw_decision,
            authorization_differential=None)

    # Unknown family: fail-closed, never guessed.
    return _blocked(f"unknown_vulnerability_family:{family}")


def _to_guard_observation(obs: dict[str, Any]) -> dict[str, Any]:
    """Normalize an experiment observation into the extended observation
    model consumed by ``guarded_causal_evaluate`` (status, digests,
    request path, authorization context headers)."""
    headers = obs.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    request_url = str(obs.get("request_url") or obs.get("url_shape") or "")
    path = "/"
    try:
        from urllib.parse import urlsplit
        path = urlsplit(request_url).path or "/"
    except (ValueError, TypeError):
        path = "/"
    body = str(obs.get("response_body") or "")
    body_length = obs.get("body_length")
    if body_length is None:
        body_length = len(body)
    # Semantic digest covers status, body, AND the Location channel (the
    # differentiator for redirect families, where bodies are often equal).
    location = ""
    for hk, hv in headers.items():
        if hk.lower() == "location":
            location = str(hv)
            break
    if not location and obs.get("location_host"):
        location = str(obs["location_host"])
    semantic_digest = None
    try:
        import hashlib
        semantic_digest = "sha256:" + hashlib.sha256(
            (str(obs.get("status_code")) + "|" + location + "|" + body[:4096]).encode(
                "utf-8", "replace")).hexdigest()
    except (TypeError, ValueError):
        semantic_digest = None
    return {
        "status_code": obs.get("status_code"),
        "body_length": body_length,
        "semantic_digest": semantic_digest,
        "headers": headers,
        "request": {"path": path, "url": request_url},
        # Authorization context is passed through so _extract_context can
        # read X-Actor-*/X-Resource-* channels from real target responses.
        "actor_id": obs.get("actor_id"),
        "actor_role": obs.get("actor_role"),
        "actor_tenant": obs.get("actor_tenant"),
        "auth_state": obs.get("auth_state"),
        "resource_owner": obs.get("resource_owner"),
        "resource_tenant": obs.get("resource_tenant"),
        "resource_id": obs.get("resource_id"),
        "resource_type": obs.get("resource_type"),
        "authorization_outcome": obs.get("authorization_outcome"),
        "effective_privilege_granted": obs.get("effective_privilege_granted"),
        "privilege_required": obs.get("privilege_required"),
        "location_host": obs.get("location_host"),
    }
