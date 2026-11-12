"""UM-DR-35.1 — Confirmation Adapter (CausalGuard integration contract).

Specialized validators (production/validators.py) remain USEFUL technical
evidence producers: they extract family-specific discriminating signals
from real target observations. This module adapts their structured output
into ``ExperimentCausalEvidence`` and submits it to the SOLE confirmation
authority, ``cqa_v2.causal_guard.guarded_causal_evaluate_experiment``.

ARCHITECTURE RULES (UM-DR-35 §1.1):
  * No validator label, LLM score, scanner claim, or string constant is a
    confirmation. Only a typed ``GuardedCausalResult`` returned from the
    real CausalGuard implementation can authorize promotion.
  * This adapter never confirms anything by itself — it BUILDS evidence and
    DELEGATES adjudication.
  * Per-role technical signals are derived by ROLE-ABLATION: the specialized
    validator itself is re-invoked with each role's observation swapped
    into the candidate slot. The validator's own family logic then tells
    us whether that role alone would produce its CONFIRMED-grade signal.
    This reuses the validator's technical analysis (no duplicated family
    logic) and measures exactly "is the signal attributable to this role's
    observation?".
"""
from __future__ import annotations

from typing import Any

from webpent.cqa_v2.causal_guard import (
    CAUSALGUARD_AUTHORITY_ID,
    ExperimentCausalEvidence,
    GuardedCausalResult,
    Verdict,
    guarded_causal_evaluate_experiment,
)
from webpent.production.validators import (
    ValidationOutcome,
    ValidatorError,
    run_validator,
)

__all__ = [
    "CAUSALGUARD_AUTHORITY_ID",
    "ExperimentCausalEvidence",
    "GuardedCausalResult",
    "Verdict",
    "build_experiment_causal_evidence",
    "causalguard_adjudicate",
    "causalguard_verdict_matches",
]


def _ablation_signal(
    vulnerability_class: str,
    *,
    baseline_raw: dict[str, Any],
    role_observation: dict[str, Any],
    negative_control_raw: dict[str, Any],
) -> tuple[bool, str | None]:
    """Run the specialized validator with ``role_observation`` in the
    candidate slot (role-ablation). Returns (signal_present, note).

    The validator's CONFIRMED outcome here means: this role's observation,
    viewed as the candidate, satisfies the validator's own family-specific
    discriminating test. Exceptions and REFUTED/INCONCLUSIVE all map to
    signal=False (fail-closed — an unusable validator never yields a signal).
    """
    try:
        vr = run_validator(vulnerability_class, baseline=baseline_raw,
                           candidate=role_observation,
                           negative_control=negative_control_raw)
    except (ValidatorError, AttributeError, KeyError, RuntimeError, TypeError, ValueError):
        return False, "ablation_validator_unusable"
    if vr is None or vr.outcome != ValidationOutcome.CONFIRMED:
        return False, (vr.outcome.value if vr is not None else "none")
    return True, (vr.discriminating_signal or "confirmed")[:200]


def build_experiment_causal_evidence(
    *,
    vulnerability_class: str,
    experiment_id: str,
    baseline_raw: dict[str, Any],
    candidate_raw: dict[str, Any],
    negative_control_raw: dict[str, Any],
    hypothesis: dict[str, Any] | None = None,
    identity_binding: dict[str, Any] | None = None,
    validator_outcome: str | None = None,
    refutation_info: str | None = None,
    evidence_origin: str = "target_runtime",
) -> ExperimentCausalEvidence:
    """Build the structured evidence object for CausalGuard adjudication.

    Pulls together: the real HTTP triple, per-role ablation signals from the
    specialized validator, identity/ownership context from the M4 binding,
    and request-path semantic facts. Nothing here judges causality.
    """
    hyp = hypothesis if isinstance(hypothesis, dict) else {}
    ib = identity_binding if isinstance(identity_binding, dict) else {}

    technical_signal: dict[str, Any] = {}
    signal_notes: dict[str, Any] = {}
    for role, obs in (("baseline", baseline_raw),
                      ("candidate", candidate_raw),
                      ("negative_control", negative_control_raw)):
        present, note = _ablation_signal(
            vulnerability_class,
            baseline_raw=baseline_raw,
            role_observation=obs,
            negative_control_raw=negative_control_raw,
        )
        technical_signal[role] = present
        signal_notes[f"{role}_note"] = note

    # Authorization context is attached to every observation so CausalGuard's
    # extended observation model can read actor/owner/tenant channels for
    # the authorization-class families. Values come from the M4 binding and
    # real response headers — never invented.
    def _with_identity(obs: dict[str, Any], *, principal_hint: str | None) -> dict[str, Any]:
        merged = dict(obs)
        headers = dict(merged.get("headers") or {})
        merged["headers"] = headers
        actor = principal_hint or ib.get("actor_id") or obs.get("actor_id")
        if actor:
            merged["actor_id"] = str(actor)
            headers.setdefault("X-Actor-Echo", str(actor))
        resource = ib.get("resource_id") or obs.get("resource_id")
        owner = ib.get("resource_owner") or obs.get("resource_owner")
        if resource:
            merged["resource_id"] = str(resource)
        if owner:
            merged["resource_owner"] = str(owner)
            headers.setdefault("X-Resource-Owner", str(owner))
        role_ctx = ib.get("actor_role") or obs.get("actor_role")
        if role_ctx:
            merged["actor_role"] = str(role_ctx)
            headers.setdefault("X-Actor-Role", str(role_ctx))
        tenant = ib.get("actor_tenant") or obs.get("actor_tenant")
        if tenant:
            merged["actor_tenant"] = str(tenant)
            headers.setdefault("X-Actor-Tenant", str(tenant))
        return merged

    requests_spec = hyp.get("requests") if isinstance(hyp.get("requests"), dict) else {}
    principal_by_role: dict[str, str | None] = {}
    for role in ("baseline", "candidate", "negative_control"):
        spec = requests_spec.get(role, {}) if isinstance(requests_spec.get(role, {}), dict) else {}
        principal_by_role[role] = spec.get("principal_alias") or spec.get("principal_role")

    baseline_ev = _with_identity(
        baseline_raw, principal_hint=principal_by_role.get("baseline"))
    candidate_ev = _with_identity(
        candidate_raw, principal_hint=principal_by_role.get("candidate"))
    control_ev = _with_identity(
        negative_control_raw,
        principal_hint=principal_by_role.get("negative_control"))

    semantic_facts: dict[str, Any] = {
        "identity_binding": {k: ib.get(k) for k in
                              ("actor_id", "resource_id", "resource_owner", "identity_bound",
                               "identity_bound_reason", "causal_difference")},
        "ablation_notes": signal_notes,
        "experiment_id": experiment_id,
        "hypothesis_id": str(hyp.get("id", "")),
    }

    return ExperimentCausalEvidence(
        vulnerability_family=vulnerability_class,
        experiment_id=experiment_id,
        baseline=baseline_ev,
        candidate=candidate_ev,
        negative_control=control_ev,
        technical_signal=technical_signal,
        semantic_facts=semantic_facts,
        evidence_origin=evidence_origin,
        evidence_provenance="avi_real_http_triple+m4_binding",
        validator_outcome=validator_outcome,
        refutation_info=refutation_info,
    )


def causalguard_adjudicate(
    evidence: ExperimentCausalEvidence,
) -> GuardedCausalResult:
    """Submit evidence to the SOLE confirmation authority.

    Thin delegation: the authority is (and can only be)
    ``cqa_v2.causal_guard.guarded_causal_evaluate_experiment``.
    """
    return guarded_causal_evaluate_experiment(evidence)


def causalguard_verdict_matches(
    original: GuardedCausalResult | None,
    replayed: GuardedCausalResult | None,
) -> bool:
    """Replay contract helper: the replayed CausalGuard verdict must equal the
    original verdict AND both must be genuine typed results. A None on either
    side can never match (missing authority result = replay failure)."""
    if original is None or replayed is None:
        return False
    both_typed = (isinstance(original, GuardedCausalResult)
                  and isinstance(replayed, GuardedCausalResult))
    if not both_typed:
        return False
    return (original.verdict == replayed.verdict
            and original.causal_signal == replayed.causal_signal)


# ---------------------------------------------------------------------------
# UM-DR-35 Gate 35-A — graph validator-node confirmation gate
# ---------------------------------------------------------------------------

#: Graph-path vulnerability class labels -> guard family identities.
_GRAPH_FAMILY_MAP: dict[str, str] = {
    "xss": "XSS", "sqli": "SQLI", "ssrf": "SSRF", "rce": "COMMAND_INJECTION",
    "command_injection": "COMMAND_INJECTION", "open_redirect": "OPEN_REDIRECT",
    "ssti": "SSTI", "lfi": "LFI", "path_traversal": "PATH_TRAVERSAL",
    "xxe": "XXE", "rfi": "RFI", "idor": "IDOR", "bola": "BOLA",
    "mass_assignment": "MASS_ASSIGNMENT", "info_disclosure": "INFO_DISCLOSURE",
    "auth_bypass": "AUTH_BYPASS", "jwt_manipulation": "JWT_MANIPULATION",
    "race_condition": "RACE_CONDITION", "business_logic": "BUSINESS_LOGIC",
    "file_upload": "FILE_UPLOAD", "cache_poisoning": "CACHE_POISONING",
    "prototype_pollution": "PROTOTYPE_POLLUTION", "bac": "AUTH_BYPASS",
}


def _observation_shaped(obs: Any) -> bool:
    return isinstance(obs, dict) and obs.get("status_code") is not None


def causalguard_tool_confirmation_gate(
    *,
    vulnerability_class: str,
    differential_observation: dict[str, Any] | None,
    candidate_signal: bool,
    finding_id: str = "unknown",
) -> tuple[bool, Any, str]:
    """Graph validator-node confirmation gate (UM-DR-35 Gate 35-A).

    A finding may be marked CONFIRMED / "Tool-Confirmed" on the standard
    campaign graph ONLY when CausalGuard — the sole confirmation authority —
    adjudicates the finding's recorded differential evidence (real
    baseline / candidate / negative-control observations) as causally
    CONFIRMED. A tool marker, structural check, LLM verdict, or reauth
    exception without a guard-confirmed differential is NOT confirmable and
    must fail closed to human review.

    Returns ``(allowed, guard_result, reason)``. ``allowed`` is True only
    for a typed GuardedCausalResult with verdict CONFIRMED.
    """
    family = _GRAPH_FAMILY_MAP.get(str(vulnerability_class or "").lower())
    if not family:
        return (False, None,
                f"causalguard_family_unmapped:{vulnerability_class}")
    triple = differential_observation if isinstance(differential_observation, dict) else None
    if not triple:
        return (False, None, "causalguard_no_differential_observation")
    baseline = triple.get("baseline")
    candidate = triple.get("candidate")
    control = triple.get("negative_control") or triple.get("control")
    if not (_observation_shaped(baseline) and _observation_shaped(candidate)
            and _observation_shaped(control)):
        return (False, None, "causalguard_differential_incomplete")
    try:
        evidence = ExperimentCausalEvidence(
            vulnerability_family=family,
            experiment_id=f"graph_{family.lower()}_{finding_id}",
            baseline=dict(baseline),
            candidate=dict(candidate),
            negative_control=dict(control),
            technical_signal={"baseline": False,
                             "candidate": bool(candidate_signal),
                             "negative_control": False},
            semantic_facts={"finding_id": str(finding_id),
                            "path": "graph_validator_node"},
            evidence_origin="target_runtime",
            evidence_provenance="graph_differential_observation",
        )
        result = causalguard_adjudicate(evidence)
    except (AttributeError, KeyError, RuntimeError, TypeError, ValueError) as exc:
        return (False, None, f"causalguard_gate_error:{type(exc).__name__}")
    if result.verdict.value == "CONFIRMED" and result.causal_signal is True:
        return (True, result, "causalguard_confirmed")
    suffix = f":{result.block_reason}" if result.block_reason else ""
    return (False, result, f"causalguard_{result.verdict.value.lower()}" + suffix)
