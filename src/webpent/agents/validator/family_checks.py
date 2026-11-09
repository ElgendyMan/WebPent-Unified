"""Deterministic, bounded validators for the five logic families + OAuth.

Mirrors ``webpent.agents.validator.active_checks``: conservative, replay-
based, never auto-promotes on ambiguous evidence. A candidate is CONFIRMED
only when (a) the discriminating replay succeeds AND (b) independent state
evidence / causal link proves the invariant broke. Status codes alone are
never sufficient (fail-closed).

Evidence stores digests only — no Cookie/Authorization/Set-Cookie/raw bodies.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


@dataclass(frozen=True)
class Replay:
    """Replay shape for family validators. Compatible with active_checks.Replay
    (superset: adds body_digest and label for evidence marking). Digests only."""
    method: str
    url: str
    request_body: str | None
    status_code: int
    body: str = ""
    body_digest: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0
    label: str = ""


class FamilyVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"
    NOT_SCANNED = "NOT_SCANNED"


@dataclass(frozen=True)
class FamilyValidationResult:
    vuln_class: str
    scenario_id: str
    verdict: FamilyVerdict
    rationale: str
    evidence_refs: tuple[str, ...] = ()
    proof_bundle_spec: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProofBundleSpec:
    """The evidence a full ProofBundle would seal. The central proof pipeline
    consumes this spec; this validator never seals a bundle itself."""
    vuln_class: str
    scenario_id: str
    baseline_digest: str
    negative_control_digest: str
    candidate_digest: str
    causal_oracle: str
    target_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_class": self.vuln_class,
            "scenario_id": self.scenario_id,
            "baseline_digest": self.baseline_digest,
            "negative_control_digest": self.negative_control_digest,
            "candidate_digest": self.candidate_digest,
            "causal_oracle": self.causal_oracle,
            "target_fingerprint": self.target_fingerprint,
        }


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8', 'replace')).hexdigest()[:16]}"


def _target_fingerprint(url: str) -> str:
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(str(url))
    shape = urlunparse(parsed._replace(query="", fragment=""))
    return f"sha256:{hashlib.sha256(shape.encode('utf-8', 'replace')).hexdigest()[:16]}"


def _body_of(replay: Replay) -> str:
    return getattr(replay, "body", "") or ""


def _digest_of(replay: Replay) -> str:
    d = getattr(replay, "body_digest", "") or ""
    if d:
        return d
    return _digest(_body_of(replay))


def _is_2xx(replay: Replay | None) -> bool:
    return replay is not None and 200 <= replay.status_code < 300


# ---------------------------------------------------------------------------
# race_condition — confirmation requires post-state side-effect evidence.
# ---------------------------------------------------------------------------
def validate_race_condition(
    burst_replays: list[Replay],
    sequential_replays: list[Replay],
    post_state_replay: Replay | None = None,
    *,
    max_allowed_success: int = 1,
    expected_side_effect_count: int | None = None,
) -> FamilyValidationResult:
    if not burst_replays:
        return FamilyValidationResult("race_condition", "RACE-000", FamilyVerdict.NOT_SCANNED, "no burst replays")
    burst_2xx = sum(1 for r in burst_replays if _is_2xx(r))
    seq_2xx = sum(1 for r in sequential_replays if _is_2xx(r))
    if burst_2xx <= max_allowed_success:
        return FamilyValidationResult(
            "race_condition", "RACE-burst", FamilyVerdict.NOT_CONFIRMED,
            f"burst {burst_2xx} 2xx did not exceed limit {max_allowed_success}",
        )
    if seq_2xx > max_allowed_success:
        return FamilyValidationResult(
            "race_condition", "RACE-burst", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            "both burst and sequential exceed limit — not race-specific",
        )
    if post_state_replay is None or expected_side_effect_count is None:
        return FamilyValidationResult(
            "race_condition", "RACE-burst", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            f"burst {burst_2xx} 2xx vs sequential {seq_2xx}; post-state side-effect evidence required",
        )
    post_label = str(getattr(post_state_replay, "label", ""))
    # Confirm only if committed side effects EXCEED the allowed limit.
    # expected_side_effect_count=0 (no side effects) must never confirm.
    if (f"side_effects:{expected_side_effect_count}" in post_label
            and expected_side_effect_count > max_allowed_success):
        spec = ProofBundleSpec(
            vuln_class="race_condition", scenario_id="RACE-burst",
            baseline_digest=_digest_of(sequential_replays[0]) if sequential_replays else "",
            negative_control_digest=_digest_of(sequential_replays[-1]) if sequential_replays else "",
            candidate_digest=_digest_of(burst_replays[0]),
            causal_oracle=f"burst_committed_side_effects={expected_side_effect_count}",
            target_fingerprint=_target_fingerprint(burst_replays[0].url),
        )
        return FamilyValidationResult(
            "race_condition", "RACE-burst", FamilyVerdict.CONFIRMED,
            f"burst {burst_2xx} 2xx, sequential {seq_2xx}, post-state shows {expected_side_effect_count} committed side effects",
            evidence_refs=(_digest(f"burst:{burst_2xx}"), _digest(f"seq:{seq_2xx}"), _digest_of(post_state_replay)),
            proof_bundle_spec=spec.to_dict(),
        )
    return FamilyValidationResult(
        "race_condition", "RACE-burst", FamilyVerdict.NEEDS_HUMAN_REVIEW,
        "burst exceeded limit but post-state did not prove committed side effects",
    )


# ---------------------------------------------------------------------------
# tenant_isolation — confirmation requires foreign-tenant data in response.
# ---------------------------------------------------------------------------
def validate_tenant_isolation(
    actor_a_replay: Replay | None,
    actor_b_baseline: Replay | None,
    same_tenant_negative: Replay | None = None,
    *,
    foreign_tenant_identifiers: list[str] | None = None,
) -> FamilyValidationResult:
    if not actor_a_replay or not actor_b_baseline:
        return FamilyValidationResult("tenant_isolation", "TENANT-000", FamilyVerdict.NOT_SCANNED, "missing actor replays")
    if same_tenant_negative and _is_2xx(same_tenant_negative):
        return FamilyValidationResult(
            "tenant_isolation", "TENANT-cross", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            "same-tenant negative also succeeded — object ACL may be absent",
        )
    if not _is_2xx(actor_a_replay):
        return FamilyValidationResult(
            "tenant_isolation", "TENANT-cross", FamilyVerdict.NOT_CONFIRMED,
            f"actor A status={actor_a_replay.status_code} (rejected)",
        )
    foreign_ids = foreign_tenant_identifiers or []
    a_body = _body_of(actor_a_replay)
    matched = [fid for fid in foreign_ids if fid and fid in a_body]
    if matched:
        spec = ProofBundleSpec(
            vuln_class="tenant_isolation", scenario_id="TENANT-cross",
            baseline_digest=_digest_of(actor_b_baseline),
            negative_control_digest=_digest_of(same_tenant_negative) if same_tenant_negative else "",
            candidate_digest=_digest_of(actor_a_replay),
            causal_oracle=f"foreign_tenant_ids_in_response={matched}",
            target_fingerprint=_target_fingerprint(actor_a_replay.url),
        )
        return FamilyValidationResult(
            "tenant_isolation", "TENANT-cross", FamilyVerdict.CONFIRMED,
            f"actor A (2xx) response contains foreign-tenant identifiers {matched}",
            evidence_refs=(_digest_of(actor_a_replay), _digest_of(actor_b_baseline)),
            proof_bundle_spec=spec.to_dict(),
        )
    return FamilyValidationResult(
        "tenant_isolation", "TENANT-cross", FamilyVerdict.NEEDS_HUMAN_REVIEW,
        "actor A received 2xx but no foreign-tenant identifiers observed — structural review required",
    )


# ---------------------------------------------------------------------------
# multi_step_auth_bypass — confirmation requires a valid issued session.
# ---------------------------------------------------------------------------
def validate_multi_step_auth_bypass(
    step_inventory: list[Replay],
    direct_final_replay: Replay | None,
    post_replay_session_check: Replay | None = None,
    *,
    expected_steps: int = 2,
) -> FamilyValidationResult:
    if not direct_final_replay:
        return FamilyValidationResult("multi_step_auth_bypass", "MSAUTH-000", FamilyVerdict.NOT_SCANNED, "no final replay")
    if len(step_inventory) < expected_steps:
        return FamilyValidationResult(
            "multi_step_auth_bypass", "MSAUTH-step-skip", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            f"step inventory incomplete ({len(step_inventory)} < {expected_steps})",
        )
    if not _is_2xx(direct_final_replay):
        return FamilyValidationResult(
            "multi_step_auth_bypass", "MSAUTH-step-skip", FamilyVerdict.NOT_CONFIRMED,
            f"direct final replay status={direct_final_replay.status_code}",
        )
    if post_replay_session_check is None or not _is_2xx(post_replay_session_check):
        return FamilyValidationResult(
            "multi_step_auth_bypass", "MSAUTH-step-skip", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            "final step returned 2xx but no valid authenticated session observed",
        )
    spec = ProofBundleSpec(
        vuln_class="multi_step_auth_bypass", scenario_id="MSAUTH-step-skip",
        baseline_digest=_digest_of(step_inventory[0]),
        negative_control_digest=_digest_of(post_replay_session_check),
        candidate_digest=_digest_of(direct_final_replay),
        causal_oracle="session_issued_without_expected_steps",
        target_fingerprint=_target_fingerprint(direct_final_replay.url),
    )
    return FamilyValidationResult(
        "multi_step_auth_bypass", "MSAUTH-step-skip", FamilyVerdict.CONFIRMED,
        f"final step 2xx without {expected_steps} prior steps AND valid session issued",
        evidence_refs=(_digest_of(direct_final_replay), _digest_of(post_replay_session_check)),
        proof_bundle_spec=spec.to_dict(),
    )


# ---------------------------------------------------------------------------
# exploit_chain — confirmation requires feeder artifacts actually used AND
# a negative-control replay proving the artifacts mattered.
#
# M1-B (H-3/1.3b, 2026-11-05): the pre-fix contract confirmed on a single
# 2xx composed replay + ≥2 declared artifacts. A composed request that a
# server answers 2xx regardless (unauthenticated GET, catch-all route)
# therefore "confirmed" theft chains. The new contract is fail-closed:
# CONFIRMED requires the SAME composed request with the feeder artifact
# neutralized (``control_replay``) to be rejected (non-2xx) — proving the
# 2xx is causally dependent on the artifacts. Missing control replay ⇒
# NEEDS_HUMAN_REVIEW (never CONFIRMED).
# ---------------------------------------------------------------------------
def validate_exploit_chain(
    feeder_findings: list[dict[str, Any]],
    composed_replay: Replay | None,
    *,
    chain_scenario_id: str = "",
    feeder_artifacts_used: list[str] | None = None,
    control_replay: Replay | None = None,
) -> FamilyValidationResult:
    if not composed_replay:
        return FamilyValidationResult("exploit_chain", chain_scenario_id or "CHAIN-000", FamilyVerdict.NOT_SCANNED, "no composed replay")
    if len(feeder_findings) < 2:
        return FamilyValidationResult(
            "exploit_chain", chain_scenario_id or "CHAIN-000", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            "fewer than 2 feeder findings — chain impact not amplifiable",
        )
    if not _is_2xx(composed_replay):
        return FamilyValidationResult(
            "exploit_chain", chain_scenario_id or "CHAIN-composed", FamilyVerdict.NOT_CONFIRMED,
            f"composed replay status={composed_replay.status_code}",
        )
    used = feeder_artifacts_used or []
    if len(used) < 2:
        return FamilyValidationResult(
            "exploit_chain", chain_scenario_id or "CHAIN-composed", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            "composed replay succeeded but causal link to feeder artifacts not proven",
        )
    if control_replay is None:
        return FamilyValidationResult(
            "exploit_chain", chain_scenario_id or "CHAIN-composed", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            "no negative-control replay — a 2xx composed request alone cannot "
            "prove the feeder artifacts caused the impact (M1-B: negative "
            "control is mandatory for confirmation)",
        )
    if _is_2xx(control_replay):
        return FamilyValidationResult(
            "exploit_chain", chain_scenario_id or "CHAIN-composed", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            "negative-control replay also succeeded (status="
            f"{control_replay.status_code}) — the server accepts the composed "
            "request regardless of the feeder artifacts; impact not causally "
            "proven",
        )
    spec = ProofBundleSpec(
        vuln_class="exploit_chain", scenario_id=chain_scenario_id or "CHAIN-composed",
        baseline_digest=_digest(",".join(sorted(str(f.get("vuln_class", "")) for f in feeder_findings))),
        negative_control_digest=_digest_of(control_replay),
        candidate_digest=_digest_of(composed_replay),
        causal_oracle=(
            f"feeder_artifacts_used={used};"
            f"control_rejected={control_replay.status_code}"
        ),
        target_fingerprint=_target_fingerprint(composed_replay.url),
    )
    return FamilyValidationResult(
        "exploit_chain", chain_scenario_id or "CHAIN-composed", FamilyVerdict.CONFIRMED,
        f"composed replay succeeded ({composed_replay.status_code}) using "
        f"{len(used)} feeder artifacts while the negative-control replay was "
        f"rejected ({control_replay.status_code})",
        evidence_refs=(_digest_of(composed_replay), _digest_of(control_replay)),
        proof_bundle_spec=spec.to_dict(),
    )


# ---------------------------------------------------------------------------
# business_logic — confirmation requires post-state invariant break.
# ---------------------------------------------------------------------------
def validate_business_logic(
    tampered_replay: Replay | None,
    baseline_replay: Replay | None,
    post_state_replay: Replay | None = None,
    *,
    invariant_broken_marker: str = "",
) -> FamilyValidationResult:
    if not tampered_replay or not baseline_replay:
        return FamilyValidationResult("business_logic", "BIZ-000", FamilyVerdict.NOT_SCANNED, "missing replays")
    if not _is_2xx(tampered_replay):
        return FamilyValidationResult(
            "business_logic", "BIZ-invariant", FamilyVerdict.NOT_CONFIRMED,
            f"tampered request rejected (status={tampered_replay.status_code})",
        )
    if post_state_replay and invariant_broken_marker:
        post_label = str(getattr(post_state_replay, "label", ""))
        post_body = _body_of(post_state_replay)
        if invariant_broken_marker in post_label or invariant_broken_marker in post_body:
            spec = ProofBundleSpec(
                vuln_class="business_logic", scenario_id="BIZ-invariant",
                baseline_digest=_digest_of(baseline_replay),
                negative_control_digest=_digest_of(baseline_replay),
                candidate_digest=_digest_of(tampered_replay),
                causal_oracle=f"invariant_broken_marker={invariant_broken_marker}",
                target_fingerprint=_target_fingerprint(tampered_replay.url),
            )
            return FamilyValidationResult(
                "business_logic", "BIZ-invariant", FamilyVerdict.CONFIRMED,
                "tampered request accepted and post-state replay shows invariant broken",
                evidence_refs=(_digest_of(tampered_replay), _digest_of(baseline_replay), _digest_of(post_state_replay)),
                proof_bundle_spec=spec.to_dict(),
            )
    if _digest_of(tampered_replay) != _digest_of(baseline_replay):
        return FamilyValidationResult(
            "business_logic", "BIZ-invariant", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            "tampered request accepted with different response — post-state evidence required",
        )
    return FamilyValidationResult(
        "business_logic", "BIZ-invariant", FamilyVerdict.NOT_CONFIRMED,
        "business invariant held under tampered replay",
    )


# ---------------------------------------------------------------------------
# oauth — confirmation requires the delivered code/token artifact to be
# observable in the attacker-controlled replay.
#
# M1-B (H-3/1.3c, 2026-11-05): the pre-fix contract trusted caller-supplied
# booleans (``code_delivered_to_attacker`` / ``token_misuse_confirmed``)
# with no replay substantiation — an optimistic caller flag confirmed an
# OAuth finding with a sealed-looking proof bundle. The new contract:
# a delivery claim counts ONLY when ``delivered_artifact_marker`` (the
# delivered code/token fragment, or its digest) actually appears in the
# attacker replay's body or label; token misuse requires a 2xx
# ``misuse_replay``. The legitimate-callback baseline becomes the
# negative-control digest — without it the check degrades to
# NEEDS_HUMAN_REVIEW (fail-closed).
# ---------------------------------------------------------------------------
def validate_oauth(
    attacker_redirect_replay: Replay | None,
    legitimate_callback_baseline: Replay | None = None,
    *,
    oauth_scenario_id: str = "",
    code_delivered_to_attacker: bool = False,
    token_misuse_confirmed: bool = False,
    delivered_artifact_marker: str = "",
    misuse_replay: Replay | None = None,
) -> FamilyValidationResult:
    if not attacker_redirect_replay:
        return FamilyValidationResult("oauth", oauth_scenario_id or "OAUTH-000", FamilyVerdict.NOT_SCANNED, "no replay")
    status = attacker_redirect_replay.status_code
    if not _is_2xx(attacker_redirect_replay) and status not in (301, 302, 303, 307, 308):
        return FamilyValidationResult(
            "oauth", oauth_scenario_id or "OAUTH", FamilyVerdict.NOT_CONFIRMED,
            f"attacker endpoint status={status}",
        )

    # M1-B: substantiate the delivery claim against the replay itself.
    marker = str(delivered_artifact_marker or "").strip()
    delivered_substantiated = bool(marker) and (
        marker in _body_of(attacker_redirect_replay)
        or marker in str(getattr(attacker_redirect_replay, "label", ""))
    )
    if code_delivered_to_attacker and not delivered_substantiated:
        return FamilyValidationResult(
            "oauth", oauth_scenario_id or "OAUTH", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            "code_delivered_to_attacker asserted but the delivered artifact "
            "marker does not appear in the attacker replay — unsubstantiated "
            "delivery claims cannot confirm (M1-B)",
        )
    misuse_substantiated = bool(token_misuse_confirmed) and (
        misuse_replay is not None and _is_2xx(misuse_replay)
    )
    if token_misuse_confirmed and not misuse_substantiated:
        return FamilyValidationResult(
            "oauth", oauth_scenario_id or "OAUTH", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            "token_misuse_confirmed asserted without a successful misuse "
            "replay — unsubstantiated misuse claims cannot confirm (M1-B)",
        )

    if delivered_substantiated or misuse_substantiated:
        if legitimate_callback_baseline is None:
            return FamilyValidationResult(
                "oauth", oauth_scenario_id or "OAUTH", FamilyVerdict.NEEDS_HUMAN_REVIEW,
                "delivery/misuse substantiated but no legitimate-callback "
                "baseline replay — negative-control digest unavailable, "
                "fail-closed (M1-B)",
            )
        spec = ProofBundleSpec(
            vuln_class="oauth", scenario_id=oauth_scenario_id or "OAUTH",
            baseline_digest=_digest_of(legitimate_callback_baseline),
            negative_control_digest=_digest_of(legitimate_callback_baseline),
            candidate_digest=_digest_of(attacker_redirect_replay),
            causal_oracle=(
                f"delivered_marker_present={delivered_substantiated}, "
                f"misuse_replay_2xx={misuse_substantiated}"
            ),
            target_fingerprint=_target_fingerprint(attacker_redirect_replay.url),
        )
        return FamilyValidationResult(
            "oauth", oauth_scenario_id or "OAUTH", FamilyVerdict.CONFIRMED,
            "OAuth code/token delivery substantiated in the attacker replay "
            "and/or misuse replay succeeded, against a legitimate-callback "
            "negative control",
            evidence_refs=(
                _digest_of(attacker_redirect_replay),
                _digest_of(legitimate_callback_baseline),
            ),
            proof_bundle_spec=spec.to_dict(),
        )
    return FamilyValidationResult(
        "oauth", oauth_scenario_id or "OAUTH", FamilyVerdict.NEEDS_HUMAN_REVIEW,
        "redirect accepted but code/token delivery to attacker not proven",
    )


FAMILY_VALIDATORS: dict[str, Any] = {
    "race_condition": validate_race_condition,
    "tenant_isolation": validate_tenant_isolation,
    "multi_step_auth_bypass": validate_multi_step_auth_bypass,
    "exploit_chain": validate_exploit_chain,
    "business_logic": validate_business_logic,
    "oauth": validate_oauth,
}

# Required evidence inputs per validator (used by the dispatch bridge to
# fail-closed when the evidence pack is incomplete).
VALIDATOR_REQUIRED_INPUTS: dict[str, tuple[str, ...]] = {
    "race_condition": ("burst_replays", "sequential_replays", "post_state_replay", "expected_side_effect_count"),
    "tenant_isolation": ("actor_a_replay", "actor_b_baseline", "foreign_tenant_identifiers"),
    "multi_step_auth_bypass": ("step_inventory", "direct_final_replay", "post_replay_session_check"),
    "exploit_chain": ("feeder_findings", "composed_replay", "feeder_artifacts_used"),
    "business_logic": ("tampered_replay", "baseline_replay", "post_state_replay", "invariant_broken_marker"),
    "oauth": ("attacker_redirect_replay",),
}


def dispatch_family_validator(vuln_class: str, evidence_pack: dict[str, Any]) -> FamilyValidationResult:
    """Dispatch bridge — the live dispatch path for the five families + OAuth.

    Fail-closed: if a required evidence input is missing, returns
    NEEDS_HUMAN_REVIEW (never silent, never auto-confirmed).
    """
    validator = FAMILY_VALIDATORS.get(str(vuln_class))
    if validator is None:
        return FamilyValidationResult(str(vuln_class), "UNKNOWN", FamilyVerdict.NOT_SCANNED, "no family validator")
    required = VALIDATOR_REQUIRED_INPUTS.get(str(vuln_class), ())
    # Missing = None / empty container / empty string. Numeric 0 (e.g.
    # expected_side_effect_count=0) is a legitimate value, NOT missing.
    _EMPTY = (None, [], "", {}, ())
    missing = [k for k in required if evidence_pack.get(k) in _EMPTY or k not in evidence_pack]
    if missing:
        return FamilyValidationResult(
            str(vuln_class), "DISPATCH", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            f"missing required evidence inputs: {missing}",
        )
    try:
        return validator(**evidence_pack)
    except TypeError as exc:
        return FamilyValidationResult(
            str(vuln_class), "DISPATCH", FamilyVerdict.NEEDS_HUMAN_REVIEW,
            f"validator signature mismatch: {exc}",
        )


__all__ = [
    "FamilyVerdict",
    "FamilyValidationResult",
    "ProofBundleSpec",
    "Replay",
    "FAMILY_VALIDATORS",
    "VALIDATOR_REQUIRED_INPUTS",
    "dispatch_family_validator",
    "validate_business_logic",
    "validate_exploit_chain",
    "validate_multi_step_auth_bypass",
    "validate_oauth",
    "validate_race_condition",
    "validate_tenant_isolation",
]
