"""Strict evidence verifier for deterministic promotion.

The verifier is deliberately small and side-effect free. It does not perform
network I/O and it never promotes a finding by itself; callers must provide
observations produced by an authorized validator. It checks that a baseline
and a candidate exist, that the validator supplied independent causal and
negative-control signals, and that the resulting sealed ProofBundle can be
replayed from the redaction-safe observations.

UM-DR-35 corrective closure: CausalGuard
(``webpent.cqa_v2.causal_guard.guarded_causal_evaluate``) is the SOLE
technical confirmation authority. This verifier therefore MANDATORILY
adjudicates the exact baseline/candidate/negative-control evidence through
``webpent.production.confirmation_adapter.adjudicate_with_causal_guard``
before any bundle is built. Caller-supplied boolean signals are recorded as
advisory only — they can never produce a passing verification on their own,
and a non-CONFIRMED guard verdict blocks promotion (fail-closed).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

from webpent.cqa_v2.causal_guard import Verdict as CausalGuardVerdict
from webpent.models.evidence import redact_sensitive
from webpent.models.findings import Finding
from webpent.models.proof_bundle import (
    ProofBundle,
    build_proof_bundle,
    proof_bundle_promotion_ready,
)
from webpent.shared.proof_oracles import CausalDecision, CausalOracleResult


@dataclass(frozen=True)
class VerificationResult:
    """Immutable result of one bounded verifier pass."""

    passed: bool
    reason: str
    evidence: dict[str, Any]
    proof_bundle: ProofBundle | None = None


def _target_fingerprint(url: str) -> str:
    """Hash one stable origin/path shape consistently with browser adapters."""
    parsed = urlparse(str(url))
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    shape = urlunparse((scheme, netloc, path, "", "", ""))
    return f"sha256:{hashlib.sha256(shape.encode('utf-8', 'replace')).hexdigest()}"


def _digest(value: Any) -> str:
    import json

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(encoded.encode('utf-8', 'replace')).hexdigest()}"


def _target_observation_ok(
    value: Any,
    *,
    role: str,
    target_fingerprint: str,
) -> bool:
    """Accept redacted target evidence with transport and origin provenance.

    Older target-backed callers did not emit ``evidence_origin``; absence is
    accepted for compatibility, while an explicit offline tag is fail-closed.
    """
    if not isinstance(value, Mapping):
        return False
    origin = value.get("evidence_origin")
    return bool(
        value.get("target_backed") is True
        and origin != "offline_fixture"
        and value.get("observation_role") == role
        and value.get("target_fingerprint") == target_fingerprint
        and isinstance(value.get("request_digest"), str)
        and value.get("request_digest", "").startswith("sha256:")
        and isinstance(value.get("response_digest"), str)
        and value.get("response_digest", "").startswith("sha256:")
    )


def verify_replay_evidence(
    finding: Finding,
    *,
    baseline: dict[str, Any] | None,
    candidate: dict[str, Any] | None,
    negative_control: dict[str, Any] | None,
    target_fingerprint: str | None = None,
    causal_signal: bool = False,
    negative_control_complete: bool = False,
    validator_id: str,
    validator_version: str,
    causal_basis: str,
    engagement_id: str,
    hypothesis_id: str | None = None,
    scope_context: dict[str, Any] | None = None,
    identity_context: dict[str, Any] | None = None,
    replay_metadata: dict[str, Any] | None = None,
    target_package_id: str | None = None,
    target_package_sha256: str | None = None,
    target_package_scope_digest: str | None = None,
    target_package_policy_digest: str | None = None,
    require_target_backed: bool = False,
    # vNext additive parameters
    causal_result: CausalOracleResult | None = None,
    campaign_id: str | None = None,
    run_id: str | None = None,
    vulnerability_class: str | None = None,
    target_identity: str | None = None,
    target_context_hash: str | None = None,
) -> VerificationResult:
    """Verify a baseline/candidate replay and create a strict proof bundle.

    Confirmation requires deterministic causal and negative-control signals.
    If ``causal_result`` is provided, it must be ``CONFIRMED``. Otherwise,
    legacy boolean signals are used. The verifier rejects missing observations,
    missing provenance, and any bundle that fails its promotion contract.
    """
    evidence: dict[str, Any] = {
        "verifier": "webpent.replay.v2",
        "validator_id": str(validator_id)[:120],
        "validator_version": str(validator_version)[:80],
    }

    # Handle vNext vs Legacy signals
    if causal_result:
        causal_signal = causal_result.decision == CausalDecision.CONFIRMED
        negative_control_complete = causal_result.negative_control_observed
        causal_basis = causal_result.reason
        decision_value = (
            causal_result.decision.value
            if isinstance(causal_result.decision, CausalDecision)
            else str(causal_result.decision)
        )
        evidence["causal_decision"] = decision_value

    evidence["causal_signal"] = bool(causal_signal)
    evidence["negative_control_complete"] = bool(negative_control_complete)
    evidence["evidence_origin"] = (
        "target_runtime" if require_target_backed else "offline_fixture"
    )
    evidence["causal_basis"] = str(causal_basis)[:240]

    if baseline is None or candidate is None:
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "baseline_and_candidate_required",
        }
        return VerificationResult(False, "baseline_and_candidate_required", evidence)
    if negative_control is None:
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "negative_control_required",
        }
        return VerificationResult(False, "negative_control_required", evidence)

    if not causal_signal or not negative_control_complete:
        reason = "causal_signal_and_negative_control_required"
        if causal_result and causal_result.decision != CausalDecision.CONFIRMED:
            decision_value = (
                causal_result.decision.value
                if isinstance(causal_result.decision, CausalDecision)
                else str(causal_result.decision)
            )
            reason = f"causal_oracle_{decision_value.lower()}"

        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": reason,
        }
        return VerificationResult(False, reason, evidence)

    expected_target_fingerprint = str(
        target_fingerprint or _target_fingerprint(finding.url)
    ).strip()
    if not expected_target_fingerprint.startswith("sha256:"):
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "target_fingerprint_invalid",
        }
        return VerificationResult(False, "target_fingerprint_invalid", evidence)

    if require_target_backed:
        if any(
            isinstance(observation, Mapping)
            and observation.get("evidence_origin") == "offline_fixture"
            for observation in (baseline, candidate, negative_control)
        ):
            evidence["promotion_guard"] = {
                "status": "blocked",
                "reason": "offline_fixture_cannot_be_target_backed",
            }
            return VerificationResult(
                False,
                "offline_fixture_cannot_be_target_backed",
                evidence,
            )
        if not _target_observation_ok(
            baseline, role="baseline", target_fingerprint=expected_target_fingerprint
        ) or not _target_observation_ok(
            candidate, role="candidate", target_fingerprint=expected_target_fingerprint
        ):
            evidence["promotion_guard"] = {
                "status": "blocked",
                "reason": "target_backed_baseline_and_candidate_required",
            }
            return VerificationResult(
                False,
                "target_backed_baseline_and_candidate_required",
                evidence,
            )
        if causal_result and any(
            not isinstance(observation, Mapping)
            or observation.get("evidence_origin") != "target_runtime"
            for observation in (baseline, candidate, negative_control)
        ):
            evidence["promotion_guard"] = {
                "status": "blocked",
                "reason": "target_runtime_origin_required",
            }
            return VerificationResult(False, "target_runtime_origin_required", evidence)
        if not _target_observation_ok(
            negative_control,
            role="negative_control",
            target_fingerprint=expected_target_fingerprint,
        ):
            evidence["promotion_guard"] = {
                "status": "blocked",
                "reason": "independent_target_backed_negative_control_required",
            }
            return VerificationResult(
                False,
                "independent_target_backed_negative_control_required",
                evidence,
            )
        request_digests = {
            candidate.get("request_digest"),
            negative_control.get("request_digest"),
        }
        if len(request_digests) != 2:
            evidence["promotion_guard"] = {
                "status": "blocked",
                "reason": "negative_control_must_be_independent",
            }
            return VerificationResult(False, "negative_control_must_be_independent", evidence)

    provenance_values = {
        "engagement_id": str(engagement_id or "").strip(),
        "validator_id": str(validator_id or "").strip(),
        "validator_version": str(validator_version or "").strip(),
        "causal_basis": str(causal_basis or "").strip(),
    }
    placeholder_engagements = {
        "default",
        "default-engagement",
        "runtime-unbound",
        "unknown",
        "none",
    }
    if (
        not all(provenance_values.values())
        or provenance_values["engagement_id"].lower() in placeholder_engagements
    ):
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "verifier_provenance_incomplete_or_placeholder",
        }
        return VerificationResult(
            False,
            "verifier_provenance_incomplete_or_placeholder",
            evidence,
        )

    clean_scope = dict(scope_context or {})
    clean_identity = dict(identity_context or {})
    if not clean_scope or not clean_identity:
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "scope_and_identity_context_required",
        }
        return VerificationResult(False, "scope_and_identity_context_required", evidence)

    # ------------------------------------------------------------------
    # UM-DR-35 §1.1/§1.3 — MANDATORY CausalGuard adjudication.
    # The authority (webpent.cqa_v2.causal_guard.guarded_causal_evaluate)
    # adjudicates the exact three observations this verifier holds. The
    # caller-supplied booleans above are advisory only; the decisive
    # causal_signal / negative_control_complete are DERIVED from the typed
    # guard result. Any non-CONFIRMED verdict blocks (fail-closed), and the
    # guard provenance is embedded in both the evidence and the bundle.
    # ------------------------------------------------------------------
    from webpent.production.confirmation_adapter import (  # noqa: PLC0415
        adjudicate_with_causal_guard,
    )
    guard_class = str(vulnerability_class or finding.vuln_class or "").upper()
    adjudication = adjudicate_with_causal_guard(
        baseline,
        candidate,
        negative_control,
        vulnerability_class=guard_class or "UNKNOWN",
        identity_context=clean_identity,
        extra_context={
            "resource_owner": (
                clean_identity.get("resource_owner")
                or clean_identity.get("expected_owner")
            ),
        },
    )
    guard_result = adjudication.guard_result
    guard_verdict = str(guard_result.verdict.value)
    evidence["causal_guard"] = adjudication.to_dict()
    evidence["causal_signal"] = adjudication.confirmed
    evidence["negative_control_complete"] = bool(
        adjudication.confirmed
        and adjudication.role_signals.get("negative_control", {}).get("signal") is True
    )
    if not adjudication.confirmed:
        reason = f"causal_guard_verdict_{guard_verdict.lower()}"
        if guard_result.block_reason:
            reason = f"causal_guard_blocked:{guard_result.block_reason}"
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": reason,
            "authority": "webpent.cqa_v2.causal_guard.guarded_causal_evaluate",
            "guard_verdict": guard_verdict,
        }
        return VerificationResult(False, reason, evidence)
    if causal_result and causal_result.decision != CausalDecision.CONFIRMED:
        # A secondary oracle disagreeing with the authority still blocks.
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "causal_oracle_disagrees_with_causal_guard",
        }
        return VerificationResult(
            False, "causal_oracle_disagrees_with_causal_guard", evidence,
        )

    clean_baseline = redact_sensitive(baseline)[0]
    clean_candidate = redact_sensitive(candidate)[0]
    clean_negative_control = redact_sensitive(negative_control)[0]

    replay = {
        "replayable": True,
        "sequence": ["baseline", "candidate", "negative_control"],
        "negative_control": "negative_control",
        "observations": 3,
        "target_backed": bool(require_target_backed),
        "independent_control": bool(require_target_backed),
    }

    # vNext bundle construction
    # E2E WAVE R-4 (runtime-discovered 2026-09-15): Finding.hypothesis_id is
    # a UUID in the live graph path; ProofBundle declares it as str. Coerce
    # instead of letting a Pydantic ValidationError abort the whole
    # engagement mid-promotion.
    _hypothesis_id_str = (
        str(hypothesis_id) if hypothesis_id else f"finding:{finding.id}"
    )
    bundle_kwargs = {
        "engagement_id": engagement_id,
        "finding_id": str(finding.id),
        "hypothesis_id": _hypothesis_id_str,
        "target_fingerprint": expected_target_fingerprint,
        "target_package_id": target_package_id,
        "target_package_sha256": target_package_sha256,
        "target_package_scope_digest": target_package_scope_digest,
        "target_package_policy_digest": target_package_policy_digest,
        "scope_context": clean_scope,
        "identity_context": clean_identity,
        "evidence": [clean_baseline, clean_candidate, clean_negative_control],
        "evidence_refs": (
            f"replay:{validator_id}:baseline",
            f"replay:{validator_id}:candidate",
            f"replay:{validator_id}:negative_control",
        ),
        "negative_control": clean_negative_control,
        "baseline": clean_baseline,
        "request_evidence": [clean_baseline, clean_candidate, clean_negative_control],
        "response_evidence": [clean_baseline, clean_candidate, clean_negative_control],
        "causal_oracle": {
            "causal_signal": True,
            "negative_control_complete": True,
            "requires_target_backed": bool(require_target_backed),
            "basis": str(causal_basis)[:240],
            # UM-DR-35: the typed CausalGuard adjudication that this bundle's
            # confirmation is grounded in — same evidence, same verdict, full
            # provenance (authority module, role signals, observation digests).
            "causal_guard": adjudication.to_dict(),
        },
        "target_backed": bool(require_target_backed),
        "negative_control_independent": bool(require_target_backed),
        "evidence_origin": (
            "target_runtime" if require_target_backed else "offline_fixture"
        ),
        # UM-DR-35: for target-runtime evidence the decisive oracle decision is
        # the CausalGuard verdict (CONFIRMED — adjudicated above). Offline
        # fixture bundles deliberately keep no oracle decision: they are
        # engine-validation artifacts and can never enter scoring promotion.
        **(
            {"oracle_decision": "CONFIRMED"} if require_target_backed else {}
        ),
        "validator_id": validator_id,
        "validator_version": validator_version,
        "replay_metadata": {**replay, **(replay_metadata or {})},
        "cleanup_status": "not_applicable",
        "redaction_manifest": (
            "request_body",
            "cookie",
            "authorization",
            "set-cookie",
            "raw_response_body",
        ),
    }

    if causal_result:
        bundle_kwargs.update({
            "campaign_id": campaign_id,
            "run_id": run_id,
            "vulnerability_class": vulnerability_class,
            "target_identity": target_identity,
            "target_context_hash": target_context_hash,
            "baseline_evidence_ref": causal_result.baseline.observation_ref,
            "candidate_evidence_ref": causal_result.candidate.observation_ref,
            "negative_control_evidence_ref": causal_result.negative_control.observation_ref,
            "oracle_decision": (
                causal_result.decision.value
                if isinstance(causal_result.decision, CausalDecision)
                else str(causal_result.decision)
            ),
            "invariant_analysis": causal_result.invariant_analysis,
            "validator_result": causal_result.model_dump(mode="json"),
            "evidence_origin": (
                "target_runtime" if require_target_backed else "offline_fixture"
            ),
        })

    bundle = build_proof_bundle(**bundle_kwargs).seal(actor="strict_replay_verifier")

    replay_context: dict[str, Any] = {
        "engagement_id": str(engagement_id),
        "finding_id": str(finding.id),
        "hypothesis_id": hypothesis_id or f"finding:{finding.id}",
        "target_fingerprint": expected_target_fingerprint,
        "scope_context": clean_scope,
        "identity_context": clean_identity,
    }
    if target_package_id:
        replay_context.update({
            "target_package_id": target_package_id,
            "target_package_sha256": target_package_sha256,
            "target_package_scope_digest": target_package_scope_digest,
            "target_package_policy_digest": target_package_policy_digest,
        })
    if campaign_id:
        replay_context["campaign_id"] = campaign_id
    if run_id:
        replay_context["run_id"] = run_id
    if target_identity:
        replay_context["target_identity"] = target_identity
    if target_context_hash:
        replay_context["target_context_hash"] = target_context_hash
    if vulnerability_class:
        replay_context["vulnerability_class"] = vulnerability_class
    if causal_result:
        replay_context.update({
            "oracle_decision": bundle.oracle_decision,
            "evidence_origin": bundle.evidence_origin,
            "invariant_analysis": bundle.invariant_analysis,
            "evidence_refs": bundle.evidence_refs,
            "sealed_digest": bundle.seal_digest,
        })

    if not proof_bundle_promotion_ready(bundle):
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "proof_bundle_promotion_contract_failed",
        }
        return VerificationResult(False, "proof_bundle_promotion_contract_failed", evidence)
    if not bundle.verify_seal():
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "proof_bundle_seal_verification_failed",
        }
        return VerificationResult(False, "proof_bundle_seal_verification_failed", evidence)
    if not bundle.replay(
        [baseline, candidate, negative_control],
        negative_control,
        replay_context=replay_context,
    ):
        evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "proof_bundle_replay_failed",
        }
        return VerificationResult(False, "proof_bundle_replay_failed", evidence)

    clean_replay_metadata = redact_sensitive(
        {**replay, **(replay_metadata or {}), "replay_verified": True}
    )[0]
    evidence.update({
        "proof_verified": True,
        "proof_bundle_sealed": True,
        "target_backed": bool(require_target_backed),
        "negative_control_independent": bool(require_target_backed),
        "proof_bundle": bundle.model_dump(mode="json"),
        "proof_evidence": [clean_baseline, clean_candidate, clean_negative_control],
        "baseline": clean_baseline,
        "candidate": clean_candidate,
        "negative_control": clean_negative_control,
        "evidence_refs": bundle_kwargs["evidence_refs"],
        "request_evidence": [clean_baseline, clean_candidate, clean_negative_control],
        "response_evidence": [clean_baseline, clean_candidate, clean_negative_control],
        "scope_context": clean_scope,
        "identity_context": clean_identity,
        "causal_oracle": bundle_kwargs["causal_oracle"],
        "validator_id": validator_id,
        "validator_version": validator_version,
        "cleanup_status": "not_applicable",
        "finding_id": str(finding.id),
        "hypothesis_id": hypothesis_id or f"finding:{finding.id}",
        "target_fingerprint": expected_target_fingerprint,
        "replay_context": replay_context,
        "replay_metadata": clean_replay_metadata,
        "promotion_guard": {
            "status": "passed",
            "proof_bundle_sealed": True,
            "replayable": True,
            "replay_verified": True,
            "replay_context": replay_context,
        },
    })
    return VerificationResult(True, "verified_replay", evidence, bundle)


__all__ = ["VerificationResult", "verify_replay_evidence"]
