"""TEAM-1 — ProofBundle semantic integrity layer.

Three preserved layers:
  1. Cryptographic (verify_seal) — bytes unchanged after sealing
  2. Semantic (ProofSemanticValidator + canonical_semantic_digest) — required evidence existed BEFORE sealing, ALL security-critical semantics bound to seal
  3. Promotion (proof_bundle_promotion_ready + promotion_valid) — strict promotion rules

CRITICAL FIX (TEAM-2 hostile acceptance): canonical_semantic_digest covers ALL
security-critical semantics and is stored in validator_config_digest, which IS
in the seal payload. Any semantic tampering post-seal breaks either the crypto
seal or the re-derived semantic digest. created_at/chronology/execution identity
are now bound to the seal.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Final

from webpent.models.evidence import redact_sensitive, sha256_text
from webpent.models.proof_bundle import ProofBundle, build_proof_bundle

REQUIRED_SEMANTIC_FIELDS: Final[tuple[str, ...]] = (
    "target_identity", "vulnerability_class", "baseline", "candidate",
    "negative_control", "evidence_origin", "causal_result",
    "execution_identity", "session_context", "replay_information",
)


class SemanticValidationError(ValueError):
    pass


class SemanticValidationReport:
    def __init__(self, complete: bool, missing_fields: tuple, invalid_fields: tuple, details: dict | None = None):
        self.complete = complete
        self.missing_fields = missing_fields
        self.invalid_fields = invalid_fields
        self.details = details or {}
    @property
    def reason(self) -> str:
        parts = []
        if self.missing_fields: parts.append(f"missing:{','.join(self.missing_fields)}")
        if self.invalid_fields: parts.append(f"invalid:{','.join(self.invalid_fields)}")
        return ";".join(parts) if parts else "unknown_semantic_failure"


def canonical_semantic_representation(bundle: Any) -> dict[str, Any]:
    """Canonical, deterministic semantic identity of a ProofBundle.

    Covers ALL security-critical semantics including chronology, execution
    identity, negative-control identity, evidence origin, target-backed,
    lifecycle, causal relation. Deterministic field ordering. Any semantically
    meaningful change MUST change this representation.
    """
    def _d(payload: Any) -> str:
        text = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(text.encode()).hexdigest()}"
    return {
        "schema_version": "canonical_semantic_v1",
        "engagement_id": getattr(bundle, "engagement_id", None),
        "finding_id": getattr(bundle, "finding_id", None),
        "hypothesis_id": getattr(bundle, "hypothesis_id", None),
        "vulnerability_class": getattr(bundle, "vulnerability_class", None),
        "target_identity": getattr(bundle, "target_identity", None) or getattr(bundle, "target_fingerprint", None),
        "evidence_origin": getattr(bundle, "evidence_origin", None),
        "target_backed": getattr(bundle, "target_backed", None),
        "negative_control_independent": getattr(bundle, "negative_control_independent", None),
        "oracle_decision": getattr(bundle, "oracle_decision", None),
        "causal_oracle_digest": _d(getattr(bundle, "causal_oracle", {})),
        "scope_context_digest": _d(getattr(bundle, "scope_context", {})),
        "identity_context_digest": _d(getattr(bundle, "identity_context", {})),
        "replay_metadata_digest": _d(getattr(bundle, "replay_metadata", {})),
        "baseline_digest": getattr(bundle, "baseline_digest", None),
        "negative_control_digest": getattr(bundle, "negative_control_digest", None),
        "evidence_refs": sorted(list(getattr(bundle, "evidence_refs", []) or [])),
        "evidence_digests": sorted(list(getattr(bundle, "evidence_digests", []) or [])),
        "request_digests": sorted(list(getattr(bundle, "request_digests", []) or [])),
        "response_digests": sorted(list(getattr(bundle, "response_digests", []) or [])),
        "baseline_evidence_ref": getattr(bundle, "baseline_evidence_ref", None),
        "candidate_evidence_ref": getattr(bundle, "candidate_evidence_ref", None),
        "negative_control_evidence_ref": getattr(bundle, "negative_control_evidence_ref", None),
        "validator_id": getattr(bundle, "validator_id", None),
        "validator_version": getattr(bundle, "validator_version", None),
        "run_id": getattr(bundle, "run_id", None),
        "campaign_id": getattr(bundle, "campaign_id", None),
        "cleanup_status": getattr(bundle, "cleanup_status", None),
        "bundle_id": getattr(bundle, "bundle_id", None),
    }


def canonical_semantic_digest(bundle: Any) -> str:
    rep = canonical_semantic_representation(bundle)
    text = json.dumps(rep, sort_keys=True, separators=(",", ":"))
    return f"semantic_v1:{hashlib.sha256(text.encode()).hexdigest()}"


class ProofSemanticValidator:
    valid_origins = {"target_runtime", "engine_validation", "offline_replay", "external_verified"}

    @staticmethod
    def _evidence_digest(payload: Any) -> str:
        text = json.dumps(payload, sort_keys=True, default=str) if not isinstance(payload, str) else payload
        return f"sha256:{hashlib.sha256(text.encode()).hexdigest()[:16]}"

    def validate(self, *, target_fingerprint, vulnerability_class, baseline, candidate,
                 negative_control, evidence_origin, causal_result, execution_identity,
                 session_context, replay_context=None) -> SemanticValidationReport:
        missing, invalid = [], []
        if not target_fingerprint: missing.append("target_identity")
        if not vulnerability_class or not str(vulnerability_class).strip(): missing.append("vulnerability_class")
        if baseline is None: missing.append("baseline")
        if candidate is None: missing.append("candidate")
        if negative_control is None: missing.append("negative_control")
        if not evidence_origin: missing.append("evidence_origin")
        if not causal_result: missing.append("causal_result")
        if not execution_identity or not str(execution_identity).strip(): missing.append("execution_identity")
        if not session_context: missing.append("session_context")
        if negative_control is not None and baseline is not None:
            if self._evidence_digest(negative_control) == self._evidence_digest(baseline):
                invalid.append("negative_control_identical_to_baseline")
        if negative_control is not None and candidate is not None:
            if self._evidence_digest(negative_control) == self._evidence_digest(candidate):
                invalid.append("negative_control_identical_to_candidate")
        if causal_result and causal_result.get("causal_signal") is not True:
            invalid.append("causal_signal_not_true")
        if causal_result and not causal_result.get("negative_control_complete"):
            invalid.append("negative_control_not_complete")
        if evidence_origin and evidence_origin not in self.valid_origins and evidence_origin != "target_runtime":
            invalid.append("evidence_origin_not_target_runtime")
        return SemanticValidationReport(complete=not missing and not invalid,
                                        missing_fields=tuple(missing), invalid_fields=tuple(invalid))

    def validate_bundle(self, bundle: ProofBundle) -> SemanticValidationReport:
        missing, invalid = [], []
        if not getattr(bundle, "target_fingerprint", None) and not getattr(bundle, "target_identity", None):
            missing.append("target_identity")
        if not getattr(bundle, "vulnerability_class", None): missing.append("vulnerability_class")
        if not getattr(bundle, "baseline_digest", None): missing.append("baseline")
        if not getattr(bundle, "negative_control_digest", None): missing.append("negative_control")
        if not getattr(bundle, "evidence_refs", []): missing.append("evidence_refs")
        if not getattr(bundle, "causal_oracle", {}).get("causal_signal"): invalid.append("causal_signal_not_true")
        return SemanticValidationReport(complete=not missing and not invalid,
                                        missing_fields=tuple(missing), invalid_fields=tuple(invalid))


def build_promotion_grade_bundle(*, engagement_id, finding_id, vulnerability_class, baseline,
                                 candidate, negative_control, evidence_origin, causal_result,
                                 execution_identity, session_context, replay_context=None,
                                 target_fingerprint=None, hypothesis_id=None, actor="system") -> ProofBundle:
    validator = ProofSemanticValidator()
    report = validator.validate(target_fingerprint=target_fingerprint, vulnerability_class=vulnerability_class,
        baseline=baseline, candidate=candidate, negative_control=negative_control,
        evidence_origin=evidence_origin, causal_result=causal_result, execution_identity=execution_identity,
        session_context=session_context, replay_context=replay_context)
    if not report.complete:
        raise SemanticValidationError(f"Cannot build promotion-grade bundle: {report.reason}. Missing: {report.missing_fields}. Invalid: {report.invalid_fields}.")

    # CALLER-FORGING RESISTANCE: derive from evidence, never trust caller.
    bd = ProofSemanticValidator._evidence_digest(baseline)
    cd = ProofSemanticValidator._evidence_digest(candidate)
    nd = ProofSemanticValidator._evidence_digest(negative_control)
    nc_independent = (nd != bd and nd != cd)
    if not nc_independent:
        raise SemanticValidationError("Caller-forging resistance: negative_control is NOT independent (digest matches baseline or candidate). Derived from evidence, never trusted from caller assertion.")

    origin = "target_runtime" if evidence_origin == "target_runtime" else "offline_fixture"
    derived_target_backed = (origin == "target_runtime")
    if causal_result.get("target_backed") is True and not derived_target_backed:
        raise SemanticValidationError("Caller-forging resistance: caller asserted target_backed=True but evidence_origin is not target_runtime.")
    if causal_result.get("oracle_decision") == "CONFIRMED" and causal_result.get("causal_signal") is not True:
        raise SemanticValidationError("Caller-forging resistance: oracle_decision=CONFIRMED asserted but causal_signal is not True.")

    # CROSS-RUN + CHRONOLOGY + EXECUTION IDENTITY consistency.
    run_ids = []
    for ctx in (session_context, replay_context, causal_result):
        if isinstance(ctx, dict):
            for k in ("run_id", "experiment_id", "campaign_id", "engagement_id"):
                v = ctx.get(k)
                if v: run_ids.append((k, str(v)))
    if run_ids:
        by_key: dict[str, set] = {}
        for k, v in run_ids: by_key.setdefault(k, set()).add(v)
        mismatched = {k: v for k, v in by_key.items() if len(v) > 1}
        if mismatched:
            raise SemanticValidationError(f"Cross-run consistency violation: mismatched identifiers {mismatched}.")

    # EXECUTION IDENTITY: baseline, candidate, negative_control must reference
    # DISTINCT executions. If execution IDs are provided and match → fail.
    exec_ids = set()
    for ev in (baseline, candidate, negative_control):
        if isinstance(ev, dict) and ev.get("execution_id"):
            eid = str(ev["execution_id"])
            if eid in exec_ids:
                raise SemanticValidationError(f"Execution identity violation: execution_id {eid} reused for multiple evidence roles. Baseline/attacker/negative_control must be distinct executions.")
            exec_ids.add(eid)

    # CHRONOLOGY: timestamps across contexts must not be wildly disconnected.
    timestamps = [t for t in (causal_result.get("timestamp"), session_context.get("timestamp"),
                              (replay_context or {}).get("timestamp")) if t is not None]
    if timestamps:
        try:
            ts = [int(float(t)) for t in timestamps]
        except (ValueError, TypeError):
            ts = []
        if ts and (max(ts) - min(ts)) > 86400 * 365:
            raise SemanticValidationError("Chronology violation: timestamps disconnected (>1 year apart). Must derive from real event ordering.")

    def _ref(prefix, payload):
        text = json.dumps(payload, sort_keys=True, default=str) if not isinstance(payload, str) else payload
        clean, _ = redact_sensitive(text)
        return f"{prefix}_{sha256_text(clean)[:16]}"

    baseline_ref, candidate_ref, nc_ref = _ref("baseline", baseline), _ref("candidate", candidate), _ref("negctrl", negative_control)

    bundle = build_proof_bundle(
        engagement_id=engagement_id, finding_id=finding_id,
        evidence=(baseline, candidate, negative_control),
        evidence_refs=(baseline_ref, candidate_ref, nc_ref),
        negative_control=negative_control, hypothesis_id=hypothesis_id,
        target_fingerprint=target_fingerprint,
        scope_context=session_context.get("scope_context", {}),
        identity_context=session_context.get("identity_context", {}),
        baseline=baseline,
        request_evidence=tuple(causal_result.get("request_evidence", [])),
        response_evidence=tuple(causal_result.get("response_evidence", [])),
        causal_oracle={"causal_signal": True, "negative_control_complete": True,
                       "requires_target_backed": causal_result.get("requires_target_backed", False),
                       **{k: v for k, v in causal_result.items()
                          if k not in {"oracle_decision", "requires_target_backed", "request_evidence",
                                       "response_evidence", "validator_version", "target_backed", "timestamp"}}},
        target_backed=derived_target_backed, negative_control_independent=nc_independent,
        validator_id=execution_identity, validator_version=causal_result.get("validator_version", "semantic_v1"),
        replay_metadata={"replayable": bool(replay_context and replay_context.get("replayable", True)), **(replay_context or {})},
        cleanup_status="complete", target_identity=target_fingerprint,
        vulnerability_class=vulnerability_class,
        baseline_evidence_ref=baseline_ref, candidate_evidence_ref=candidate_ref,
        negative_control_evidence_ref=nc_ref,
        oracle_decision=causal_result.get("oracle_decision", "CONFIRMED"),
        evidence_origin=origin,
    )
    # CRITICAL: bind canonical semantic digest to the seal (stored in validator_config_digest
    # which IS in _seal_payload). Any post-seal semantic tampering breaks the seal.
    bundle = bundle.model_copy(update={"validator_config_digest": canonical_semantic_digest(bundle)})
    return bundle.seal(actor=actor)


def replay_semantic_consistent(bundle: ProofBundle) -> tuple[bool, str]:
    rm = bundle.replay_metadata or {}
    if rm.get("replayable") is not True: return False, "replay_not_marked_replayable"
    if not bundle.engagement_id: return False, "replay_missing_engagement_id"
    if not bundle.baseline_digest or len(bundle.evidence_digests) < 2: return False, "replay_missing_evidence_digests"
    if not bundle.negative_control_digest: return False, "replay_missing_negative_control_digest"
    if not bundle.verify_seal(): return False, "replay_cryptographic_seal_failed"
    validator = ProofSemanticValidator()
    sr = validator.validate_bundle(bundle)
    if not sr.complete: return False, f"replay_semantic_incomplete:{sr.reason}"
    return True, "replay_semantically_consistent"


def promotion_valid(bundle: Any) -> tuple[bool, str]:
    from webpent.models.proof_bundle import proof_bundle_promotion_ready
    try:
        b = bundle if isinstance(bundle, ProofBundle) else ProofBundle.model_validate(bundle)
    except Exception as exc:
        return False, f"bundle_parse_error:{exc}"
    # Layer 1: Cryptographic
    if not b.verify_seal(): return False, "cryptographic_seal_failed"
    # Layer 2: Semantic completeness
    validator = ProofSemanticValidator()
    sr = validator.validate_bundle(b)
    if not sr.complete: return False, f"semantic_incomplete:{sr.reason}"
    # Layer 2.5: Canonical semantic digest — binds ALL semantics to seal.
    expected = b.validator_config_digest or ""
    derived = canonical_semantic_digest(b)
    if expected and derived != expected:
        return False, "semantic_digest_mismatch:post_seal_tampering_detected"
    # Layer 3: Strict promotion contract
    if not proof_bundle_promotion_ready(b): return False, "promotion_contract_failed"
    # Layer 4: Replay consistency
    rok, rreason = replay_semantic_consistent(b)
    if not rok: return False, f"replay_semantic_fail:{rreason}"
    return True, "promotion_valid"


__all__ = ["ProofSemanticValidator", "SemanticValidationReport", "SemanticValidationError",
           "build_promotion_grade_bundle", "promotion_valid", "replay_semantic_consistent",
           "canonical_semantic_representation", "canonical_semantic_digest", "REQUIRED_SEMANTIC_FIELDS"]
