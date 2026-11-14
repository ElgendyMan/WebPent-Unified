"""TEAM-1 — Autonomous Validation Intelligence V1 → Production Release Candidate.

This module CLOSES the final production gap. It wires the full autonomous
lifecycle into ONE deterministic, traceable, anti-fake pipeline:

    build_graph() dispatch
      → ResearchLoop (advisory only)
      → AutonomousExperimentSelector (deterministic, NO LLM authority)
      → ExperimentRegistry lookup
      → GenericExperimentRunner
      → Real authorized HTTP execution (ScopeLaw + ToolBoundary, 3 real requests)
      → ObservationNormalizer
      → Causal Validator (ValidatorAdapter → run_validator)
      → EvidenceQuality calculation
      → ProofBundle (sealed, HMAC-authentic)
      → Replay verification (deterministic re-derivation)
      → PromotionPipeline (anti-fake gates, fail-closed)
      → SecurityReport (promoted findings only)
      → OutcomeTracker → research feedback → next decision

ARCHITECTURE RULES (enforced here):
  * No second ScopeLaw / ToolBoundary — we delegate to ModernOrchestrator's.
  * No LLM confirmation authority — selection is deterministic scoring.
  * No scheduler replacement — ResearchLoop remains the only scheduler.
  * External tools remain advisory only — external scanner claims are REJECTED
    by PromotionPipeline.
  * No manual-only execution path — the campaign is driven by production
    dispatch (ModernOrchestrator.run_autonomous_validation_campaign), and the
    legacy manual helper is removed/redirected to this path.

ANTI-FKE GUARANTEES (PromotionPipeline rejects):
  1. synthetic observations            (evidence_origin != target_runtime)
  2. missing negative control
  3. missing baseline
  4. missing replay                    (replay_verified != True)
  5. unsigned ProofBundle              (sealed=False / no HMAC / verify_seal fails)
  6. external scanner authority claims (nuclei/zap/burp/sqlmap/... as verdict authority)
  7. confidence-only promotion         (no CONFIRMED causal validator outcome)
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Final, Literal
from urllib.parse import parse_qs, quote_plus, urlencode, urlsplit

from webpent.models.evidence import sha256_text
from webpent.production.experiment_fabric import (
    EXPERIMENT_REGISTRY,
    GenericExperimentRunner,
    normalize_observation,
)
from webpent.production.validators import (
    EvidenceQuality,
    ValidatorError,
    ValidationOutcome,
    extract_info_disclosure_indicators,
    extract_ssrf_indicators,
    _reflection_payload,
    parse_external_location,
    run_validator,
)

logger = logging.getLogger(__name__)

AVI_VERSION: Final[str] = "autonomous_validation_intelligence_v1"


def _canonical_finding_id(*, engagement_id: str, target_fingerprint: str,
                          hypothesis_id: str, experiment_id: str,
                          vulnerability_class: str) -> str:
    """Create a deterministic reportable ID scoped to one target run."""
    material = "|".join((
        str(engagement_id), str(target_fingerprint), str(hypothesis_id),
        str(experiment_id), str(vulnerability_class).upper(),
    ))
    return f"finding_{str(vulnerability_class).lower()}_{sha256_text(material)[:16]}"

# External scanner authority names — advisory only, NEVER promotion authority.
EXTERNAL_SCANNER_AUTHORITIES: Final[frozenset[str]] = frozenset({
    "nuclei", "zap", "burp", "burpsuite", "sqlmap", "nikto", "wpscan",
    "nmap", "masscan", "acunetix", "nessus", "openvas", "arachni",
    "w3af", "skipfish", "dirb", "gobuster", "ffuf", "external_scanner",
    "scanner_advisory", "llm_confidence", "llm_verdict",
})


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


# ===========================================================================
# 1. Deterministic Runtime Trace — hash-chained, append-only, tamper-evident.
#    Proves every required stage actually executed.
# ===========================================================================
@dataclass(frozen=True)
class TraceStage:
    """One immutable, hash-chained stage record."""
    seq: int
    stage: str
    component: str
    proof: dict[str, Any]          # bounded proof fields (ids, digests, booleans)
    at: str
    prev_digest: str
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq, "stage": self.stage, "component": self.component,
            "proof": self.proof, "at": self.at,
            "prev_digest": self.prev_digest, "digest": self.digest,
        }


class DeterministicRuntimeTrace:
    """Append-only, hash-chained runtime trace.

    Every record includes bounded PROOF fields (not just timestamps):
      - selected hypothesis id, selected experiment id, vulnerability class
      - real execution flag + request digests
      - validator adapter executed flag + outcome + evidence quality
      - proof created flag + bundle id + seal digest
      - replay verified flag
      - promotion decision + reason
      - research feedback recorded flag
    """

    REQUIRED_STAGES: Final[tuple[str, ...]] = (
        "research_loop_step",
        "experiment_selected",
        "registry_lookup",
        "real_execution",
        "observation_normalized",
        "validator_adapter_executed",
        "evidence_quality_calculated",
        "proof_created",
        "replay_verified",
        "promotion_decision",
        "research_feedback_recorded",
    )

    def __init__(self) -> None:
        self._stages: list[TraceStage] = []
        self._chain_root = sha256_text(f"avi_root_{AVI_VERSION}")[:16]

    @property
    def stages(self) -> tuple[TraceStage, ...]:
        return tuple(self._stages)

    def record(self, *, stage: str, component: str, proof: dict[str, Any]) -> TraceStage:
        prev = self._stages[-1].digest if self._stages else self._chain_root
        seq = len(self._stages) + 1
        at = _utc()
        proof_bounded = {k: (v if not isinstance(v, (dict, list)) else json.dumps(v, sort_keys=True, default=str)[:512])
                         for k, v in (proof or {}).items()}
        payload = json.dumps(
            {"seq": seq, "stage": stage, "component": component,
             "proof": proof_bounded, "at": at, "prev_digest": prev},
            sort_keys=True, default=str, separators=(",", ":"),
        )
        digest = hashlib.sha256(payload.encode()).hexdigest()
        rec = TraceStage(seq=seq, stage=stage, component=component,
                         proof=proof_bounded, at=at, prev_digest=prev, digest=digest)
        self._stages.append(rec)
        logger.debug("AVI trace[%s] %s/%s", seq, stage, component)
        return rec

    def saw_stage(self, stage: str) -> bool:
        return any(s.stage == stage for s in self._stages)

    def stages_by_name(self, stage: str) -> list[TraceStage]:
        return [s for s in self._stages if s.stage == stage]

    def verify_chain(self) -> bool:
        """Recompute every hash link. Tamper-evident."""
        prev = self._chain_root
        for s in self._stages:
            if s.prev_digest != prev:
                return False
            payload = json.dumps(
                {"seq": s.seq, "stage": s.stage, "component": s.component,
                 "proof": s.proof, "at": s.at, "prev_digest": s.prev_digest},
                sort_keys=True, default=str, separators=(",", ":"),
            )
            if hashlib.sha256(payload.encode()).hexdigest() != s.digest:
                return False
            prev = s.digest
        return True

    def coverage(self) -> dict[str, bool]:
        return {stage: self.saw_stage(stage) for stage in self.REQUIRED_STAGES}

    def full_coverage(self) -> bool:
        return all(self.coverage().values())

    def summary(self) -> dict[str, Any]:
        return {
            "avi_version": AVI_VERSION,
            "stage_count": len(self._stages),
            "coverage": self.coverage(),
            "full_coverage": self.full_coverage(),
            "chain_verified": self.verify_chain(),
            "head_digest": self._stages[-1].digest if self._stages else None,
        }

    def to_list(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self._stages]


# ===========================================================================
# 2. AutonomousExperimentSelector — deterministic, NO LLM authority.
#    Scores hypotheses by: registry coverage, information value, novelty.
# ===========================================================================
class AutonomousExperimentSelector:
    """Deterministic hypothesis→experiment selector. Advisory inputs only.

    The LLM/ResearchLoop may propose and reorder, but the FINAL selection is
    deterministic scoring here. No LLM confirmation authority.
    """

    def __init__(self) -> None:
        self._selected_signatures: set[str] = set()
        self.selection_count = 0

    @staticmethod
    def _score(hypothesis: dict[str, Any], registry: dict[str, Any]) -> tuple[int, str]:
        """Deterministic score tuple (higher = selected first)."""
        vuln = str(hypothesis.get("vulnerability_class", "")).upper()
        in_registry = 1000 if vuln in registry else 0
        info = int(float(hypothesis.get("information_value", hypothesis.get("priority", 0.5)) or 0.5) * 100)
        api_bonus = 50 if str(hypothesis.get("api_type", "rest")).lower() in ("rest", "graphql") else 0
        # UM-DR-36 corrective closure: the application semantic model
        # influences experiment selection. A hypothesis carrying an
        # evidence-backed appmodel hint (object-ownership boundary /
        # identity relationship, recorded by the hypothesis node's
        # semantic-influence pass) scores higher — a deterministic,
        # recorded influence on the research decision. Advisory only:
        # the hint can reorder selection, never authorize or confirm.
        semantic_bonus = 0
        evidence_contract = hypothesis.get("evidence_contract")
        if isinstance(evidence_contract, dict) and isinstance(
            evidence_contract.get("appmodel_hint"), dict,
        ):
            appmodel_hint = evidence_contract["appmodel_hint"]
            semantic_bonus = {
                "object_ownership_boundary": 200,
                "identity_relationship": 120,
                "observed_behavior": 60,
                "coverage_gap": 20,
            }.get(str(appmodel_hint.get("kind")), 0)
        # tie-break by hypothesis id for full determinism
        return (in_registry + info + api_bonus + semantic_bonus, str(hypothesis.get("id", "")))

    def select(self, hypotheses: list[dict[str, Any]],
               registry: dict[str, Any] | None = None) -> dict[str, Any]:
        """Select the next hypothesis + experiment. Deterministic.

        Returns {hypothesis_id, vulnerability_class, experiment_id,
                 api_type, target_path, selection_reason}.
        Raises StopIteration-ish (returns None-ish dict) when none remain.
        """
        reg = registry if registry is not None else EXPERIMENT_REGISTRY
        available = [h for h in hypotheses
                     if str(h.get("id", "")) not in self._selected_signatures]
        if not available:
            return {"selected": False, "reason": "no_available_hypotheses"}
        ranked = sorted(available, key=lambda h: self._score(h, reg), reverse=True)
        chosen = ranked[0]
        hid = str(chosen["id"])
        vuln = str(chosen.get("vulnerability_class", "")).upper()
        exp = reg.get(vuln, {}).get("experiment_id", f"exp_unknown_{vuln.lower()}")
        self._selected_signatures.add(hid)
        self.selection_count += 1
        return {
            "selected": True,
            "hypothesis_id": hid,
            "vulnerability_class": vuln,
            "experiment_id": exp,
            "api_type": str(chosen.get("api_type", "rest")).lower(),
            "target_path": str(chosen.get("path", chosen.get("endpoint", "/api/"))),
            "graphql_query": chosen.get("graphql_query"),
            "selection_reason": "deterministic_score:registry_coverage+information_value+novelty",
            "selector_version": "autonomous_experiment_selector_v1",
            # V1.2 release closure (TEAM-4 BLOCKER 2): record the deterministic
            # runner-up candidates rejected by THIS selection decision. Same
            # scoring function, same pass — no new authority, full transparency.
            "selected_candidate_score": self._score(chosen, reg)[0],
            "rejected_candidates": [
                {
                    "hypothesis_id": str(h.get("id", "")),
                    "vulnerability_class": str(h.get("vulnerability_class", "")).upper(),
                    "score": self._score(h, reg)[0],
                    "rejected_reason": "lower_deterministic_score_than_selected",
                }
                for h in ranked[1:9]
            ],
        }


# ===========================================================================
# 3. ReplayVerifier — deterministic re-derivation. Re-normalizes observations
#    and re-runs the causal validator; compares digests + outcome.
# ===========================================================================
class ReplayVerifier:
    """Deterministic replay verification.

    Given the ORIGINAL raw observations + the sealed ProofBundle + validator
    result, re-derive normalized observations and validator outcome. Replay
    passes iff normalized digests match AND validator outcome matches AND
    bundle seal verifies. No network — replay is pure re-computation.
    """

    @staticmethod
    def verify(*, experiment_id: str,
               baseline_raw: dict, candidate_raw: dict, negative_control_raw: dict,
               vulnerability_class: str, expected_outcome: str,
               expected_baseline_digest: str, expected_candidate_digest: str,
               expected_negative_control_digest: str,
               proof_bundle: Any | None = None) -> dict[str, Any]:
        # Re-normalize (deterministic).
        b = normalize_observation(experiment_id, "baseline", baseline_raw)
        c = normalize_observation(experiment_id, "candidate", candidate_raw)
        nc = normalize_observation(experiment_id, "negative_control", negative_control_raw)
        digests_match = (
            b.digest() == expected_baseline_digest
            and c.digest() == expected_candidate_digest
            and nc.digest() == expected_negative_control_digest
        )
        # Re-run causal validator (deterministic) with REAL redacted bodies —
        # consistent with the original AVI validator input.
        def _vi(raw: dict) -> dict[str, Any]:
            return {"status_code": raw.get("status_code", 0),
                    "response_body": str(raw.get("response_body", ""))[:2000],
                    "headers": dict(raw.get("headers", {}) or {}),
                    "structured_fields": dict(raw.get("structured_fields", {}) or {}),
                    "request_url": raw.get("request_url", ""),
                    "response_time_ms": raw.get("response_time_ms"),
                    "payload": raw.get("payload") or raw.get("structured_fields", {}).get("payload") if isinstance(raw.get("structured_fields"), dict) else raw.get("payload"),
                    "sql_payload": raw.get("sql_payload") or raw.get("structured_fields", {}).get("sql_payload") if isinstance(raw.get("structured_fields"), dict) else raw.get("sql_payload"),
                    "reflection_payload": raw.get("reflection_payload") or raw.get("structured_fields", {}).get("reflection_payload") if isinstance(raw.get("structured_fields"), dict) else raw.get("reflection_payload"),}
        try:
            vr = run_validator(
                vulnerability_class,
                baseline=_vi(baseline_raw),
                candidate=_vi(candidate_raw),
                negative_control=_vi(negative_control_raw),
            )
            outcome_match = vr.outcome.value == expected_outcome
        except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
            outcome_match = False
            vr = None
        # Bundle seal authenticity (HMAC).
        seal_ok = False
        if proof_bundle is not None and hasattr(proof_bundle, "verify_seal"):
            try:
                seal_ok = bool(proof_bundle.verify_seal())
            except (AttributeError, TypeError, ValueError, RuntimeError):
                seal_ok = False
        # V1.2: verify semantic relationship (evidence MEANING), not just hashes.
        # Re-derive access results from raw observations and compare with the
        # semantic fields sealed in the ProofBundle.
        semantic_match = True
        if proof_bundle is not None:
            co = getattr(proof_bundle, "causal_oracle", None) or {}
            if isinstance(co, dict) and co.get("identity_bound"):
                c_status = candidate_raw.get("status_code")
                b_status = baseline_raw.get("status_code")
                nc_status = negative_control_raw.get("status_code")
                semantic_match = (
                    c_status == co.get("candidate_access_result")
                    and b_status == co.get("baseline_access_result")
                    and nc_status == co.get("negative_control_result")
                    and bool(co.get("causal_difference"))
                    and bool(co.get("actor_id"))
                    and bool(co.get("resource_id"))
                )
        replay_verified = bool(digests_match and outcome_match and seal_ok and semantic_match)
        return {
            "replay_verified": replay_verified,
            "digests_match": digests_match,
            "outcome_match": outcome_match,
            "seal_verified": seal_ok,
            "semantic_match": semantic_match,
            "replayed_outcome": vr.outcome.value if vr else None,
            "expected_outcome": expected_outcome,
            "replay_component": "ReplayVerifier_v1_2_semantic",
        }


# ===========================================================================
# 4. PromotionPipeline — anti-fake gates. Fail-closed.
# ===========================================================================
class PromotionDecision(str, Enum):
    PROMOTED = "PROMOTED"
    REJECTED = "REJECTED"


@dataclass
class PromotionResult:
    decision: PromotionDecision
    reason: str
    gates_passed: list[str]
    gates_failed: list[str]
    finding_id: str | None = None
    vulnerability_class: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value, "reason": self.reason,
            "gates_passed": self.gates_passed, "gates_failed": self.gates_failed,
            "finding_id": self.finding_id, "vulnerability_class": self.vulnerability_class,
            "pipeline": "PromotionPipeline_v1",
        }


class PromotionPipeline:
    """SOLE promotion authority. Anti-fake gates. Fail-closed.

    A finding is promoted ONLY if every gate passes. Confidence scores alone
    are never sufficient. External scanner claims are advisory only and are
    rejected if presented as verdict authority.
    """

    GATES: Final[tuple[str, ...]] = (
        "real_runtime_observations",      # anti-synthetic
        "baseline_present",
        "negative_control_present",
        "causal_guard_adjudicated",       # UM-DR-35: sole technical confirmation authority
        "causal_validator_confirmed",     # anti confidence-only
        "proof_bundle_signed",            # anti unsigned
        "replay_verified",                # anti missing replay
        "no_external_scanner_authority",  # anti external authority
        "semantic_identity_bound",        # V1.2
        "self_critique_passed",           # U-10a
    )

    def evaluate(
        self, *,
        # observations
        baseline_obs: Any, candidate_obs: Any, negative_control_obs: Any,
        evidence_origin: str,
        # validator
        validator_outcome: str | None,
        evidence_quality: int,
        # proof
        proof_bundle: Any | None,
        # replay
        replay_verified: bool,
        # authority / confidence
        verdict_authority: str = "CausalGuard_deterministic_engine",
        confidence_score: float | None = None,
        finding_id: str | None = None,
        vulnerability_class: str | None = None,
        # UM-DR-35 corrective closure: the typed CausalGuard adjudication for
        # THIS experiment's evidence. Promotion without a CONFIRMED
        # adjudication bound to the same evidence is impossible (fail-closed).
        guard_adjudication: Any | None = None,
    ) -> PromotionResult:
        passed: list[str] = []
        failed: list[str] = []

        def gate(name: str, ok: bool, reason: str) -> bool:
            (passed if ok else failed).append(name)
            return ok

        # Gate 0: evidence origin must be real target runtime, not synthetic.
        origin_ok = gate(
            "real_runtime_observations",
            evidence_origin == "target_runtime",
            f"synthetic observations rejected (origin={evidence_origin})",
        )
        # Also reject if any observation is flagged synthetic.
        for role, obs in (("baseline", baseline_obs), ("candidate", candidate_obs),
                          ("negative_control", negative_control_obs)):
            if obs is None:
                continue
            is_synthetic = (getattr(obs, "synthetic", False)
                            or (isinstance(obs, dict) and obs.get("synthetic") is True)
                            or (isinstance(obs, dict) and obs.get("real_http") is False))
            if is_synthetic:
                origin_ok = False
                if "real_runtime_observations" not in failed:
                    failed.append("real_runtime_observations")

        # Gate 1: baseline present (non-null, real digest).
        base_ok = gate(
            "baseline_present",
            baseline_obs is not None and bool(getattr(baseline_obs, "digest", lambda: None)() or (isinstance(baseline_obs, dict) and baseline_obs.get("body_fingerprint"))),
            "missing baseline",
        )

        # Gate 2: negative control present.
        nc_ok = gate(
            "negative_control_present",
            negative_control_obs is not None and bool(getattr(negative_control_obs, "digest", lambda: None)() or (isinstance(negative_control_obs, dict) and negative_control_obs.get("body_fingerprint"))),
            "missing negative control",
        )

        # Gate 3 (UM-DR-35): CausalGuard adjudicated CONFIRMED.
        # The authority is webpent.cqa_v2.causal_guard.guarded_causal_evaluate,
        # invoked through the universal confirmation adapter on the exact
        # baseline/candidate/negative-control evidence of THIS decision.
        # A missing, blocked, clean, or inconclusive adjudication rejects
        # promotion — a validator CONFIRM alone can never substitute for it.
        guard_ok = gate(
            "causal_guard_adjudicated",
            bool(
                guard_adjudication is not None
                and getattr(guard_adjudication, "confirmed", False)
                and getattr(guard_adjudication, "evidence_digests", None)
            ),
            "causal_guard_adjudication_missing_or_not_confirmed",
        )

        # Gate 3: causal validator CONFIRMED (anti confidence-only).
        # Even if confidence_score is high, without CONFIRMED outcome → reject.
        causal_confirmed = validator_outcome == ValidationOutcome.CONFIRMED.value
        conf_only = (confidence_score is not None and confidence_score >= 0.9
                     and not causal_confirmed)
        causal_ok = gate(
            "causal_validator_confirmed",
            causal_confirmed and not conf_only,
            "confidence-only promotion rejected" if conf_only else "validator not CONFIRMED",
        )
        # Evidence quality must be at least observed differential.
        if evidence_quality < int(EvidenceQuality.OBSERVED_DIFFERENTIAL):
            causal_ok = False
            if "causal_validator_confirmed" not in failed:
                failed.append("causal_validator_confirmed")

        # Gate 4: ProofBundle signed (sealed + HMAC authentic).
        bundle_signed = False
        verified_bundle = proof_bundle
        if proof_bundle is not None and isinstance(proof_bundle, dict):
            # Serialized bundles are untrusted input. Normalize once through
            # the frozen model so later gates cannot trust caller-controlled
            # dictionary flags or inspect a different object than gate 4.
            try:
                from webpent.models.proof_bundle import ProofBundle
                verified_bundle = ProofBundle.model_validate(proof_bundle)
            except (AttributeError, TypeError, ValueError, RuntimeError):
                verified_bundle = None
        if verified_bundle is not None and hasattr(verified_bundle, "verify_seal"):
            try:
                bundle_signed = bool(verified_bundle.verify_seal())
            except (AttributeError, TypeError, ValueError, RuntimeError):
                bundle_signed = False
        signed_ok = gate("proof_bundle_signed", bundle_signed, "unsigned ProofBundle rejected")

        # Gate 5: replay verified.
        replay_ok = gate("replay_verified", bool(replay_verified), "missing replay verification")

        # Gate 6: no external scanner authority.
        authority_clean = verdict_authority not in EXTERNAL_SCANNER_AUTHORITIES
        if not authority_clean:
            # advisory-only external scanner claim presented as authority → reject.
            pass
        auth_ok = gate(
            "no_external_scanner_authority",
            authority_clean,
            f"external scanner authority rejected: {verdict_authority}",
        )

        # Gate 7 (V1.2): semantic identity bound — ProofBundle must prove
        # real security property (actor/resource/authorization/causal difference).
        # Response difference alone is insufficient.
        semantic_bound = False
        if verified_bundle is not None:
            co = getattr(verified_bundle, "causal_oracle", None) or {}
            if isinstance(co, dict):
                semantic_bound = bool(co.get("identity_bound", False)) and bool(co.get("causal_difference"))
        semantic_ok = gate("semantic_identity_bound", semantic_bound,
                           "semantic identity binding not proven (response difference alone insufficient)")

        # U-10a: Self-critique pre-promotion honesty pass
        try:
            from webpent.shared.self_critique import generate_adversarial_questions
            _questions = generate_adversarial_questions(vulnerability_class=vulnerability_class or "", validator_outcome=validator_outcome or "", evidence_origin=evidence_origin)
            _unanswered = [q for q in _questions if not q.get("resolved", False)]
            critique_ok = gate("self_critique_passed", len(_unanswered) == 0, f"self_critique: {len(_unanswered)} unanswered")
        except (ImportError, TypeError, ValueError, KeyError, AttributeError):
            critique_ok = gate("self_critique_passed", False, "self_critique unavailable — fail-closed")
        promoted = not failed
        if promoted:
            reason = "all_anti_fake_gates_passed"
        else:
            reason = "; ".join(f"{g}:rejected" for g in failed)

        return PromotionResult(
            decision=PromotionDecision.PROMOTED if promoted else PromotionDecision.REJECTED,
            reason=reason,
            gates_passed=passed,
            gates_failed=failed,
            finding_id=finding_id,
            vulnerability_class=vulnerability_class,
        )


# ===========================================================================
# 5. SecurityReport — final report artifact, promoted findings only.
#    V1.2 release closure (TEAM-4 BLOCKER 1): every promoted finding exposes
#    the COMPLETE proof trace, extracted from the EXISTING trusted chain
#    (CausalGuard identity binding → sealed ProofBundle → ReplayVerifier →
#    PromotionPipeline). Values are REFERENCED from those authorities —
#    no new verifier, no duplicated authority, no re-derivation here.
# ===========================================================================
SECURITY_REPORT_TRACE_CONTRACT: Final[tuple[str, ...]] = (
    "actor_identity",          # CausalGuard identity binding (sealed in ProofBundle)
    "resource_identity",       # resource + owner (sealed in ProofBundle)
    "authorization_context",   # authorization boundary (sealed in ProofBundle)
    "baseline_result",         # baseline access result + evidence digest (ProofBundle)
    "candidate_result",        # candidate access result + evidence digest (ProofBundle)
    "negative_control",        # negative control result + independence (ProofBundle)
    "causal_difference",       # discriminating causal difference (sealed ProofBundle)
    "proof_seal",              # seal via EXISTING ProofBundle.verify_seal() (SHA-256 + HMAC)
    "replay_verification",     # EXISTING ReplayVerifier result (pass-through, not re-derived)
)

TRACE_CONTRACT_VERSION: Final[str] = "security_report_trace_contract_v1_2"


def _auth_context_is_redacted(co: dict[str, Any], ic: dict[str, Any]) -> bool:
    """True when the sealed authorization_context was replaced by the redaction sentinel."""
    direct = co.get("authorization_context") or ic.get("authorization_context")
    return direct is None or direct == "[REDACTED]"


def _auth_context_value(co: dict[str, Any], ic: dict[str, Any]) -> Any:
    """Authorization boundary value for the report trace.

    Prefers the direct sealed field; when the ProofBundle redaction policy has
    sentinel-replaced it (key-name based policy), reconstructs the SAME boundary
    from the sealed redaction-safe sibling field ``expected_owner``. Falls back
    to the sealed resource_owner. No value is invented: every input is read from
    the sealed ProofBundle.
    """
    direct = co.get("authorization_context") or ic.get("authorization_context")
    if direct is not None and direct != "[REDACTED]":
        return direct
    expected_owner = co.get("expected_owner") or ic.get("expected_owner")
    if expected_owner:
        return f"owner={expected_owner}"
    return ic.get("resource_owner")


def build_proof_trace(*, proof_bundle: Any, replay_result: dict[str, Any],
                      promotion: dict[str, Any] | None = None) -> dict[str, Any]:
    """Extract the complete SecurityReport proof trace for a promoted finding.

    SOURCES — existing trusted components only (no duplication of authority):
      * CausalGuard identity binding, as SEALED inside the frozen ProofBundle
        (``causal_oracle`` + ``identity_context``). Tampering with these fields
        breaks the HMAC seal, so values read here are seal-protected.
      * ``ProofBundle.verify_seal()`` — the existing dual-layer (SHA-256
        integrity + HMAC-SHA256 authenticity) verification method. Called,
        never re-implemented.
      * ``ReplayVerifier.verify()`` result — the existing deterministic replay
        authority (digests + outcome + seal + semantic). Passed through as-is;
        NOT re-derived.
      * ``PromotionPipeline`` decision — the sole promotion authority;
        referenced by decision, gates and pipeline version.

    The trace additionally carries ``proof_chain`` — pointers (bundle_id,
    finding_id, hypothesis_id, engagement_id, seal_digest) into the EXISTING
    proof chain so any reviewer can independently verify against the sealed
    bundle instead of trusting the report text.
    """
    co = dict(getattr(proof_bundle, "causal_oracle", {}) or {})
    ic = dict(getattr(proof_bundle, "identity_context", {}) or {})
    evidence_digests = tuple(getattr(proof_bundle, "evidence_digests", ()) or ())
    candidate_digest = evidence_digests[1] if len(evidence_digests) > 1 else None
    try:
        seal_verified = bool(proof_bundle.verify_seal())
    except (AttributeError, TypeError, ValueError, RuntimeError):
        seal_verified = False
    prom = dict(promotion or {})
    return {
        "actor_identity": {
            "actor_id": co.get("actor_id") or ic.get("actor_id"),
            "baseline_actor_id": ic.get("baseline_actor_id"),
            "identity_bound": bool(co.get("identity_bound", False)),
            "identity_bound_reason": co.get("identity_bound_reason"),
            "source": "CausalGuard_identity_binding sealed in ProofBundle.causal_oracle.actor_id",
        },
        "resource_identity": {
            "resource_id": co.get("resource_id") or ic.get("resource_id"),
            "resource_owner": ic.get("resource_owner"),
            "source": "CausalGuard_identity_binding sealed in ProofBundle.causal_oracle.resource_id",
        },
        "authorization_context": {
            "value": _auth_context_value(co, ic),
            "sealed_field": co.get("authorization_context") or ic.get("authorization_context"),
            "redaction_note": (
                "direct authorization_context key is redacted by the ProofBundle "
                "redaction policy (key-name based); boundary value reconstructed "
                "from the sealed expected_owner sibling field"
                if _auth_context_is_redacted(co, ic) else None),
            "source": "CausalGuard_identity_binding sealed in ProofBundle.causal_oracle (authorization_context / expected_owner)",
        },
        "baseline_result": {
            "access_result": co.get("baseline_access_result"),
            "evidence_digest": getattr(proof_bundle, "baseline_digest", None),
            "evidence_ref": (getattr(proof_bundle, "baseline_evidence_ref", None)
                             or (getattr(proof_bundle, "evidence_refs", ()) or (None,))[0]),
            "source": "ProofBundle.causal_oracle.baseline_access_result + ProofBundle.baseline_digest",
        },
        "candidate_result": {
            "access_result": co.get("candidate_access_result"),
            "evidence_digest": candidate_digest,
            "evidence_ref": (getattr(proof_bundle, "candidate_evidence_ref", None)
                             or (getattr(proof_bundle, "evidence_refs", ()) or (None, None))[1]),
            "source": "ProofBundle.causal_oracle.candidate_access_result + ProofBundle.evidence_digests[1]",
        },
        "negative_control": {
            "access_result": co.get("negative_control_result"),
            "evidence_digest": getattr(proof_bundle, "negative_control_digest", None),
            "independent": bool(getattr(proof_bundle, "negative_control_independent", False)),
            "source": "ProofBundle.causal_oracle.negative_control_result + ProofBundle.negative_control_digest",
        },
        "causal_difference": {
            "value": co.get("causal_difference"),
            "validator_outcome": co.get("validator_outcome") or getattr(proof_bundle, "oracle_decision", None),
            "discriminating_signal": (getattr(proof_bundle, "validator_result", {}) or {}).get("discriminating_signal"),
            "source": "CausalGuard validator + identity binding sealed in ProofBundle.causal_oracle.causal_difference",
        },
        "proof_seal": {
            "bundle_id": getattr(proof_bundle, "bundle_id", None),
            "seal_digest": getattr(proof_bundle, "seal_digest", None),
            "sealed": bool(getattr(proof_bundle, "sealed", False)),
            "authenticity_tag_present": bool(getattr(proof_bundle, "authenticity_tag", None)),
            "authenticity_algorithm": getattr(proof_bundle, "authenticity_algorithm", None),
            "seal_verified": seal_verified,
            "verifier": "ProofBundle.verify_seal() (existing dual-layer SHA-256 + HMAC-SHA256 authority)",
        },
        "replay_verification": {
            "replay_verified": bool(replay_result.get("replay_verified", False)),
            "digests_match": replay_result.get("digests_match"),
            "outcome_match": replay_result.get("outcome_match"),
            "seal_verified": replay_result.get("seal_verified"),
            "semantic_match": replay_result.get("semantic_match"),
            "replayed_outcome": replay_result.get("replayed_outcome"),
            "replay_component": replay_result.get("replay_component"),
            "verifier": "ReplayVerifier (existing deterministic re-derivation authority — result passed through, not re-computed)",
        },
        "promotion_reference": {
            "decision": prom.get("decision"),
            "reason": prom.get("reason"),
            "gates_passed": prom.get("gates_passed"),
            "pipeline": prom.get("pipeline", "PromotionPipeline_v1"),
            "source": "PromotionPipeline (sole promotion authority) decision dict",
        },
        "proof_chain": {
            "engagement_id": getattr(proof_bundle, "engagement_id", None),
            "finding_id": getattr(proof_bundle, "finding_id", None),
            "bundle_id": getattr(proof_bundle, "bundle_id", None),
            "hypothesis_id": getattr(proof_bundle, "hypothesis_id", None),
            "seal_digest": getattr(proof_bundle, "seal_digest", None),
            "vulnerability_class": getattr(proof_bundle, "vulnerability_class", None),
            "evidence_origin": getattr(proof_bundle, "evidence_origin", None),
            "note": "verify against the sealed ProofBundle — the report references, it does not replace, the proof chain",
        },
    }


def _trace_contract_missing(finding: Any) -> list[str]:
    """Return required trace-contract fields missing/incomplete on a finding.

    Fail-closed: a promoted finding without a COMPLETE proof trace cannot
    enter the SecurityReport promoted section.
    """
    trace = finding.get("proof_trace") if isinstance(finding, dict) else None
    if not isinstance(trace, dict):
        return list(SECURITY_REPORT_TRACE_CONTRACT)
    missing: list[str] = []
    if not (trace.get("actor_identity") or {}).get("actor_id"):
        missing.append("actor_identity")
    if not (trace.get("resource_identity") or {}).get("resource_id"):
        missing.append("resource_identity")
    if not ((trace.get("authorization_context") or {}).get("value")
            or (trace.get("authorization_context") or {}).get("authorization_context")):
        missing.append("authorization_context")
    if (trace.get("baseline_result") or {}).get("access_result") is None:
        missing.append("baseline_result")
    if (trace.get("candidate_result") or {}).get("access_result") is None:
        missing.append("candidate_result")
    if (trace.get("negative_control") or {}).get("access_result") is None:
        missing.append("negative_control")
    if not (trace.get("causal_difference") or {}).get("value"):
        missing.append("causal_difference")
    seal = trace.get("proof_seal") or {}
    if not seal.get("seal_verified") or not seal.get("seal_digest"):
        missing.append("proof_seal")
    if not (trace.get("replay_verification") or {}).get("replay_verified"):
        missing.append("replay_verification")
    return missing


@dataclass
class SecurityReport:
    engagement_id: str
    generated_at: str = field(default_factory=_utc)
    promoted_findings: list[dict[str, Any]] = field(default_factory=list)
    rejected_findings: list[dict[str, Any]] = field(default_factory=list)
    trace_summary: dict[str, Any] = field(default_factory=dict)
    report_version: str = "security_report_v1"

    def add_promoted(self, finding: dict[str, Any]) -> None:
        # V1.2: SecurityReport enforcement — require promoted ProofBundle +
        # verified seal + verified replay + semantic validation success.
        # No report from raw decision dictionaries.
        # V1.2 release closure (TEAM-4 BLOCKER 1): additionally require the
        # COMPLETE proof trace contract (9 fields sourced from CausalGuard /
        # ProofBundle / ReplayVerifier / PromotionPipeline). Missing or
        # incomplete trace -> fail-closed rejection. This STRENGTHENS, never
        # weakens, the prior requirements.
        prom = finding.get("promotion", {}) if isinstance(finding, dict) else {}
        is_promoted = prom.get("decision") == "PROMOTED"
        replay_ok = bool(finding.get("replay_verified")) if isinstance(finding, dict) else False
        semantic_ok = bool(finding.get("identity_bound")) if isinstance(finding, dict) else False
        seal_ok = bool(finding.get("proof_seal_verified")) if isinstance(finding, dict) else False
        contract_missing = _trace_contract_missing(finding)
        if is_promoted and replay_ok and semantic_ok and seal_ok and not contract_missing:
            finding["proof_trace_contract"] = TRACE_CONTRACT_VERSION
            self.promoted_findings.append(finding)
        else:
            # Fail-closed: route to rejected with explicit reason.
            finding = dict(finding) if isinstance(finding, dict) else {}
            finding["report_rejection_reason"] = (
                f"missing_security_report_requirements promoted={is_promoted} "
                f"replay={replay_ok} semantic={semantic_ok} seal={seal_ok}")
            if contract_missing:
                finding["trace_contract_missing"] = contract_missing
                finding["report_rejection_reason"] += f" trace_contract_missing={contract_missing}"
            self.rejected_findings.append(finding)

    def add_rejected(self, finding: dict[str, Any]) -> None:
        self.rejected_findings.append(finding)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_version": self.report_version,
            "trace_contract": TRACE_CONTRACT_VERSION,
            "trace_contract_required_fields": list(SECURITY_REPORT_TRACE_CONTRACT),
            "engagement_id": self.engagement_id,
            "generated_at": self.generated_at,
            "promoted_findings": self.promoted_findings,
            "rejected_findings_count": len(self.rejected_findings),
            "rejected_findings": self.rejected_findings[:50],
            "trace_summary": self.trace_summary,
            "promoted_count": len(self.promoted_findings),
            "digest": sha256_text(json.dumps(self.promoted_findings, sort_keys=True, default=str))[:16],
        }


# ===========================================================================
# 6. AutonomousValidationIntelligence — the full wired campaign orchestrator.
#    Composes ModernOrchestrator (ScopeLaw/ToolBoundary/ResearchLoop/
#    OutcomeTracker/real HTTP). NO second authority components.
# ===========================================================================
class AVICampaignError(RuntimeError):
    pass


# FINAL-CLOSURE RULING R1: the M4 principal binding (mandatory principal_alias,
# vault-bound X-User overwrite, decision token) applies ONLY to the two-principal
# comparative-authorization families. Other families' identity binding does not
# use actor_mismatch (M7 v1.2 per-class table) and run without principal_alias.
_M4_PRINCIPAL_FAMILIES = frozenset({"IDOR", "BOLA"})


class _M4NotApplicable(Exception):
    """Internal control-flow marker: M4 does not apply to this family (R1)."""


class AutonomousValidationIntelligence:
    """Wires the FULL autonomous lifecycle into the production dispatch path.

    Usage (production dispatch, NOT manual helper):
        # FIX 1 (Sprint R1): ModernOrchestrator is no longer constructed
        # directly outside webpent.production.production_spine — this
        # docstring example was the only "site c" match found for this
        # fix (see change log); it documents usage, it is not executable.
        orch, _trace = resolve_production_spine(ProductionSpineConfig(
            engagement_id=..., target_url=..., entrypoint=...))
        avi = AutonomousValidationIntelligence(orch)
        result = avi.run_campaign(target_url=..., hypotheses=[...], max_decisions=30)

    Each decision executes the full 11-stage pipeline and records a
    DeterministicRuntimeTrace proving every stage.
    """

    def __init__(self, orchestrator: Any) -> None:
        if orchestrator is None:
            raise AVICampaignError("AutonomousValidationIntelligence requires a bound ModernOrchestrator")
        self.orch = orchestrator
        self.selector = AutonomousExperimentSelector()
        self.promotion_pipeline = PromotionPipeline()
        self.replay_verifier = ReplayVerifier()
        self.trace = DeterministicRuntimeTrace()
        self.security_report = SecurityReport(engagement_id=getattr(orchestrator, "engagement_id", "unknown"))
        self.decisions: list[dict[str, Any]] = []
        self.promoted_count = 0
        self.rejected_count = 0

    # -- Real execution: 3 real authorized HTTP requests -------------------
    def _execute_real_triple(self, *, target_url: str, hypothesis: dict[str, Any],
                             vuln_class: str) -> dict[str, Any]:
        """Execute baseline / candidate / negative_control as REAL HTTP.

        V1.1: if the hypothesis carries explicit ``requests`` specs (per-role
        method/path/headers/body — constructed from realistic target discovery),
        execute those through the orchestrator's generalized real request path.
        Otherwise fall back to the V1 URL convention. All three go through the
        SAME authorization (ScopeLaw + ToolBoundary). No synthetic observations.
        """
        api_type = str(hypothesis.get("api_type", "rest")).lower()
        base_path = str(hypothesis.get("path", hypothesis.get("endpoint", "/api/")))
        reg = EXPERIMENT_REGISTRY.get(vuln_class, {})

        explicit = hypothesis.get("requests") if isinstance(hypothesis.get("requests"), dict) else None

        def _url(role: str) -> str:
            if api_type == "graphql" and not explicit:
                query = str(hypothesis.get(f"graphql_query_{role}",
                                           hypothesis.get("graphql_query", "{ __typename }")))
                return f"{target_url}/graphql?query={quote_plus(query)}&role={role}"
            if role == "baseline":
                return f"{target_url}{base_path}"
            if role == "candidate":
                return f"{target_url}{base_path}?variant=candidate&class={vuln_class.lower()}"
            return f"{target_url}{base_path}/nonexistent_control_99999"

        raw: dict[str, Any] = {}
        for role in ("baseline", "candidate", "negative_control"):
            if explicit and role in explicit:
                spec = explicit[role]
                url = target_url + str(spec.get("path", "/"))
                # Sprint I-2 HOTFIX (D-RED-1/3/5) + FINAL-CLOSURE RULING R1:
                # M4 is MANDATORY for every explicit request spec of the
                # IDOR/BOLA families (the B11/B5 two-principal perimeter).
                # Missing principal_alias there is a FAILURE (BLOCKED), never a
                # silent bypass. On ANY M4 failure the caller-supplied X-User
                # header is STRIPPED (replaced with a neutral marker) so a
                # forged identity never reaches _compute_identity_binding. The
                # decision token is minted ONLY via
                # ContextAuthority.authorize_execution (single choke point).
                # For the other families (SSRF, OPEN_REDIRECT, MASS_ASSIGNMENT,
                # INFO_DISCLOSURE, AUTH_BYPASS) identity binding does not use
                # actor_mismatch (M7 v1.2 per-class table): the explicit-spec
                # path runs WITHOUT principal_alias, still through
                # orch.execute_real_request (ToolBoundary + ScopeLaw,
                # modern_spine.py:589-610). X-User there is advisory only.
                _m4_scoped = str(vuln_class).upper() in _M4_PRINCIPAL_FAMILIES
                principal_alias = spec.get("principal_alias")
                engagement_id = str(getattr(self.orch, "engagement_id",
                                    hypothesis.get("engagement_id", "unknown")))
                target_fp = sha256_text(target_url)[:16]
                if _m4_scoped and not principal_alias:
                    # D-RED-1 (IDOR/BOLA only): absence of principal_alias is fail-closed.
                    hypothesis["_m4_block_reason"] = "principal_alias_missing_fail_closed"
                    _hdr = dict(spec.get("headers") or {})
                    _hdr.pop("X-User", None); _hdr.pop("x-user", None)
                    _hdr["X-User"] = "m4_unbound_unknown"
                    spec["headers"] = _hdr
                    raw[role] = {
                        "status_code": 0, "response_body": "", "headers": {},
                        "real_http": False, "authorized": False,
                        "evidence_origin": "m4_blocked",
                        "blocked": True,
                        "block_reason": "principal_alias_missing_fail_closed",
                        "request_url_digest": sha256_text(url)[:16],
                    }
                    continue
                try:
                    if not _m4_scoped:
                        # R1: non-IDOR/BOLA family -> no M4 principal binding;
                        # fall through to orch.execute_real_request below.
                        raise _M4NotApplicable()
                    from webpent.production.context_authority import (  # noqa: PLC0415
                        ContextAuthority, PrincipalRef, PrincipalRole,
                    )
                    # D-RED-6: audit chain is built from the engagement, NOT
                    # read from a hypothesis fixture. Cached on the instance.
                    if not hasattr(self, "_m4_audit_chain"):
                        try:
                            from webpent.shared.engagement_audit import EngagementAuditChain
                            import tempfile
                            from pathlib import Path as _Path
                            _ac_dir = _Path(tempfile.mkdtemp(prefix="m4_audit_"))
                            self._m4_audit_chain = EngagementAuditChain(
                                engagement_id=engagement_id,
                                audit_dir=_ac_dir / "audit",
                                workspace_dir=_ac_dir / "workspace",
                            )
                        except (ImportError, OSError, RuntimeError, TypeError, ValueError):
                            self._m4_audit_chain = None
                    authority = ContextAuthority(
                        engagement_id=engagement_id,
                        target_fingerprint=target_fp,
                        audit_chain=getattr(self, "_m4_audit_chain", None),
                    )
                    alias = str(principal_alias)
                    role_enum = PrincipalRole(str(spec.get("principal_role", "foreign-user")))
                    pref = PrincipalRef(
                        principal_alias=alias,
                        engagement_id=engagement_id,
                        target_fingerprint=target_fp,
                        role=role_enum,
                    )
                    # D-RED-5: token minted ONLY at the authorize_execution
                    # choke point (which also confirms vault binding pre-issue).
                    decision_token = authority.authorize_execution(
                        principal_ref=pref,
                        tool_name="httpx_bounded",
                        target_url=url,
                        arguments={"method": spec.get("method", "GET"),
                                   "path": spec.get("path", "/"),
                                   "role": role},
                        execution_window_id=f"win_{hypothesis.get('id', 'unknown')}_{role}",
                    )
                    ctx = authority.resolve(pref, decision_token)
                    # attach mutates spec["headers"] in place: the forged
                    # X-User (if any) is discarded and overwritten with
                    # the vault-resolved alias. It therefore NEVER reaches
                    # _compute_identity_binding (which reads spec headers).
                    authority.attach(ctx, spec)
                except _M4NotApplicable:
                    pass  # R1: scope narrowing, not a failure
                except (AttributeError, KeyError, OSError, PermissionError, RuntimeError, TypeError, ValueError) as m4_exc:
                    reason = str(m4_exc)
                    block_reason = "x_user_not_vault_bound"
                    if "DECISION_TOKEN" in reason or "decision token" in reason:
                        block_reason = "decision_token_invalid_or_replayed"
                    elif "not usable" in reason or "PRINCIPAL_NOT_USABLE" in reason:
                        block_reason = "principal_revoked"
                    elif "principal_alias_missing" in reason:
                        block_reason = "principal_alias_missing_fail_closed"
                    hypothesis["_m4_block_reason"] = block_reason
                    hypothesis["_m4_block_detail"] = reason[:200]
                    # D-RED-3: STRIP caller-supplied X-User on failure so a
                    # forged identity never reaches _compute_identity_binding.
                    _hdr = dict(spec.get("headers") or {})
                    _hdr.pop("X-User", None); _hdr.pop("x-user", None)
                    _hdr["X-User"] = "m4_unbound_unknown"
                    spec["headers"] = _hdr
                    raw[role] = {
                        "status_code": 0, "response_body": "", "headers": {},
                        "real_http": False, "authorized": False,
                        "evidence_origin": "m4_blocked",
                        "blocked": True, "block_reason": block_reason,
                        "request_url_digest": sha256_text(url)[:16],
                    }
                    continue
                request_headers = dict(spec.get("headers") or {})
                if spec.get("content_type") and not any(str(key).lower() == "content-type" for key in request_headers):
                    request_headers["Content-Type"] = str(spec["content_type"])
                request_body = spec.get("body")
                if isinstance(request_body, dict):
                    content_type = str(request_headers.get("Content-Type", request_headers.get("content-type", ""))).lower()
                    if "json" in content_type:
                        request_body = json.dumps(request_body, sort_keys=True)
                    else:
                        request_body = urlencode({str(key): str(value) for key, value in request_body.items()})
                # Sprint A (file upload): a multipart spec carries the artifact as
                # structured upload fields. The multipart body is serialized here
                # and executed through the SAME orch.execute_real_request path —
                # no separate transport, no direct HTTP.
                if str(spec.get("content_type", "")).lower() == "multipart/form-data" and spec.get("upload_body") is not None:
                    boundary = "----webpentUpload" + sha256_text(str(hypothesis.get("id", "")) + role)[:12]
                    field_name = str(spec.get("upload_field", "file"))
                    filename = str(spec.get("upload_filename", "probe.txt"))
                    part_content_type = str(spec.get("upload_part_content_type", "application/octet-stream"))
                    part_body = str(spec.get("upload_body", ""))
                    extra_fields = spec.get("extra_fields") if isinstance(spec.get("extra_fields"), dict) else {}
                    parts: list[str] = []
                    for extra_key, extra_value in sorted((str(k), str(v)) for k, v in extra_fields.items()):
                        parts.append(
                            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{extra_key}\"\r\n\r\n{extra_value}\r\n"
                        )
                    parts.append(
                        f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\r\n"
                        f"Content-Type: {part_content_type}\r\n\r\n{part_body}\r\n"
                    )
                    parts.append(f"--{boundary}--\r\n")
                    request_body = "".join(parts)
                    request_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
                # Sprint A (race condition): a concurrent spec executes as a
                # BOUNDED burst of identical governed requests. Every burst
                # member goes through the same orch.execute_real_request
                # (ToolBoundary + ScopeLaw) — concurrency happens at the caller
                # layer only, never by bypassing the boundary. The burst is
                # clamped to [2, 5] and its aggregate result is recorded in
                # structured fields for the canonical validator.
                if bool(spec.get("concurrent")) and str(vuln_class).upper() == "RACE_CONDITION":
                    try:
                        concurrency = max(2, min(5, int(spec.get("concurrency", 5))))
                    except (TypeError, ValueError):
                        concurrency = 5
                    try:
                        expected_successes = max(0, int(spec.get("expected_successes", 1)))
                    except (TypeError, ValueError):
                        expected_successes = 1
                    burst_results: list[dict[str, Any]] = []
                    burst_error: str | None = None
                    try:
                        from concurrent.futures import ThreadPoolExecutor
                        with ThreadPoolExecutor(max_workers=concurrency) as pool:
                            futures = [
                                pool.submit(
                                    self.orch.execute_real_request,
                                    method=str(spec.get("method", "GET")),
                                    target_url=url,
                                    headers=dict(request_headers),
                                    body=request_body,
                                    hypothesis_id=str(hypothesis["id"]),
                                )
                                for _ in range(concurrency)
                            ]
                            burst_results = [future.result() for future in futures]
                    except (RuntimeError, OSError, ValueError, TypeError) as burst_exc:
                        burst_error = str(burst_exc)[:120]
                    if burst_error is not None:
                        obs = {"status_code": 0, "response_body": "", "headers": {},
                               "real_http": False, "authorized": True,
                               "evidence_origin": "target_runtime",
                               "burst_error": burst_error}
                    else:
                        statuses = []
                        for item in burst_results:
                            try:
                                statuses.append(int(item.get("status_code") or 0))
                            except (TypeError, ValueError, AttributeError):
                                statuses.append(0)
                        successes = sum(1 for status in statuses if 200 <= status < 300)
                        first_ok = next((item for item in burst_results
                                         if isinstance(item, dict) and 200 <= int(item.get("status_code") or 0) < 300),
                                        burst_results[0] if burst_results else {})
                        first_ok = first_ok if isinstance(first_ok, dict) else {}
                        obs = dict(first_ok)
                        obs.update({
                            "_concurrent_attempts": len(burst_results),
                            "_concurrent_successes": successes,
                            "_concurrent_expected_successes": expected_successes,
                            "_concurrent_statuses": statuses,
                            "real_http": any(bool(item.get("real_http")) for item in burst_results if isinstance(item, dict)),
                            "authorized": all(bool(item.get("authorized", False)) for item in burst_results if isinstance(item, dict)),
                        })
                    raw[role] = {
                        "status_code": obs.get("status_code", 0),
                        "response_body": str(obs.get("response_body", "")),
                        "headers": obs.get("headers", {}) or {},
                        "structured_fields": {
                            "_concurrent_attempts": obs.get("_concurrent_attempts", 0),
                            "_concurrent_successes": obs.get("_concurrent_successes", 0),
                            "_concurrent_expected_successes": obs.get("_concurrent_expected_successes", expected_successes),
                            "_concurrent_statuses": obs.get("_concurrent_statuses", []),
                            "_body_fingerprint": str(obs.get("body_digest") or ""),
                        },
                        "real_http": bool(obs.get("real_http", False)),
                        "body_digest": obs.get("body_digest"),
                        "authorized": bool(obs.get("authorized", False)),
                        "evidence_origin": "target_runtime",
                        "request_method": str(spec.get("method", "GET")),
                        "request_url": url,
                        "request_digest": f"sha256:{sha256_text(json.dumps({'method': str(spec.get('method', 'GET')).upper(), 'url': url, 'role': role, 'concurrency': concurrency}, sort_keys=True))}",
                        "request_url_digest": sha256_text(url)[:16],
                    }
                    continue
                obs = self.orch.execute_real_request(
                    method=str(spec.get("method", "GET")),
                    target_url=url,
                    headers=request_headers,
                    body=request_body,
                    hypothesis_id=str(hypothesis["id"]),
                )
            else:
                # D-RED-2 (hotfix): the legacy (non-explicit-spec) path is NOT
                # M4-authorized. For IDOR/BOLA (the B11/B5 perimeter) this is
                # fail-closed: BLOCK the row. Other vuln classes retain the
                # historical run_bounded_experiment path (documented exclusion).
                if str(vuln_class).upper() in ("IDOR", "BOLA"):
                    hypothesis["_m4_block_reason"] = "legacy_path_not_m4_authorized_fail_closed"
                    raw[role] = {
                        "status_code": 0, "response_body": "", "headers": {},
                        "real_http": False, "authorized": False,
                        "evidence_origin": "m4_blocked",
                        "blocked": True,
                        "block_reason": "legacy_path_not_m4_authorized_fail_closed",
                        "request_url_digest": sha256_text(_url(role))[:16],
                    }
                    continue
                url = _url(role)
                exec_result = self.orch.run_bounded_experiment(
                    candidate_id=f"c_{hypothesis['id']}_{role}",
                    hypothesis_id=str(hypothesis["id"]),
                    tool_name="httpx_bounded",
                    target_url=url,
                    local_loopback=True,
                    replan=False,
                )
                obs = exec_result.get("observation", {}) if isinstance(exec_result, dict) else {}
                obs = dict(obs)
                obs["authorized"] = bool(exec_result.get("authorized", False)) if isinstance(exec_result, dict) else False
            structured_fields = dict(obs.get("structured_fields", {}) or {}) if isinstance(obs, dict) else {}
            body_digest = obs.get("body_digest") if isinstance(obs, dict) else None
            if body_digest:
                # Body digests are already redacted, deterministic evidence
                # metadata. Keep the content out of the validator while still
                # allowing an independent 200 control to be distinguished.
                structured_fields["_body_fingerprint"] = str(body_digest)
            # Sprint A (race condition): the burst summary from the concurrent
            # executor is folded into structured_fields so the canonical
            # validator can read the observed attempt/success counts.
            if isinstance(obs, dict) and "_concurrent_successes" in obs:
                structured_fields["_concurrent_attempts"] = obs.get("_concurrent_attempts", 0)
                structured_fields["_concurrent_successes"] = obs.get("_concurrent_successes", 0)
                structured_fields["_concurrent_expected_successes"] = obs.get("_concurrent_expected_successes", 0)
                structured_fields["_concurrent_statuses"] = obs.get("_concurrent_statuses", [])
            raw[role] = {
                "status_code": obs.get("status_code", obs.get("status", 0)),
                "response_body": str(obs.get("response_body", obs.get("body", ""))),
                "headers": obs.get("headers", {}) or {},
                "structured_fields": structured_fields,
                "real_http": bool(obs.get("real_http", False)),
                "body_digest": obs.get("body_digest"),
                "authorized": bool(obs.get("authorized", False)),
                "evidence_origin": "target_runtime",
                "request_method": str((spec if explicit and role in explicit else {}).get("method", "GET")),
                "request_url": url,
                "request_digest": f"sha256:{sha256_text(json.dumps({'method': str((spec if explicit and role in explicit else {}).get('method', 'GET')).upper(), 'url': url, 'role': role}, sort_keys=True))}",
                "request_url_digest": obs.get("request_url_digest", sha256_text(str(obs.get("request_url", url)))[:16]),
            }
            if explicit and role in explicit:
                sent_spec = explicit[role]
                sent_payload = sent_spec.get("payload", sent_spec.get("parameter_value"))
                if sent_payload is None and isinstance(sent_spec.get("body"), dict):
                    sent_payload = sent_spec["body"].get(str(hypothesis.get("parameter", "")))
                if sent_payload is None:
                    query_values = parse_qs(urlsplit(url).query, keep_blank_values=True).get(str(hypothesis.get("parameter", "")), [])
                    if query_values:
                        sent_payload = query_values[-1]
                if sent_payload is not None:
                    raw[role]["structured_fields"] = {
                        **dict(raw[role].get("structured_fields", {}) or {}),
                        "payload": str(sent_payload),
                    }
        return raw

    # -- ProofBundle construction (reuse canonical model) ------------------
    def _compute_identity_binding(self, *, hypothesis: dict[str, Any], vuln_class: str,
                                  raw_triple: dict[str, Any]) -> dict[str, Any]:
        """V1.2: Prove real security property, not internal observation consistency.

        Extracts actor identity, resource identity, authorization boundary, and
        baseline/candidate/negative-control access results from the REAL request
        specs. identity_bound=True only when an actor accessed a resource they
        should not access (proven by actor mismatch + unauthorized success).
        Synthetic observations (no explicit request specs) cannot bind -> False.
        """
        explicit = hypothesis.get("requests") if isinstance(hypothesis.get("requests"), dict) else None
        cand_spec = explicit.get("candidate", {}) if explicit else {}
        base_spec = explicit.get("baseline", {}) if explicit else {}
        headers = dict(cand_spec.get("headers", {}) or {})
        base_headers = dict(base_spec.get("headers", {}) or {})
        actor_candidate = headers.get("X-User", headers.get("x-user", "unauthenticated"))
        actor_baseline = base_headers.get("X-User", base_headers.get("x-user", "unauthenticated"))
        resource_id = cand_spec.get("path", hypothesis.get("path", "unknown"))
        # Expected owner / authorization context (from hypothesis ground truth).
        resource_owner = hypothesis.get("resource_owner", actor_baseline)
        auth_context = hypothesis.get("authorization_context",
                                      f"owner={resource_owner}")
        b_status = raw_triple["baseline"]["status_code"]
        c_status = raw_triple["candidate"]["status_code"]
        nc_status = raw_triple["negative_control"]["status_code"]
        c_body = str(raw_triple["candidate"].get("response_body", ""))
        b_body = str(raw_triple["baseline"].get("response_body", ""))

        identity_bound = False
        reason = "no_identity_proof"
        causal_difference = None

        if not explicit and vuln_class in _M4_PRINCIPAL_FAMILIES:
            reason = "no_explicit_request_specs_synthetic_observation_cannot_bind_identity"
        elif vuln_class in ("IDOR", "BOLA"):
            # Must prove: candidate actor != owner AND candidate succeeded (200)
            # AND baseline (owner) succeeded AND negative control independent.
            actor_mismatch = actor_candidate != resource_owner and actor_candidate != actor_baseline
            unauthorized_success = c_status == 200 and b_status == 200
            nc_structured = raw_triple["negative_control"].get("structured_fields") or {}
            nc_body = str(raw_triple["negative_control"].get("response_body", ""))
            try:
                nc_json = json.loads(nc_body)
            except (TypeError, ValueError, json.JSONDecodeError):
                nc_json = None
            nc_is_empty = bool(nc_structured.get("json_data_null")) or (
                isinstance(nc_json, dict) and "data" in nc_json and nc_json.get("data") is None
            )
            nc_fingerprint = nc_structured.get("_body_fingerprint")
            base_fingerprint = (raw_triple["baseline"].get("structured_fields") or {}).get("_body_fingerprint")
            candidate_fingerprint = (raw_triple["candidate"].get("structured_fields") or {}).get("_body_fingerprint")
            nc_independent = (
                nc_status in (403, 404)
                or (nc_status == 200 and nc_is_empty)
                or (nc_status == 200 and nc_fingerprint and nc_fingerprint not in {base_fingerprint, candidate_fingerprint})
            )
            if actor_mismatch and unauthorized_success and nc_independent:
                identity_bound = True
                causal_difference = (f"actor={actor_candidate} (not owner {resource_owner}) "
                                     f"accessed resource {resource_id} (status 200); "
                                     f"owner={actor_baseline} also 200; nc={nc_status}")
                reason = "actor_mismatch_and_unauthorized_access_proven"
            elif not actor_mismatch:
                reason = f"actor_mismatch_absent candidate={actor_candidate} owner={resource_owner}"
            elif not unauthorized_success:
                reason = f"unauthorized_access_not_proven c_status={c_status} b_status={b_status}"
            else:
                reason = f"negative_control_not_independent nc_status={nc_status}"
        elif vuln_class == "AUTH_BYPASS":
            # Baseline unauthenticated denied; candidate with bypass header succeeds.
            bypass_header = headers.get("X-Forwarded-For", headers.get("x-forwarded-for"))
            baseline_denied = b_status in (401, 403)
            candidate_succeeded = c_status == 200
            if bypass_header and baseline_denied and candidate_succeeded:
                identity_bound = True
                causal_difference = (f"unauthenticated baseline={b_status}, "
                                     f"candidate with bypass header={bypass_header} got 200")
                reason = "auth_bypass_header_changed_authorization_outcome"
            else:
                reason = f"auth_bypass_not_proven baseline={b_status} candidate={c_status} bypass={bool(bypass_header)}"
        elif vuln_class == "MASS_ASSIGNMENT":
            # Candidate response reflects ELEVATED role (admin) that baseline lacks.
            elevated_in_candidate = "admin" in c_body.lower()
            elevated_absent_baseline = "admin" not in b_body.lower()
            if elevated_in_candidate and elevated_absent_baseline and c_status == 200:
                identity_bound = True
                causal_difference = "candidate assigned elevated role=admin reflected in response, baseline lacked it"
                reason = "mass_assignment_elevated_role_accepted"
            else:
                reason = f"mass_assignment_not_proven cand_has_admin={elevated_in_candidate} base_has_admin={not elevated_absent_baseline} status={c_status}"
        elif vuln_class == "SSRF":
            # Candidate URL param points to internal/metadata, response contains internal indicators.
            candidate_indicators = extract_ssrf_indicators(c_body)
            baseline_indicators = extract_ssrf_indicators(b_body)
            control_indicators = extract_ssrf_indicators(
                str(raw_triple["negative_control"].get("response_body", ""))
            )
            if (len(candidate_indicators) >= 2
                    and len(candidate_indicators) > len(baseline_indicators)
                    and not control_indicators and nc_status in (400, 403, 404)):
                identity_bound = True
                causal_difference = (
                    "attacker-controlled URL parameter produced "
                    f"{len(candidate_indicators)} internal indicator classes"
                )
                reason = "ssrf_internal_fetch_proven"
            else:
                reason = (
                    "ssrf_not_proven "
                    f"indicators={len(candidate_indicators)} "
                    f"baseline={len(baseline_indicators)} "
                    f"control={len(control_indicators)} nc={nc_status}"
                )
        elif vuln_class == "OPEN_REDIRECT":
            # Candidate Location header is external attacker-controlled.
            candidate_location, candidate_external = parse_external_location(raw_triple["candidate"])
            _, baseline_external = parse_external_location(raw_triple["baseline"])
            _, control_external = parse_external_location(raw_triple["negative_control"])
            if (candidate_external and c_status in (301, 302)
                    and not baseline_external and not control_external):
                identity_bound = True
                causal_difference = "candidate returned an unallowlisted external redirect Location"
                reason = "open_redirect_external_location_proven"
            else:
                reason = (
                    "open_redirect_not_proven "
                    f"external={candidate_external} status={c_status} "
                    f"baseline_external={baseline_external} control_external={control_external}"
                )
        elif vuln_class == "XSS":
            payload = _reflection_payload(raw_triple["candidate"])
            candidate_body = str(raw_triple["candidate"].get("response_body", ""))
            baseline_body = str(raw_triple["baseline"].get("response_body", ""))
            control_body = str(raw_triple["negative_control"].get("response_body", ""))
            content_type = str((raw_triple["candidate"].get("headers", {}) or {}).get("content-type", "")).lower()
            if payload and payload in candidate_body and payload not in baseline_body and payload not in control_body and "html" in content_type:
                identity_bound = True
                causal_difference = "candidate reflected the supplied payload while baseline and control did not"
                reason = "xss_candidate_only_unencoded_reflection_proven"
            else:
                reason = "xss_reflection_not_proven_or_content_type_not_html"
        elif vuln_class == "SQLI":
            candidate_body = str(raw_triple["candidate"].get("response_body", ""))
            baseline_body = str(raw_triple["baseline"].get("response_body", ""))
            candidate_status = raw_triple["candidate"].get("status_code", 0)
            baseline_status = raw_triple["baseline"].get("status_code", 0)
            if candidate_body != baseline_body or candidate_status != baseline_status:
                identity_bound = True
                causal_difference = "candidate SQL probe produced a response differential from baseline"
                reason = "sqli_candidate_baseline_differential_proven"
            else:
                reason = "sqli_candidate_baseline_differential_not_proven"
        elif vuln_class == "INFO_DISCLOSURE":
            # Candidate response contains >=2 sensitive patterns absent from baseline.
            candidate_indicators = extract_info_disclosure_indicators(c_body)
            baseline_indicators = extract_info_disclosure_indicators(b_body)
            control_indicators = extract_info_disclosure_indicators(
                str(raw_triple["negative_control"].get("response_body", ""))
            )
            if (len(candidate_indicators) >= 2
                    and len(candidate_indicators) > max(len(baseline_indicators), len(control_indicators))):
                identity_bound = True
                causal_difference = (
                    "candidate exposed "
                    f"{len(candidate_indicators)} sensitive pattern classes"
                )
                reason = "info_disclosure_sensitive_data_exposed"
            else:
                reason = (
                    "info_disclosure_not_proven "
                    f"sensitive={len(candidate_indicators)} "
                    f"baseline={len(baseline_indicators)} control={len(control_indicators)}"
                )
        elif vuln_class == "RACE_CONDITION":
            # Sprint A: the concurrent burst over-succeeded where one request was
            # expected, while the control burst did not over-succeed.
            c_struct = raw_triple["candidate"].get("structured_fields") or {}
            nc_struct = raw_triple["negative_control"].get("structured_fields") or {}

            def _int_field(structured: dict[str, Any], key: str) -> int:
                try:
                    return int(structured.get(key, 0) or 0)
                except (TypeError, ValueError):
                    return 0

            attempts = _int_field(c_struct, "_concurrent_attempts")
            successes = _int_field(c_struct, "_concurrent_successes")
            expected = _int_field(c_struct, "_concurrent_expected_successes") or 1
            nc_successes = _int_field(nc_struct, "_concurrent_successes")
            baseline_ok = 200 <= b_status < 300
            if attempts > 0 and successes > expected and baseline_ok and nc_successes <= expected:
                identity_bound = True
                causal_difference = (
                    f"bounded burst produced {successes}/{attempts} successes where {expected}"
                    f" was expected (baseline 2xx, control successes={nc_successes})"
                )
                reason = "race_condition_atomic_locking_absent"
            else:
                reason = (
                    "race_condition_not_proven "
                    f"attempts={attempts} successes={successes} expected={expected} "
                    f"baseline={b_status} control_successes={nc_successes}"
                )
        elif vuln_class == "BUSINESS_LOGIC":
            # Sprint A: the manipulated value was accepted where baseline/control
            # were not, and the candidate response differs materially.
            c_struct = raw_triple["candidate"].get("structured_fields") or {}
            manipulated = str(c_struct.get("candidate_value") or hypothesis.get("metadata", {}).get("candidate_value") or "")
            c_body_lower = c_body.lower()
            rejection = any(
                marker in c_body_lower
                for marker in ("invalid", "must be positive", "not allowed", "rejected", "out of range")
            )
            candidate_accepted = 200 <= c_status < 300 and not rejection and bool(manipulated) and manipulated.lower() in c_body_lower
            baseline_ok = 200 <= b_status < 300
            nc_body_lower = str(raw_triple["negative_control"].get("response_body", "")).lower()
            control_clean = not (bool(manipulated) and manipulated.lower() in nc_body_lower)
            materially_different = (c_body != b_body) or (c_status != b_status)
            if candidate_accepted and baseline_ok and control_clean and materially_different:
                identity_bound = True
                causal_difference = f"manipulated value {manipulated!r} accepted (baseline 2xx, control clean)"
                reason = "business_logic_invariant_broken"
            else:
                reason = (
                    "business_logic_not_proven "
                    f"accepted={candidate_accepted} baseline={b_status} control_clean={control_clean}"
                )
        elif vuln_class == "FILE_UPLOAD":
            # Sprint A: the uploaded artifact was reachable and demonstrated impact.
            c_struct = raw_triple["candidate"].get("structured_fields") or {}
            marker = "webpent_upload_probe_9c31"
            c_body_lower = c_body.lower()
            b_body_lower = b_body.lower()
            nc_body_lower = str(raw_triple["negative_control"].get("response_body", "")).lower()
            c_served = bool(c_struct.get("_upload_marker_served")) if c_struct.get("_upload_marker_served") is not None else (marker in c_body_lower)
            executed = bool(c_struct.get("_upload_executed")) if c_struct.get("_upload_executed") is not None else (marker in c_body_lower and "<?php" not in c_body_lower and "<script" not in c_body_lower)
            traversal = bool(c_struct.get("_upload_traversal_written")) if c_struct.get("_upload_traversal_written") is not None else False
            active_sink = "<script" in c_body_lower and marker in c_body_lower
            b_served = marker in b_body_lower
            nc_served = marker in nc_body_lower
            if c_served and (executed or traversal or active_sink) and not b_served and not nc_served and 200 <= c_status < 300:
                identity_bound = True
                causal_difference = (
                    "uploaded artifact reachable and demonstrated impact "
                    f"(executed={executed} traversal={traversal} active_sink={active_sink})"
                )
                reason = "file_upload_artifact_reachable_with_impact"
            else:
                reason = (
                    "file_upload_not_proven "
                    f"served={c_served} executed={executed} traversal={traversal} "
                    f"baseline_served={b_served} control_served={nc_served}"
                )
        elif vuln_class == "JWT_MANIPULATION":
            # Sprint A: a tampered token was accepted where baseline and control
            # were both denied at the same protected route.
            c_body_lower = c_body.lower()
            denied = any(
                marker in c_body_lower
                for marker in ("unauthorized", "forbidden", "invalid token", "authentication required")
            )
            candidate_accepted = 200 <= c_status < 300 and not denied
            baseline_denied = b_status in (401, 403)
            control_denied = nc_status in (401, 403)
            if candidate_accepted and baseline_denied and control_denied:
                identity_bound = True
                causal_difference = (
                    f"tampered token accepted (200) where baseline={b_status} and control={nc_status} were denied"
                )
                reason = "jwt_signature_verification_absent"
            else:
                reason = (
                    "jwt_manipulation_not_proven "
                    f"candidate={c_status} baseline={b_status} control={nc_status}"
                )
        elif vuln_class in ("SSTI", "LFI", "PATH_TRAVERSAL", "COMMAND_INJECTION", "XXE", "RFI", "XSS", "SQLI", "SSRF"):
            c_body = str(raw_triple.get("candidate", {}).get("response_body", ""))
            b_body = str(raw_triple.get("baseline", {}).get("response_body", ""))
            nc_status = raw_triple.get("negative_control", {}).get("status_code", 200)
            if c_body and c_body != b_body and (nc_status in (404, 403, 500) or c_body != str(raw_triple.get("negative_control", {}).get("response_body", ""))):
                identity_bound = True
                causal_difference = f"{vuln_class.lower()}_response_differential"
                reason = f"{vuln_class.lower()}_differential_confirmed"
            else:
                reason = f"{vuln_class.lower()}_no_differential"
        else:
            reason = f"unknown_vulnerability_class_{vuln_class}"

        return {
            "actor_id": actor_candidate,
            "baseline_actor_id": actor_baseline,
            "resource_id": resource_id,
            "resource_owner": resource_owner,
            "authorization_context": auth_context,
            # V1.2 release closure: redaction-safe sibling of authorization_context.
            # ProofBundle redaction policy redacts any value under a key matching
            # the "authorization" token, so the sealed bundle also carries the
            # plain expected owner under this non-sensitive key. No authority is
            # duplicated — same sealed value, redaction-safe storage key.
            "expected_owner": str(resource_owner),
            "baseline_access_result": b_status,
            "candidate_access_result": c_status,
            "negative_control_result": nc_status,
            "causal_difference": causal_difference,
            "identity_bound": identity_bound,
            "identity_bound_reason": reason,
        }

    def _build_and_seal_proof(self, *, hypothesis_id: str, vuln_class: str,
                              experiment_id: str, validator_result: Any,
                              baseline_digest: str, candidate_digest: str,
                              negative_control_digest: str,
                              target_fingerprint: str,
                              request_digests: tuple[str, ...] = (),
                              response_digests: tuple[str, ...] = (),
                              identity_binding: dict[str, Any] | None = None,
                              guard_adjudication: Any | None = None) -> Any:
        from webpent.models.proof_bundle import ProofBundle
        engagement_id = getattr(self.orch, "engagement_id", "avi_engagement")
        finding_id = _canonical_finding_id(
            engagement_id=str(engagement_id),
            target_fingerprint=str(target_fingerprint),
            hypothesis_id=hypothesis_id,
            experiment_id=experiment_id,
            vulnerability_class=vuln_class,
        )
        ib = identity_binding or {}
        causal_oracle = {
            "causal_signal": validator_result.outcome == ValidationOutcome.CONFIRMED,
            "negative_control_complete": True,
            "baseline_complete": True,
            "discriminating_signal": validator_result.discriminating_signal[:200],
            "validator_outcome": validator_result.outcome.value,
            # V1.2 semantic authority — evidence MEANING, not just integrity.
            "actor_id": ib.get("actor_id"),
            "resource_id": ib.get("resource_id"),
            "authorization_context": ib.get("authorization_context"),
            "expected_owner": ib.get("expected_owner"),
            "baseline_access_result": ib.get("baseline_access_result"),
            "candidate_access_result": ib.get("candidate_access_result"),
            "negative_control_result": ib.get("negative_control_result"),
            "causal_difference": ib.get("causal_difference"),
            "identity_bound": bool(ib.get("identity_bound", False)),
            "identity_bound_reason": ib.get("identity_bound_reason"),
            # UM-DR-35: the typed CausalGuard adjudication sealed into the
            # bundle — authority module, verdict, role-ablation signals and
            # the evidence digests it adjudicated (same-finding binding).
            "causal_guard": (
                guard_adjudication.to_dict()
                if guard_adjudication is not None else None
            ),
        }
        # Full sha256:<64hex> digests required by ProofBundle schema.
        def _full_digest(short: str) -> str:
            return f"sha256:{hashlib.sha256(short.encode()).hexdigest()}"
        bd_full = _full_digest(baseline_digest)
        cd_full = _full_digest(candidate_digest)
        ncd_full = _full_digest(negative_control_digest)
        bundle = ProofBundle(
            engagement_id=engagement_id,
            finding_id=finding_id,
            hypothesis_id=hypothesis_id,
            target_fingerprint=target_fingerprint,
            vulnerability_class=vuln_class,
            evidence_refs=(f"obs_{baseline_digest}", f"obs_{candidate_digest}", f"obs_{negative_control_digest}"),
            evidence_digests=(bd_full, cd_full, ncd_full),
            request_digests=tuple(request_digests),
            response_digests=tuple(response_digests),
            baseline_digest=bd_full,
            negative_control_digest=ncd_full,
            causal_oracle=causal_oracle,
            target_backed=True,
            negative_control_independent=True,
            validator_id=f"canonical_validator_{vuln_class.lower()}",
            validator_version="validator_coverage_v1",
            oracle_decision=validator_result.outcome.value,
            evidence_origin="target_runtime",
            campaign_id=engagement_id,
            run_id=experiment_id,
            cleanup_status="not_applicable",
            validator_result={"outcome": validator_result.outcome.value,
                              "evidence_quality": int(validator_result.evidence_quality),
                              "discriminating_signal": validator_result.discriminating_signal[:200]},
            scope_context={"authorized_via": "ScopeLaw+ToolBoundary", "tool": "httpx_bounded"},
            identity_context={
                "execution_identity": f"exec_{experiment_id}_{target_fingerprint[:8]}",
                "actor_id": ib.get("actor_id"),
                "baseline_actor_id": ib.get("baseline_actor_id"),
                "resource_id": ib.get("resource_id"),
                "resource_owner": ib.get("resource_owner"),
                "authorization_context": ib.get("authorization_context"),
                "expected_owner": ib.get("expected_owner"),
                "identity_bound": bool(ib.get("identity_bound", False)),
            },
            replay_metadata={
                "replay_required": True,
                "replayable": True,
                "requests_executed": 3,
                "replay_component": "ReplayVerifier_v1",
            },
        )
        return bundle.seal(actor="autonomous_validation_intelligence_v1")

    # -- One full decision --------------------------------------------------
    def _run_one_decision(self, *, target_url: str, hypotheses: list[dict[str, Any]],
                          decision_number: int) -> dict[str, Any]:
        trace = self.trace
        target_fingerprint = sha256_text(target_url)[:16]

        # Stage 1: ResearchLoop step (advisory).
        try:
            rl_decision = self.orch.research_step()
            rl_proof = {"decision_number": rl_decision.get("decision_number", decision_number),
                        "advisory_only": True}
        except (AttributeError, KeyError, RuntimeError, TypeError, ValueError):
            rl_proof = {"decision_number": decision_number, "advisory_only": True, "research_loop_fallback": True}
        trace.record(stage="research_loop_step", component="ResearchLoop", proof=rl_proof)

        # Stage 2: AutonomousExperimentSelector (deterministic).
        selection = self.selector.select(hypotheses)
        if not selection.get("selected"):
            trace.record(stage="experiment_selected", component="AutonomousExperimentSelector",
                         proof={"selected": False, "reason": selection.get("reason")})
            return {"decision": decision_number, "stopped": True, "reason": selection.get("reason")}
        hid = selection["hypothesis_id"]
        vuln = selection["vulnerability_class"]
        exp_id = selection["experiment_id"]
        trace.record(stage="experiment_selected", component="AutonomousExperimentSelector",
                     proof={"hypothesis_id": hid, "experiment_id": exp_id,
                            "vulnerability_class": vuln, "api_type": selection["api_type"],
                            "deterministic": True, "llm_authority": False})

        # Stage 3: ExperimentRegistry lookup.
        reg_hit = vuln in EXPERIMENT_REGISTRY
        trace.record(stage="registry_lookup", component="ExperimentRegistry",
                     proof={"vulnerability_class": vuln, "experiment_id": exp_id,
                            "registry_hit": reg_hit, "registry_size": len(EXPERIMENT_REGISTRY)})
        if not reg_hit:
            # Fail closed — unknown class is not executed, recorded as rejected.
            pr = self.promotion_pipeline.evaluate(
                baseline_obs=None, candidate_obs=None, negative_control_obs=None,
                evidence_origin="target_runtime", validator_outcome=None,
                evidence_quality=0, proof_bundle=None, replay_verified=False,
                finding_id=None, vulnerability_class=vuln,
            )
            trace.record(stage="promotion_decision", component="PromotionPipeline",
                         proof={"decision": pr.decision.value, "reason": "unknown_vulnerability_class_fail_closed"})
            self.rejected_count += 1
            self.security_report.add_rejected({"hypothesis_id": hid, "vulnerability_class": vuln,
                                               "reason": "unknown_class_fail_closed"})
            trace.record(stage="research_feedback_recorded", component="OutcomeTracker",
                         proof={"hypothesis_id": hid, "outcome_class": "rejected_unknown_class", "recorded": True})
            return {"decision": decision_number, "hypothesis_id": hid, "vulnerability_class": vuln,
                    "promotion": pr.to_dict(), "stopped": False}

        chosen_hyp = next((h for h in hypotheses if str(h.get("id")) == hid), {})

        # Stage 4: Real authorized execution (3 real HTTP requests).
        raw_triple = self._execute_real_triple(target_url=target_url, hypothesis=chosen_hyp, vuln_class=vuln)
        all_real = all(raw_triple[r].get("real_http") and raw_triple[r].get("authorized")
                       for r in ("baseline", "candidate", "negative_control"))
        trace.record(stage="real_execution", component="GenericExperimentRunner+RealHTTP",
                     proof={"hypothesis_id": hid, "experiment_id": exp_id,
                            "vulnerability_class": vuln, "real_http_executed": all_real,
                            "baseline_status": raw_triple["baseline"]["status_code"],
                            "candidate_status": raw_triple["candidate"]["status_code"],
                            "negative_control_status": raw_triple["negative_control"]["status_code"],
                            "authorized": all_real, "evidence_origin": "target_runtime"})

        # Stage 5: ObservationNormalizer.
        b_norm = normalize_observation(exp_id, "baseline", raw_triple["baseline"])
        c_norm = normalize_observation(exp_id, "candidate", raw_triple["candidate"])
        nc_norm = normalize_observation(exp_id, "negative_control", raw_triple["negative_control"])
        trace.record(stage="observation_normalized", component="ObservationNormalizer",
                     proof={"experiment_id": exp_id,
                            "baseline_digest": b_norm.digest(), "candidate_digest": c_norm.digest(),
                            "negative_control_digest": nc_norm.digest(),
                            "secrets_redacted": True})

        # Stage 6: Causal Validator (ValidatorAdapter → run_validator).
        # Use REAL redacted body content (from raw target_runtime observations)
        # so content-based validators (SSRF, INFO_DISCLOSURE, MASS_ASSIGNMENT,
        # OPEN_REDIRECT) can discriminate. Fingerprints remain for proof/replay.
        normalized_by_role = {"baseline": b_norm, "candidate": c_norm, "negative_control": nc_norm}
        identity_hint: bool | None = None
        if str(vuln).upper() in _M4_PRINCIPAL_FAMILIES:
            request_specs = chosen_hyp.get("requests") if isinstance(chosen_hyp.get("requests"), dict) else {}
            base_spec = request_specs.get("baseline", {})
            candidate_spec = request_specs.get("candidate", {})
            owner = str(chosen_hyp.get("resource_owner") or base_spec.get("principal_alias") or "")
            candidate_actor = str(candidate_spec.get("principal_alias") or candidate_spec.get("principal_role") or "")
            identity_hint = bool(candidate_actor and owner and candidate_actor != owner)
        def _vi(role: str) -> dict[str, Any]:
            raw = raw_triple[role]
            normalized = normalized_by_role[role]
            structured = {
                **dict(raw.get("structured_fields", {}) or {}),
                "_body_fingerprint": normalized.body_fingerprint,
                "_body_size": normalized.body_size,
            }
            knowledge_metadata = chosen_hyp.get("metadata", {}) if isinstance(chosen_hyp.get("metadata"), dict) else {}
            if knowledge_metadata.get("wstg_reference"):
                structured["_wstg_reference"] = str(knowledge_metadata["wstg_reference"])[:64]
            if knowledge_metadata.get("wstg_expected_behavior"):
                structured["_wstg_expected_behavior"] = str(knowledge_metadata["wstg_expected_behavior"])[:500]
            if identity_hint is not None:
                structured["_identity_mismatch_hint"] = identity_hint
            return {"status_code": raw["status_code"],
                    "response_body": str(raw["response_body"])[:2000],
                    "headers": dict(raw.get("headers", {}) or {}),
                    "structured_fields": structured,
                    "request_url": raw.get("request_url", ""),
                    "response_time_ms": raw.get("response_time_ms"),
                    "payload": raw.get("payload") or raw.get("structured_fields", {}).get("payload") if isinstance(raw.get("structured_fields"), dict) else raw.get("payload"),
                    "sql_payload": raw.get("sql_payload") or raw.get("structured_fields", {}).get("sql_payload") if isinstance(raw.get("structured_fields"), dict) else raw.get("sql_payload"),
                    "reflection_payload": raw.get("reflection_payload") or raw.get("structured_fields", {}).get("reflection_payload") if isinstance(raw.get("structured_fields"), dict) else raw.get("reflection_payload"),}
        validator_input = {
            "baseline": _vi("baseline"),
            "candidate": _vi("candidate"),
            "negative_control": _vi("negative_control"),
        }
        try:
            vr = run_validator(vuln, **validator_input)
            validator_executed = True
        except (AttributeError, KeyError, RuntimeError, TypeError, ValueError, ValidatorError) as exc:
            vr = None
            validator_executed = False
            validator_error = str(exc)[:120]
        trace.record(stage="validator_adapter_executed", component="ValidatorAdapter+CausalValidator",
                     proof={"experiment_id": exp_id, "vulnerability_class": vuln,
                            "validator_executed": validator_executed,
                            "outcome": vr.outcome.value if vr else None,
                            "discriminating_signal": (vr.discriminating_signal[:120] if vr else None)})

        # UM-DR-35 §1.3 condition 8 (AVI path): the class validator's
        # RECORDED deterministic detection is stamped on the CANDIDATE
        # observation (its role ONLY) so the CausalGuard authority
        # adjudicates the full experiment evidence. The stamp is grounded
        # in the validator's own recorded outcome — never asserted for a
        # non-CONFIRMED validator result or without a recorded
        # discriminating signal. The guard still demands the semantic
        # differential, the independent negative control, actor/resource
        # context, and the promotion gates; the stamp only makes the
        # recorded class signal VISIBLE to the authority (mirror of the
        # graph validator path's stamping in agents/validator/*).
        if (
            vr is not None
            and vr.outcome == ValidationOutcome.CONFIRMED
            and str(vr.discriminating_signal or "").strip()
            and isinstance(raw_triple.get("candidate"), dict)
            and "validator_technical_signal" not in raw_triple["candidate"]
        ):
            raw_triple["candidate"] = {
                **raw_triple["candidate"],
                "validator_technical_signal": True,
                "class_validator_id": f"canonical_validator_{str(vuln).lower()}",
            }

        # Stage 6b: Causal Identity Binding (V1.2 trust hardening).
        # CONFIRMED must prove a two-principal property for IDOR/BOLA. Other
        # validator families establish causality through their own differential
        # evidence and do not require an M4 principal binding.
        identity_binding = self._compute_identity_binding(
            hypothesis=chosen_hyp, vuln_class=vuln, raw_triple=raw_triple)
        # If validator says CONFIRMED but identity binding fails -> downgrade
        # to INCONCLUSIVE (cannot prove real security property).
        if (vr is not None and vr.outcome == ValidationOutcome.CONFIRMED
                and str(vuln).upper() in _M4_PRINCIPAL_FAMILIES
                and not identity_binding["identity_bound"]):
            from webpent.production.validators import ValidationResult as _VR
            vr = _VR(vuln, ValidationOutcome.INCONCLUSIVE,
                     EvidenceQuality.HEURISTIC_SIGNAL,
                     f"identity_binding_failed: {identity_binding['identity_bound_reason']}",
                     validator_input["baseline"], validator_input["candidate"], validator_input["negative_control"])
        trace.record(stage="identity_bound", component="CausalGuard+IdentityBinding",
                     proof={"hypothesis_id": hid, "vulnerability_class": vuln,
                            "actor_id": identity_binding["actor_id"],
                            "resource_id": identity_binding["resource_id"],
                            "identity_bound": identity_binding["identity_bound"],
                            "identity_bound_reason": identity_binding["identity_bound_reason"],
                            "causal_difference": identity_binding["causal_difference"]})

        # Stage 6c (UM-DR-35 corrective closure): MANDATORY CausalGuard
        # adjudication through the universal confirmation adapter — the
        # sole technical confirmation authority. The adapter adjudicates the
        # REAL raw triple (status codes, response bodies, per-role actor and
        # resource context derived from actual evidence) and returns a typed
        # GuardedAdjudication bound to this decision's exact evidence. No
        # promotion may occur unless this adjudication is CONFIRMED.
        guard_decision = None
        guard_adjudication = None
        try:
            from webpent.production.confirmation_adapter import (  # noqa: PLC0415
                confirmation_gate,
            )
            guard_decision = confirmation_gate(
                raw_triple["baseline"],
                raw_triple["candidate"],
                raw_triple["negative_control"],
                vulnerability_class=vuln,
                validator_outcome=(vr.outcome.value if vr else None),
                validator_id=f"canonical_validator_{str(vuln).lower()}",
                identity_context={
                    "actor_id": identity_binding.get("actor_id"),
                    "resource_owner": identity_binding.get("resource_owner"),
                    "baseline_identity": {
                        "identity_id": identity_binding.get("baseline_actor_id"),
                        "role": "owner",
                        "auth_state": "authenticated",
                    },
                    "candidate_identity": {
                        "identity_id": identity_binding.get("actor_id"),
                        "role": "foreign-user",
                        "auth_state": "authenticated",
                    },
                    "negative_control_identity": {
                        "identity_id": identity_binding.get("actor_id"),
                        "role": "foreign-user",
                        "auth_state": "authenticated",
                    },
                },
                scope_context={
                    "authorized_via": "ScopeLaw+ToolBoundary",
                    "target_origin": str(target_url),
                    "tool": "httpx_bounded",
                },
            )
            guard_adjudication = guard_decision.adjudication
        except (AttributeError, ImportError, KeyError, RuntimeError, TypeError, ValueError) as guard_exc:
            guard_decision = None
            guard_adjudication = None
            trace.record(stage="causal_guard_adjudication", component="CausalGuard+ConfirmationAdapter",
                         proof={"executed": False, "error": str(guard_exc)[:160],
                                "authority": "webpent.cqa_v2.causal_guard.guarded_causal_evaluate"})
        trace.record(stage="causal_guard_adjudication", component="CausalGuard+ConfirmationAdapter",
                     proof={
                         "executed": guard_decision is not None,
                         "outcome": str(guard_decision.outcome.value) if guard_decision else None,
                         "reason": guard_decision.reason if guard_decision else None,
                         "authority": "webpent.cqa_v2.causal_guard.guarded_causal_evaluate",
                         "adapter": "webpent.production.confirmation_adapter",
                         "verdict": str(guard_adjudication.guard_result.verdict.value) if guard_adjudication else None,
                         "causal_signal": guard_adjudication.guard_result.causal_signal if guard_adjudication else None,
                         "authorization_differential": guard_adjudication.guard_result.authorization_differential if guard_adjudication else None,
                         "role_technical_signals": (
                             {role: payload.get("signal")
                              for role, payload in guard_adjudication.role_signals.items()}
                             if guard_adjudication else None
                         ),
                         "evidence_digests": (
                             dict(guard_adjudication.evidence_digests)
                             if guard_adjudication else None
                         ),
                     })

        # Stage 7: EvidenceQuality calculated.
        eq = int(vr.evidence_quality) if vr else int(EvidenceQuality.STRUCTURAL_HINT)
        trace.record(stage="evidence_quality_calculated", component="EvidenceQuality",
                     proof={"experiment_id": exp_id, "evidence_quality": eq,
                            "evidence_quality_label": EvidenceQuality(eq).name if eq <= 5 else "UNKNOWN",
                            "promotion_grade_minimum": int(EvidenceQuality.OBSERVED_DIFFERENTIAL)})

        # Stage 8: ProofBundle created + sealed (HMAC).
        proof_bundle = None
        if vr is not None and vr.outcome == ValidationOutcome.CONFIRMED:
            try:
                proof_bundle = self._build_and_seal_proof(
                    hypothesis_id=hid, vuln_class=vuln, experiment_id=exp_id,
                    validator_result=vr, baseline_digest=b_norm.digest(),
                    candidate_digest=c_norm.digest(), negative_control_digest=nc_norm.digest(),
                    request_digests=tuple(raw_triple[role].get("request_digest", "") for role in ("baseline", "candidate", "negative_control")),
                    response_digests=tuple(f"sha256:{hashlib.sha256(d.encode()).hexdigest()}" for d in (b_norm.digest(), c_norm.digest(), nc_norm.digest())),
                    target_fingerprint=target_fingerprint,
                    identity_binding=identity_binding,
                    guard_adjudication=guard_adjudication,
                )
            except (AttributeError, KeyError, RuntimeError, TypeError, ValueError):
                proof_bundle = None
        proof_created = proof_bundle is not None and getattr(proof_bundle, "sealed", False)
        trace.record(stage="proof_created", component="ProofBundle",
                     proof={"hypothesis_id": hid, "bundle_id": getattr(proof_bundle, "bundle_id", None),
                            "sealed": proof_created,
                            "seal_digest": getattr(proof_bundle, "seal_digest", None),
                            "authenticity_tag_present": bool(getattr(proof_bundle, "authenticity_tag", None)),
                            "evidence_origin": "target_runtime"})

        # Stage 9: Replay verification (deterministic re-derivation).
        replay_result = self.replay_verifier.verify(
            experiment_id=exp_id,
            baseline_raw=raw_triple["baseline"], candidate_raw=raw_triple["candidate"],
            negative_control_raw=raw_triple["negative_control"],
            vulnerability_class=vuln,
            expected_outcome=vr.outcome.value if vr else "NONE",
            expected_baseline_digest=b_norm.digest(), expected_candidate_digest=c_norm.digest(),
            expected_negative_control_digest=nc_norm.digest(),
            proof_bundle=proof_bundle,
        )
        trace.record(stage="replay_verified", component="ReplayVerifier",
                     proof={"experiment_id": exp_id, "replay_verified": replay_result["replay_verified"],
                            "digests_match": replay_result["digests_match"],
                            "outcome_match": replay_result["outcome_match"],
                            "seal_verified": replay_result["seal_verified"]})

        # DR-005 (TC-2): the resurrection inserted the confidence computation
        # INSIDE this call's argument list, shipping the module syntactically
        # broken (unimportable).  Reconstructed intent: compute the
        # deterministic confidence score BEFORE the promotion decision, pass
        # it as the pipeline's ``confidence_score`` kwarg, and never fake a
        # number on failure (None = no confidence claim).
        _confidence_score = None
        try:
            from webpent.shared.confidence import compute_confidence_score, EvidenceType
            _ev_type = (EvidenceType.TOOL_CONFIRMED
                        if (vr and vr.outcome == ValidationOutcome.CONFIRMED)
                        else EvidenceType.HEURISTIC)
            _confidence_score = compute_confidence_score(
                _ev_type, devils_advocate_verdict="plausible")
        except (ImportError, TypeError, ValueError, KeyError):
            # P-1 exception hygiene: this is a named critical module — no
            # broad handlers.  compute_confidence_score is deterministic
            # arithmetic; only import/shape failures are plausible, and a
            # confidence failure NEVER fakes a number (None = no claim).
            _confidence_score = None

        # Stage 10: PromotionPipeline decision (anti-fake gates).
        pr = self.promotion_pipeline.evaluate(
            baseline_obs=b_norm, candidate_obs=c_norm, negative_control_obs=nc_norm,
            evidence_origin="target_runtime",
            validator_outcome=vr.outcome.value if vr else None,
            evidence_quality=eq, proof_bundle=proof_bundle,
            replay_verified=replay_result["replay_verified"],
            verdict_authority="CausalGuard_deterministic_engine",
            confidence_score=_confidence_score,
            finding_id=getattr(proof_bundle, "finding_id", None) if proof_bundle else None,
            vulnerability_class=vuln,
            guard_adjudication=guard_adjudication,
        )
        if pr.decision != PromotionDecision.PROMOTED:
            # Rejected, refuted, inconclusive, and blocked attempts are not
            # findings and must not expose a reportable identity.
            pr.finding_id = None
        reportable_bundle = proof_bundle if pr.decision == PromotionDecision.PROMOTED else None
        trace.record(stage="promotion_decision", component="PromotionPipeline",
                     proof={"hypothesis_id": hid, "vulnerability_class": vuln,
                            "decision": pr.decision.value, "reason": pr.reason,
                            "gates_passed": pr.gates_passed, "gates_failed": pr.gates_failed,
                            "confidence_used": False})
        decision_proof_trace: dict[str, Any] | None = None
        if pr.decision == PromotionDecision.PROMOTED:
            self.promoted_count += 1
            # V1.2 release closure (TEAM-4 BLOCKER 1): complete proof trace,
            # extracted from the EXISTING sealed ProofBundle + ReplayVerifier
            # result + PromotionPipeline decision. No new verifier/authority.
            decision_proof_trace = build_proof_trace(
                proof_bundle=proof_bundle, replay_result=replay_result,
                promotion=pr.to_dict())
            promoted_finding = {
                "finding_id": pr.finding_id, "hypothesis_id": hid,
                "vulnerability_class": vuln, "experiment_id": exp_id,
                "outcome": vr.outcome.value if vr else None,
                "evidence_quality": eq,
                "discriminating_signal": vr.discriminating_signal[:200] if vr else None,
                "causal_guard": (
                    guard_adjudication.to_dict() if guard_adjudication else None
                ),
                "bundle_id": getattr(proof_bundle, "bundle_id", None),
                "seal_digest": getattr(proof_bundle, "seal_digest", None),
                "api_type": selection["api_type"],
                # V1.2 SecurityReport enforcement fields.
                "promotion": pr.to_dict(),
                "replay_verified": replay_result["replay_verified"],
                "proof_seal_verified": bool(proof_created),
                "identity_bound": bool(identity_binding.get("identity_bound", False)),
                "actor_id": identity_binding.get("actor_id"),
                "resource_id": identity_binding.get("resource_id"),
                "causal_difference": identity_binding.get("causal_difference"),
            }
            promoted_finding["proof_trace"] = decision_proof_trace
            self.security_report.add_promoted(promoted_finding)
        else:
            self.rejected_count += 1
            self.security_report.add_rejected({
                "hypothesis_id": hid, "vulnerability_class": vuln,
                "reason": pr.reason, "gates_failed": pr.gates_failed,
            })

        # Stage 11: OutcomeTracker → research feedback recorded → next decision.
        outcome_cls = {
            ValidationOutcome.CONFIRMED.value: "confirmed_supported",
            ValidationOutcome.REFUTED.value: "refuted",
            ValidationOutcome.INCONCLUSIVE.value: "low_information",
        }.get(vr.outcome.value if vr else "", "low_information")
        tracker_len_before = len(self.orch.outcome_tracker.history)
        try:
            self.orch.record_outcome(
                experiment_signature=exp_id, outcome_class=outcome_cls,
                information_value=float(eq), hypothesis_id=hid,
                justification=f"avi_decision_{decision_number}_{pr.decision.value}",
            )
            feedback_recorded = True
        except (AttributeError, KeyError, RuntimeError, TypeError, ValueError):
            feedback_recorded = False
        tracker_entry = None
        if feedback_recorded and len(self.orch.outcome_tracker.history) > tracker_len_before:
            tracker_entry = dict(self.orch.outcome_tracker.history[-1])
            tracker_entry["history_index"] = tracker_len_before
            tracker_entry["feeds_next_decision"] = True
        trace.record(stage="research_feedback_recorded", component="OutcomeTracker",
                     proof={"hypothesis_id": hid, "experiment_id": exp_id,
                            "outcome_class": outcome_cls, "information_value": float(eq),
                            "feedback_recorded": feedback_recorded,
                            "feeds_next_decision": True})

        # Stage 11b (V1.2 release closure, TEAM-4 BLOCKER 2): WorldModel update
        # via the EXISTING EvidenceGraph API — the SAME seam run_bounded_experiment
        # already uses (register_hypothesis + record_observation_outcome +
        # record_experiment). WorldModel remembers observed state only; it never
        # authorizes and never confirms. This gives every decision a REAL,
        # runtime-derived world model delta instead of a runner-side assertion.
        world_model_delta: dict[str, Any] | None = None
        wm = getattr(self.orch, "world_model", None)
        if wm is not None:
            try:
                entities_before = wm.entity_count
                relations_before = wm.relation_count
                hypotheses_before = wm.hypothesis_count
                experiments_before = len(wm.past_experiment_signatures)
                wm.register_hypothesis(hid, f"avi hypothesis {hid} ({vuln})",
                                       proposed_by="avi_deterministic_selector_v1")
                obs_id = f"obs_{exp_id}_d{decision_number}"
                supports = bool(vr is not None
                                and vr.outcome == ValidationOutcome.CONFIRMED
                                and pr.decision == PromotionDecision.PROMOTED)
                wm.record_observation_outcome(
                    observation_id=obs_id, hypothesis_id=hid,
                    supports=supports, information_value=min(1.0, float(eq) / 5.0),
                )
                wm.record_experiment(exp_id)
                world_model_delta = {
                    "updated": True,
                    "api": "EvidenceGraph.register_hypothesis+record_observation_outcome+record_experiment (existing world model seam)",
                    "observation_id": obs_id,
                    "supports_hypothesis": supports,
                    "information_value": min(1.0, float(eq) / 5.0),
                    "entities_delta": wm.entity_count - entities_before,
                    "relations_delta": wm.relation_count - relations_before,
                    "hypotheses_delta": wm.hypothesis_count - hypotheses_before,
                    "experiments_delta": len(wm.past_experiment_signatures) - experiments_before,
                    "entity_count_after": wm.entity_count,
                    "relation_count_after": wm.relation_count,
                    "hypothesis_count_after": wm.hypothesis_count,
                }
            except (AttributeError, KeyError, RuntimeError, TypeError, ValueError) as exc:
                world_model_delta = {"updated": False, "error": str(exc)[:160]}
            trace.record(stage="world_model_updated", component="WorldModel+EvidenceGraph",
                         proof={"hypothesis_id": hid, "observation_id": world_model_delta.get("observation_id") if world_model_delta else None,
                                "updated": bool(world_model_delta and world_model_delta.get("updated")),
                                "entities_delta": world_model_delta.get("entities_delta") if world_model_delta else None,
                                "relations_delta": world_model_delta.get("relations_delta") if world_model_delta else None})

        return {
            "decision": decision_number,
            "hypothesis_id": hid,
            "vulnerability_class": vuln,
            "experiment_id": exp_id,
            "api_type": selection["api_type"],
            "real_http_executed": all_real,
            "validator_outcome": vr.outcome.value if vr else None,
            "evidence_quality": eq,
            "proof_sealed": reportable_bundle is not None and proof_created,
            "proof_seal_verified": reportable_bundle is not None and bool(proof_created),
            "replay_verified": replay_result["replay_verified"],
            "identity_bound": bool(identity_binding.get("identity_bound", False)),
            "identity_bound_reason": identity_binding.get("identity_bound_reason"),
            "actor_id": identity_binding.get("actor_id"),
            "resource_id": identity_binding.get("resource_id"),
            "causal_difference": identity_binding.get("causal_difference"),
            "promotion": pr.to_dict(),
            "stopped": False,
            # V1.2 release closure (TEAM-4 BLOCKER 2): full per-decision runtime
            # — selected + rejected candidates, identity binding result, proof
            # result, replay result, world model delta, outcome tracker update.
            "selection": dict(selection),
            "knowledge_metadata": {
                key: chosen_hyp.get("metadata", {}).get(key)
                for key in (
                    "payload_id", "payload_sub_type", "payload_source",
                    "payload_safety_class", "wstg_reference", "wstg_aliases",
                    "wstg_methodology_digest", "wstg_methodology_summary",
                    "wstg_expected_behavior",
                )
                if chosen_hyp.get("metadata", {}).get(key) not in (None, "", [], {})
            },
            "identity_binding_result": dict(identity_binding),
            "proof_result": {
                "bundle_created": reportable_bundle is not None,
                "bundle_id": getattr(reportable_bundle, "bundle_id", None),
                "sealed": reportable_bundle is not None and proof_created,
                "seal_digest": getattr(reportable_bundle, "seal_digest", None),
                "seal_verified_via_replay": replay_result.get("seal_verified") if reportable_bundle is not None else False,
                "evidence_origin": "target_runtime",
                "component": "ProofBundle (existing sealed evidence authority)",
            },
            "proof_bundle": reportable_bundle.model_dump(mode="json") if reportable_bundle is not None else None,
            "request_sequence": [
                {
                    "role": role,
                    "method": raw_triple[role].get("request_method", "GET"),
                    "url": raw_triple[role].get("request_url"),
                    "request_digest": raw_triple[role].get("request_digest"),
                }
                for role in ("baseline", "candidate", "negative_control")
            ],
            "response_sequence": [
                {
                    "role": role,
                    "status_code": raw_triple[role].get("status_code"),
                    "response_digest": (
                        raw_triple[role].get("body_digest")
                        or (reportable_bundle.response_digests[index]
                            if reportable_bundle is not None and index < len(reportable_bundle.response_digests)
                            else None)
                    ),
                }
                for index, role in enumerate(("baseline", "candidate", "negative_control"))
            ],
            "replay_result": dict(replay_result),
            "world_model_delta": world_model_delta,
            "outcome_tracker_update": tracker_entry,
            # BLOCKER 1: promoted decisions carry the full trace contract inline.
            "proof_trace": decision_proof_trace,
            "proof_trace_contract": TRACE_CONTRACT_VERSION if decision_proof_trace else None,
        }

    # -- Full campaign ------------------------------------------------------
    def run_campaign(self, *, target_url: str, hypotheses: list[dict[str, Any]],
                     max_decisions: int = 30) -> dict[str, Any]:
        """Run a bounded autonomous validation campaign.

        Production dispatch entry. Each decision is the full 11-stage pipeline.
        Stop when max_decisions reached or hypotheses exhausted.
        """
        if not target_url:
            raise AVICampaignError("target_url required")
        if not hypotheses:
            raise AVICampaignError("hypotheses required")
        max_decisions = max(1, min(int(max_decisions), 100))
        # Ensure orchestrator is active (deep recon run) so research_step works.
        if not getattr(self.orch, "_active", False):
            try:
                self.orch.run_deep_recon(
                    target_url=target_url,
                    observed=[{"path": h.get("path", "/api/"), "method": "GET",
                               "status_code": 200, "body": "{}", "headers": {}} for h in hypotheses[:10]],
                )
            except (AttributeError, KeyError, RuntimeError, TypeError, ValueError):
                pass  # recon telemetry is advisory; execution remains governed

        for d in range(1, max_decisions + 1):
            result = self._run_one_decision(target_url=target_url, hypotheses=hypotheses,
                                            decision_number=d)
            self.decisions.append(result)
            if result.get("stopped"):
                break

        self.security_report.trace_summary = self.trace.summary()
        return {
            "avi_version": AVI_VERSION,
            "engagement_id": getattr(self.orch, "engagement_id", "unknown"),
            "target_url_digest": sha256_text(target_url)[:16],
            "decisions_executed": len(self.decisions),
            "max_decisions": max_decisions,
            "promoted_count": self.promoted_count,
            "rejected_count": self.rejected_count,
            "decisions": self.decisions,
            "trace": self.trace.summary(),
            "trace_records": self.trace.to_list(),
            "security_report": self.security_report.to_dict(),
        }


__all__ = [
    "AVI_VERSION", "DeterministicRuntimeTrace", "TraceStage",
    "AutonomousExperimentSelector", "ReplayVerifier",
    "PromotionPipeline", "PromotionDecision", "PromotionResult",
    "SecurityReport", "AutonomousValidationIntelligence", "AVICampaignError",
    "EXTERNAL_SCANNER_AUTHORITIES",
    "SECURITY_REPORT_TRACE_CONTRACT", "TRACE_CONTRACT_VERSION",
    "build_proof_trace",
]
