# tests/test_umdr35_confirmation_authority.py
"""UM-DR-35 — Gate 35-A / 35-B security regression tests.

Gate 35-A (Confirmation Authority):
  * Promotion is impossible without a genuine TYPED CausalGuard result
    (isinstance-checked) with verdict CONFIRMED — a forged authority
    STRING, a lookalike object, an LLM confidence score, an external
    scanner claim, or a validator label alone can never promote.
  * The specialized validator's CONFIRMED is downgraded to INCONCLUSIVE
    when the CausalGuard adjudication does not confirm.
  * CausalGuard experiment adjudication fails closed on synthetic
    evidence, wrong provenance, unknown families, contaminated negative
    controls, and candidate==control collisions.
  * A validator label passed as evidence is never obeyed (advisory only).

Gate 35-B (Proof Integrity / Replay):
  * AVI ReplayVerifier fails closed when the ORIGINAL CausalGuard result
    is absent, when the replayed guard verdict diverges, when evidence
    (baseline / candidate / negative control) is mutated, and when the
    sealed bundle is tampered with.
  * cqa_v2 verify_replay enforces the strict contract (seal_match and
    replay_executed included) — a mutated bundle or evidence never
    verifies.
"""
from __future__ import annotations

import copy
import os
from types import SimpleNamespace

import pytest

os.environ.setdefault(
    "WEBPENT_AUDIT_SECRET_KEY", "umdr35_test_key_32_chars_min_1234567890"
)

from tests.lab.idor_lab_target import start_lab_server


@pytest.fixture(autouse=True)
def _allow_lab_loopback():
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )
    token = set_engagement_target_hosts("127.0.0.1", "localhost")
    yield
    clear_engagement_target_hosts(token)


def _make_orchestrator(engagement_id: str):
    from webpent.live_hunter.profile import AuthorizedLabProfile
    from webpent.live_hunter.tool_scope import ScopeLaw
    from webpent.production.modern_spine import ModernOrchestrator
    profile = AuthorizedLabProfile(
        authorized_targets=("127.0.0.1", "localhost"),
        engagement_id=engagement_id,
        operator_approval_at="2026-09-15T00:00:00Z",
        knowledge_ready=True, lab_fixture_mode=True,
    )
    return ModernOrchestrator(
        engagement_id=engagement_id,
        scope_law=ScopeLaw(profile=profile, engagement_id=engagement_id),
    )


def _seal_lab_principals(engagement_id: str, target_url: str):
    from webpent.models.evidence import sha256_text
    from webpent.production.context_authority import ContextAuthority
    authority = ContextAuthority(
        engagement_id=engagement_id,
        target_fingerprint=sha256_text(target_url)[:16],
    )
    authority.seal_principal_credentials(
        principal_alias="User_B", role="owner", password="password_b")
    authority.seal_principal_credentials(
        principal_alias="User_A", role="foreign-user", password="password_a")


def _idor_hypothesis(hid: str, target_url: str, *,
                     negative_control_invoice: str = "INV-NO-SUCH-999"):
    def _spec(actor, invoice, role_name):
        return {
            "method": "GET",
            "path": f"/api/invoices/{invoice}",
            "headers": {"X-User": actor},
            "principal_alias": actor,
            "principal_role": role_name,
        }
    return {
        "id": hid,
        "vulnerability_class": "IDOR",
        "api_type": "rest",
        "path": "/api/invoices/",
        "information_value": 0.9,
        "resource_owner": "User_B",
        "engagement_id": "umdr35_eng",
        "requests": {
            "baseline": _spec("User_B", "INV-B-204", "owner"),
            "candidate": _spec("User_A", "INV-B-204", "foreign-user"),
            "negative_control": _spec("User_A", negative_control_invoice, "foreign-user"),
        },
    }


def _run_one(orch, target_url, hyp):
    from webpent.production.autonomous_validation_v1 import (
        AutonomousValidationIntelligence,
    )
    avi = AutonomousValidationIntelligence(orch)
    result = avi._run_one_decision(
        target_url=target_url, hypotheses=[hyp], decision_number=1)
    return avi, result


@pytest.fixture(scope="module")
def vulnerable_target():
    server, url = start_lab_server(vulnerable=True)
    yield url
    server.should_exit = True


# ---------------------------------------------------------------------------
# Gate 35-A — CausalGuard is the sole confirmation authority
# ---------------------------------------------------------------------------

class TestForgedAuthorityCannotPromote:
    """A forged authority string/label can never authorize promotion."""

    def _base_eval(self, **overrides):
        from webpent.production.autonomous_validation_v1 import PromotionPipeline
        kwargs = {
            "baseline_obs": None, "candidate_obs": None, "negative_control_obs": None,
            "evidence_origin": "target_runtime",
            "validator_outcome": "CONFIRMED",
            "evidence_quality": 5,
            "proof_bundle": None,
            "replay_verified": True,
            "verdict_authority": "CausalGuard_deterministic_engine",
            "confidence_score": 0.99,
            "finding_id": "finding_forged",
            "vulnerability_class": "IDOR",
        }
        kwargs.update(overrides)
        return PromotionPipeline().evaluate(**kwargs)

    def test_forged_authority_string_alone_is_rejected(self):
        pr = self._base_eval()  # no causalguard_result at all
        assert pr.decision.value == "REJECTED"
        assert "causalguard_adjudicated" in pr.gates_failed

    def test_lookalike_object_is_rejected(self):
        # A SimpleNamespace mimicking GuardedCausalResult with CONFIRMED —
        # structurally NOT the typed authority result.
        forged = SimpleNamespace(verdict="CONFIRMED", causal_signal=True, confidence=0.99)
        pr = self._base_eval(causalguard_result=forged)
        assert pr.decision.value == "REJECTED"
        assert "causalguard_adjudicated" in pr.gates_failed

    def test_forged_string_result_is_rejected(self):
        pr = self._base_eval(causalguard_result="CONFIRMED")
        assert pr.decision.value == "REJECTED"
        assert "causalguard_adjudicated" in pr.gates_failed

    def test_llm_confidence_cannot_manufacture_confirmation(self):
        # LLM-style verdict string + max confidence, no typed guard result.
        pr = self._base_eval(
            validator_outcome="CONFIRMED",
            verdict_authority="llm_verdict",
            confidence_score=0.999999,
        )
        assert pr.decision.value == "REJECTED"
        assert "causalguard_adjudicated" in pr.gates_failed
        assert "no_external_scanner_authority" in pr.gates_failed

    def test_external_scanner_claim_cannot_promote(self):
        pr = self._base_eval(verdict_authority="nuclei")
        assert pr.decision.value == "REJECTED"
        assert "no_external_scanner_authority" in pr.gates_failed
        assert "causalguard_adjudicated" in pr.gates_failed


class TestCausalGuardFailsClosed:
    """The experiment-level authority fails closed on unusable evidence."""

    def _evidence(self, **overrides):
        from webpent.cqa_v2.causal_guard import ExperimentCausalEvidence
        base = {
            "vulnerability_family": "SSRF",
            "experiment_id": "exp_test_1",
            "baseline": {"status_code": 200, "response_body": "ok",
                         "real_http": True, "request_url": "https://t.example/a",
                         "request_digest": "d1"},
            "candidate": {"status_code": 200, "response_body": "metadata iam",
                          "real_http": True, "request_url": "https://t.example/b",
                          "request_digest": "d2"},
            "negative_control": {"status_code": 400, "response_body": "bad scheme",
                                 "real_http": True, "request_url": "https://t.example/c",
                                 "request_digest": "d3"},
            "technical_signal": {"baseline": False, "candidate": True,
                                 "negative_control": False},
        }
        base.update(overrides)
        return ExperimentCausalEvidence(**base)

    def test_synthetic_observation_is_blocked(self):
        from webpent.cqa_v2.causal_guard import (
            Verdict,
            guarded_causal_evaluate_experiment,
        )
        ev = self._evidence(candidate={"status_code": 200, "real_http": False})
        res = guarded_causal_evaluate_experiment(ev)
        assert res.verdict is Verdict.BLOCKED
        assert "candidate_observation_synthetic" in (res.block_reason or "")

    def test_wrong_evidence_origin_is_blocked(self):
        from webpent.cqa_v2.causal_guard import (
            Verdict,
            guarded_causal_evaluate_experiment,
        )
        ev = self._evidence(evidence_origin="offline_fixture")
        res = guarded_causal_evaluate_experiment(ev)
        assert res.verdict is Verdict.BLOCKED

    def test_unknown_family_is_blocked(self):
        from webpent.cqa_v2.causal_guard import (
            Verdict,
            guarded_causal_evaluate_experiment,
        )
        ev = self._evidence(vulnerability_family="TOTALLY_UNKNOWN")
        res = guarded_causal_evaluate_experiment(ev)
        assert res.verdict is Verdict.BLOCKED

    def test_contaminated_control_is_blocked(self):
        from webpent.cqa_v2.causal_guard import (
            Verdict,
            guarded_causal_evaluate_experiment,
        )
        ev = self._evidence(
            technical_signal={"baseline": False, "candidate": True,
                              "negative_control": True})
        res = guarded_causal_evaluate_experiment(ev)
        assert res.verdict is Verdict.BLOCKED
        assert "contaminated" in (res.block_reason or "")

    def test_control_identical_to_candidate_is_blocked(self):
        from webpent.cqa_v2.causal_guard import (
            Verdict,
            guarded_causal_evaluate_experiment,
        )
        cand = self._evidence().candidate
        ev = self._evidence(negative_control=cand)
        res = guarded_causal_evaluate_experiment(ev)
        assert res.verdict is Verdict.BLOCKED

    def test_clean_technical_triple_is_clean_not_confirmed(self):
        from webpent.cqa_v2.causal_guard import (
            Verdict,
            guarded_causal_evaluate_experiment,
        )
        ev = self._evidence(
            technical_signal={"baseline": False, "candidate": False,
                              "negative_control": False})
        res = guarded_causal_evaluate_experiment(ev)
        assert res.verdict is Verdict.CLEAN

    def test_validator_label_is_advisory_only(self):
        from webpent.cqa_v2.causal_guard import (
            Verdict,
            guarded_causal_evaluate_experiment,
        )
        # Validator claims CONFIRMED but no candidate signal exists ->
        # the authority still says CLEAN. The label is never obeyed.
        ev = self._evidence(
            technical_signal={"baseline": False, "candidate": False,
                              "negative_control": False},
            validator_outcome="CONFIRMED")
        res = guarded_causal_evaluate_experiment(ev)
        assert res.verdict is Verdict.CLEAN
        assert res.confidence_factors.get("validator_label_advisory") == 1.0

    def test_signal_differential_confirms(self):
        from webpent.cqa_v2.causal_guard import (
            Verdict,
            guarded_causal_evaluate_experiment,
        )
        ev = self._evidence()
        res = guarded_causal_evaluate_experiment(ev)
        assert res.verdict is Verdict.CONFIRMED
        assert res.causal_signal is True


class TestAVIPromotionRequiresRealCausalGuard:
    """On the real lab target: promotion happens ONLY with the real guard."""

    def test_promoted_finding_carries_causalguard_verdict(self, vulnerable_target):
        orch = _make_orchestrator("umdr35_pos")
        _seal_lab_principals("umdr35_pos", vulnerable_target)
        hyp = _idor_hypothesis("umdr35_h1", vulnerable_target)
        avi, result = _run_one(orch, vulnerable_target, hyp)
        stages = {s.stage: s.proof for s in avi.trace.stages}
        assert stages["causalguard_adjudication"]["authority"] == (
            "cqa_v2.guarded_causal_evaluate")
        assert stages["causalguard_adjudication"]["verdict"] == "CONFIRMED"
        promo = stages["promotion_decision"]
        assert promo["decision"] == "PROMOTED", promo.get("reason")
        assert "causalguard_adjudicated" in promo["gates_passed"]
        promoted = avi.security_report.promoted_findings[0]
        assert promoted["causalguard_verdict"] == "CONFIRMED"
        assert promoted["causalguard_authority"] == "cqa_v2.guarded_causal_evaluate"
        # The sealed ProofBundle carries the authority verdict.
        co = stages.get("proof_created", {})
        assert co.get("sealed") is True

    def test_forged_guard_result_blocks_promotion(self, vulnerable_target,
                                                  monkeypatch):
        # Forge the adapter to return a lookalike object: the pipeline must
        # reject structurally, even with everything else genuine.
        import webpent.production.autonomous_validation_v1 as avi_mod
        orch = _make_orchestrator("umdr35_forge")
        _seal_lab_principals("umdr35_forge", vulnerable_target)
        hyp = _idor_hypothesis("umdr35_h2", vulnerable_target)
        forged = SimpleNamespace(verdict="CONFIRMED", causal_signal=True,
                                 confidence=1.0, block_reason=None)
        monkeypatch.setattr(avi_mod, "_causalguard_adjudicate",
                            lambda evidence: forged)
        avi, result = _run_one(orch, vulnerable_target, hyp)
        stages = {s.stage: s.proof for s in avi.trace.stages}
        promo = stages["promotion_decision"]
        assert promo["decision"] == "REJECTED"
        assert "causalguard_adjudicated" in promo["gates_failed"]
        assert avi.promoted_count == 0

    def test_guard_not_confirmed_downgrades_validator(self, vulnerable_target,
                                                      monkeypatch):
        # Validator CONFIRMED + guard CLEAN => INCONCLUSIVE, never promoted.
        import webpent.production.autonomous_validation_v1 as avi_mod
        from webpent.cqa_v2.causal_guard import GuardedCausalResult, Verdict
        orch = _make_orchestrator("umdr35_downgrade")
        _seal_lab_principals("umdr35_downgrade", vulnerable_target)
        hyp = _idor_hypothesis("umdr35_h3", vulnerable_target)
        clean = GuardedCausalResult(
            verdict=Verdict.CLEAN, causal_signal=False, confidence=0.9,
            raw_decision="CLEAN")
        monkeypatch.setattr(avi_mod, "_causalguard_adjudicate",
                            lambda evidence: clean)
        avi, result = _run_one(orch, vulnerable_target, hyp)
        stages = {s.stage: s.proof for s in avi.trace.stages}
        assert stages["validator_adapter_executed"]["outcome"] == "CONFIRMED"
        # After stage 6c the outcome the pipeline sees is INCONCLUSIVE.
        assert stages["causalguard_adjudication"]["verdict"] == "CLEAN"
        promo = stages["promotion_decision"]
        assert promo["decision"] == "REJECTED"
        assert avi.promoted_count == 0


# ---------------------------------------------------------------------------
# Gate 35-B — replay verification integrity
# ---------------------------------------------------------------------------

class TestReplayVerifierFailsClosed:
    """AVI ReplayVerifier: every mutation breaks replay_verified."""

    def _original_triple(self, vulnerable_target):
        orch = _make_orchestrator("umdr35_replay")
        _seal_lab_principals("umdr35_replay", vulnerable_target)
        hyp = _idor_hypothesis("umdr35_hr", vulnerable_target)
        avi, _ = _run_one(orch, vulnerable_target, hyp)
        stages = {s.stage: s.proof for s in avi.trace.stages}
        assert stages["promotion_decision"]["decision"] == "PROMOTED"
        return avi, stages

    def _verify_with(self, avi, *, mutate=None, drop_guard=False):
        {s.stage: s.proof for s in avi.trace.stages}
        # Re-extract the raw triple from the real-execution trace is not
        # possible (bodies are redacted); instead re-run the verify step via
        # the AVI internal contract: re-derive from the recorded digests and
        # the replay component using the SAME hypotheses and mutated copies
        # of the recorded raw triple stored on the AVI instance.
        raw = copy.deepcopy(avi._last_raw_triple)
        guard = None if drop_guard else copy.deepcopy(avi._last_causalguard_result)
        if mutate:
            mutate(raw)
        return avi.replay_verifier.verify(
            experiment_id="exp_idor_v1",
            baseline_raw=raw["baseline"],
            candidate_raw=raw["candidate"],
            negative_control_raw=raw["negative_control"],
            vulnerability_class="IDOR",
            expected_outcome=avi._last_validator_outcome,
            expected_baseline_digest=avi._last_digests["baseline"],
            expected_candidate_digest=avi._last_digests["candidate"],
            expected_negative_control_digest=avi._last_digests["negative_control"],
            proof_bundle=avi._last_proof_bundle,
            hypothesis=avi._last_hypothesis,
            identity_binding=avi._last_identity_binding,
            causalguard_result=guard,
        )

    def test_baseline_mutation_fails_replay(self, vulnerable_target):
        avi, _ = self._original_triple(vulnerable_target)
        def mutate(raw):
            raw["baseline"]["response_body"] = "tampered baseline body"
        res = self._verify_with(avi, mutate=mutate)
        assert res["replay_verified"] is False

    def test_candidate_mutation_fails_replay(self, vulnerable_target):
        avi, _ = self._original_triple(vulnerable_target)
        def mutate(raw):
            raw["candidate"]["status_code"] = 403
        res = self._verify_with(avi, mutate=mutate)
        assert res["replay_verified"] is False

    def test_negative_control_mutation_fails_replay(self, vulnerable_target):
        avi, _ = self._original_triple(vulnerable_target)
        def mutate(raw):
            raw["negative_control"]["status_code"] = 200
            raw["negative_control"]["response_body"] = "leaked control body"
        res = self._verify_with(avi, mutate=mutate)
        assert res["replay_verified"] is False

    def test_missing_original_causalguard_result_fails_replay(self,
                                                              vulnerable_target):
        avi, _ = self._original_triple(vulnerable_target)
        res = self._verify_with(avi, drop_guard=True)
        assert res["replay_verified"] is False
        assert res["causalguard_match"] is False

    def test_tampered_bundle_fails_replay(self, vulnerable_target):
        avi, _ = self._original_triple(vulnerable_target)
        bundle = avi._last_proof_bundle
        # A bundle whose seal cannot verify -> seal_ok False.
        object.__setattr__(bundle, "sealed", False)
        res = self._verify_with(avi)
        assert res["replay_verified"] is False
        assert res["seal_verified"] is False


class TestCqaV2StrictReplay:
    """cqa_v2.verify_replay enforces the strict contract."""

    def _bundle(self):
        from webpent.cqa_v2.causal_guard import guarded_causal_evaluate
        from webpent.cqa_v2.proof_bundle_builder import build_complete_proof_bundle
        baseline = {"status_code": 200, "semantic_digest": "sha256:" + "a" * 64,
                    "headers": {"X-Actor-Echo": "u1"}, "request": {"path": "/api/x/1"}}
        candidate = {"status_code": 200, "semantic_digest": "sha256:" + "b" * 64,
                     "headers": {"X-Actor-Echo": "u1", "X-Resource-Owner": "u2",
                                 "X-Resource-Type": "invoice"},
                     "request": {"path": "/api/x/2"}}
        control = {"status_code": 403, "semantic_digest": "sha256:" + "c" * 64,
                   "headers": {"X-Actor-Echo": "u1"}, "request": {"path": "/api/x/1"}}
        causal = guarded_causal_evaluate(
            baseline=baseline, candidate=candidate, control=control)
        return build_complete_proof_bundle(
            target_identity="https://t.example",
            case_identity="case_umdr35_1",
            baseline=baseline,
            candidate=candidate,
            negative_control=control,
            causal_result=causal,
            semantic_evidence={"precondition": "read_only_no_state_mutation"},
            source_provenance={"origin": "target_runtime"},
            runtime_provenance={"executed": True},
        )

    def test_strict_replay_includes_seal_match(self):
        from webpent.cqa_v2.replay_verifier import verify_replay
        bundle = self._bundle()
        result = verify_replay(bundle)
        assert result.replay_valid == result.replay_verified
        assert result.replay_verified is True

    def test_mutated_evidence_fails(self):
        from webpent.cqa_v2.replay_verifier import verify_replay
        bundle = self._bundle()
        # Mutate the candidate observation AFTER sealing: the deterministic
        # seal no longer matches the evidence, so verify_seal() fails and
        # the strict replay contract rejects the bundle.
        object.__setattr__(bundle, "candidate_observation",
                           dict(bundle.candidate_observation,
                                semantic_digest="sha256:" + "z" * 64))
        result = verify_replay(bundle)
        assert result.replay_verified is False
        assert result.seal_valid is False

    def test_mutated_causal_result_fails(self):
        from webpent.cqa_v2.replay_verifier import verify_replay
        bundle = self._bundle()
        co = dict(bundle.causal_result)
        co["verdict"] = "CLEAN" if co.get("verdict") != "CLEAN" else "CONFIRMED"
        object.__setattr__(bundle, "causal_result", co)
        result = verify_replay(bundle)
        assert result.replay_verified is False

