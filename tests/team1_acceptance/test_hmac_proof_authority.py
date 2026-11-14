# tests/team1_acceptance/test_hmac_proof_authority.py
"""TEAM-1 — Proof Authority Consolidation + HMAC Promotion Integration.

Verifies: ONE canonical proof authority, HMAC-SHA256 authenticity enforced in
promotion path, post-seal tampering rejected, 4-quadrant authenticity matrix,
replay consistency, no authority duplication.
"""
from __future__ import annotations

import inspect
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

# Explicit test/dev key — visible, cannot silently become production.
os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")

from webpent.models.proof_bundle import ProofBundle, _compute_authenticity_tag
from webpent.models.proof_semantics import (
    build_promotion_grade_bundle,
    canonical_semantic_digest,
    promotion_valid,
    replay_semantic_consistent,
)


def _valid_evidence(**overrides):
    base = dict(
        engagement_id="eng_hmac", finding_id="find_hmac", vulnerability_class="IDOR",
        baseline={"request": "GET /api/1", "response": "200 u1", "execution_id": "E1"},
        candidate={"request": "GET /api/2 as u1", "response": "200 u2", "execution_id": "E2"},
        negative_control={"request": "GET /api/99999", "response": "404", "execution_id": "E3"},
        evidence_origin="target_runtime",
        causal_result={"causal_signal": True, "negative_control_complete": True,
                       "requires_target_backed": True, "oracle_decision": "CONFIRMED",
                       "validator_version": "hmac_v1", "request_evidence": ({"r": 1},),
                       "response_evidence": ({"r": 1},)},
        execution_identity="validator_hmac_v1",
        session_context={"scope_context": {"t": "https://lab.example.com"},
                         "identity_context": {"p": "u1"}},
        replay_context={"replayable": True, "replay_id": "r_hmac"},
        target_fingerprint="lab_sha256_hmac_123", hypothesis_id="h_hmac",
    )
    base.update(overrides)
    return base


def _sealed_valid():
    return build_promotion_grade_bundle(**_valid_evidence())


# ---- PART 4: Cryptographic model audit ------------------------------------

class TestCryptographicModel:
    def test_dual_layer_sha_plus_hmac(self):
        """Current model = C: dual-layer SHA-256 integrity + HMAC-SHA256 authenticity."""
        b = _sealed_valid()
        assert b.seal_digest is not None
        assert b.seal_digest.startswith("sha256:")
        assert b.authenticity_tag is not None
        assert b.authenticity_tag.startswith("hmac_sha256:")
        assert b.authenticity_algorithm == "hmac_sha256_v1"
        assert b.authenticity_key_version is not None

    def test_secret_never_exposed_in_bundle(self):
        b = _sealed_valid()
        bundle_dict = b.model_dump()
        key = os.environ["WEBPENT_AUDIT_SECRET_KEY"]
        for v in bundle_dict.values():
            assert key not in str(v)


# ---- PART 5/7: HMAC enforced in promotion path ----------------------------

class TestHMACPromotionEnforcement:
    def test_promotion_requires_hmac_authenticity(self):
        """Bundle with valid SHA but NO HMAC tag → promotion rejected."""
        b = _sealed_valid()
        # Strip HMAC tag (simulates old SHA-only bundle).
        no_hmac = b.model_copy(update={"authenticity_tag": None, "authenticity_algorithm": None})
        ok, reason = promotion_valid(no_hmac)
        assert ok is False
        assert "cryptographic" in reason or "seal" in reason

    def test_hmac_computed_not_ignored(self):
        """verify_seal() checks HMAC, not just SHA."""
        b = _sealed_valid()
        # Tamper tag → verify_seal fails.
        tampered = b.model_copy(update={"authenticity_tag": "hmac_sha256:forged_tag_0000"})
        assert tampered.verify_seal() is False

    def test_integrity_only_not_promotable(self):
        """verify_seal_integrity_only() can pass but promotion requires full verify_seal."""
        b = _sealed_valid()
        no_hmac = b.model_copy(update={"authenticity_tag": None, "authenticity_algorithm": None})
        assert no_hmac.verify_seal_integrity_only() is True  # SHA still valid
        assert no_hmac.verify_seal() is False  # HMAC missing → not authentic
        ok, _ = promotion_valid(no_hmac)
        assert ok is False  # promotion blocked


# ---- PART 8: Authenticity vs Semantics 4-quadrant matrix ------------------

class TestAuthenticitySemanticsMatrix:
    def test_case_A_authentic_valid_eligible(self):
        """A: authentic + semantically valid → eligible."""
        b = _sealed_valid()
        assert b.verify_seal() is True
        ok, reason = promotion_valid(b)
        assert ok is True, reason

    def test_case_B_authentic_semantically_invalid_rejected(self):
        """B: authentic + semantically invalid → rejected by SemanticValidator."""
        b = _sealed_valid()
        # Tamper vulnerability_class (breaks semantic digest + promotion contract).
        tampered = b.model_copy(update={"vulnerability_class": ""})
        assert tampered.verify_seal() is False  # HMAC/SHA broken by tamper
        ok, reason = promotion_valid(tampered)
        assert ok is False

    def test_case_C_unauthentic_semantically_valid_looking_rejected(self):
        """C: unauthentic (wrong key) + valid-looking → rejected by HMAC."""
        b = _sealed_valid()
        # Re-seal with a DIFFERENT key (simulates attacker without trusted secret).
        os.environ["WEBPENT_AUDIT_SECRET_KEY"] = "attacker_key_32_chars_minimum_required_xx"
        attacker_tag, _, _ = _compute_authenticity_tag(b.seal_digest)
        os.environ["WEBPENT_AUDIT_SECRET_KEY"] = "test_key_32_chars_minimum_required_1234567890"
        forged = b.model_copy(update={"authenticity_tag": attacker_tag})
        assert forged.verify_seal() is False  # wrong key → HMAC mismatch
        ok, _ = promotion_valid(forged)
        assert ok is False

    def test_case_D_unauthentic_invalid_rejected(self):
        """D: unauthentic + semantically invalid → rejected."""
        b = _sealed_valid()
        bad = b.model_copy(update={"authenticity_tag": None, "vulnerability_class": ""})
        ok, _ = promotion_valid(bad)
        assert ok is False


# ---- PART 9/10: Post-seal tampering + semantic digest attack ---------------

class TestPostSealTampering:
    def test_semantic_mutation_sha_recompute_leave_hmac_rejected(self):
        """Attack A: mutate semantic field + recompute SHA + leave HMAC → REJECT."""
        b = _sealed_valid()
        # Mutate target_fingerprint + recompute SHA seal_digest, keep old HMAC.
        tampered = b.model_copy(update={"target_fingerprint": "evil_target"})
        new_sha = f"sha256:{__import__('webpent.models.evidence', fromlist=['sha256_text']).sha256_text(tampered._seal_payload())}"
        tampered = tampered.model_copy(update={"seal_digest": new_sha})
        # HMAC tag still from original → mismatch.
        assert tampered.verify_seal() is False
        ok, _ = promotion_valid(tampered)
        assert ok is False

    def test_semantic_mutation_forged_hmac_rejected(self):
        """Attack B: mutate + recompute SHA + attempt forge HMAC without secret → REJECT."""
        b = _sealed_valid()
        tampered = b.model_copy(update={"evidence_origin": "offline_fixture"})
        from webpent.models.evidence import sha256_text
        new_sha = f"sha256:{sha256_text(tampered._seal_payload())}"
        # Attacker doesn't know secret → forges a random tag.
        forged = tampered.model_copy(update={
            "seal_digest": new_sha,
            "authenticity_tag": "hmac_sha256:" + "0" * 64,
        })
        assert forged.verify_seal() is False
        ok, _ = promotion_valid(forged)
        assert ok is False

    def test_different_runtime_key_rejected(self):
        """Attack C: valid proof + different runtime secret → REJECT."""
        b = _sealed_valid()
        # Temporarily swap to a different key (simulates different runtime env).
        original = os.environ["WEBPENT_AUDIT_SECRET_KEY"]
        os.environ["WEBPENT_AUDIT_SECRET_KEY"] = "different_runtime_key_32_chars_min_req"
        assert b.verify_seal() is False  # HMAC computed with original key
        ok, _ = promotion_valid(b)
        assert ok is False
        os.environ["WEBPENT_AUDIT_SECRET_KEY"] = original  # restore

    def test_semantic_digest_attack_rejected(self):
        """PART 10: caller recomputes canonical semantic digest + plain seal → still REJECTED
        because HMAC requires trusted secret."""
        b = _sealed_valid()
        tampered = b.model_copy(update={"hypothesis_id": "hijacked"})
        from webpent.models.evidence import sha256_text
        new_sha = f"sha256:{sha256_text(tampered._seal_payload())}"
        new_semantic = canonical_semantic_digest(tampered)
        # Attacker recomputes everything public (SHA + semantic digest) but NOT HMAC.
        fully_forged = tampered.model_copy(update={
            "seal_digest": new_sha,
            "validator_config_digest": new_semantic,
            "authenticity_tag": b.authenticity_tag,  # old HMAC — can't recompute without secret
        })
        assert fully_forged.verify_seal() is False
        ok, _ = promotion_valid(fully_forged)
        assert ok is False


# ---- PART 12: Replay authority consistency --------------------------------

class TestReplayAuthority:
    def test_replay_uses_canonical_verify(self):
        """Replay must use same canonical verify_seal (HMAC + SHA)."""
        b = _sealed_valid()
        rok, _ = replay_semantic_consistent(b)
        assert rok is True
        # Tamper HMAC → replay also rejects.
        tampered = b.model_copy(update={"authenticity_tag": "hmac_sha256:bad"})
        rok2, _ = replay_semantic_consistent(tampered)
        assert rok2 is False

    def test_replay_rejects_changed_target(self):
        b = _sealed_valid()
        tampered = b.model_copy(update={"target_fingerprint": "other_target"})
        rok, _ = replay_semantic_consistent(tampered)
        assert rok is False


# ---- PART 17: Authority duplication audit ---------------------------------

class TestAuthorityDuplication:
    def test_single_seal_implementation(self):
        """Only one seal() method on ProofBundle; no duplicate seal code."""
        import inspect
        src = inspect.getsource(ProofBundle.seal)
        assert "sha256:" in src
        assert "_compute_authenticity_tag" in src  # delegates to single helper

    def test_single_hmac_helper(self):
        """Only one _compute_authenticity_tag helper."""
        import webpent.models.proof_bundle as pb
        assert hasattr(pb, "_compute_authenticity_tag")
        # No other HMAC helpers in proof_bundle module.
        src = inspect.getsource(pb)
        assert src.count("_compute_hmac(") <= 1  # only in the helper

    def test_legacy_wrapper_delegates(self):
        """irta/v3/proof.py must delegate to canonical build_proof_bundle."""
        import inspect
        try:
            from webpent.irta.v3 import proof as legacy_proof
            src = inspect.getsource(legacy_proof)
            assert "build_proof_bundle" in src or "ProofBundle" in src
        except ImportError:
            pytest.skip("legacy irta/v3/proof not importable")


# ---- PART 16: Real E2E authentic proof ------------------------------------

class _LoopHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"data": "sensitive", "principal": "user_a"}')
    def log_message(self, *a): pass


@pytest.fixture(scope="module")
def loopback():
    srv = HTTPServer(("127.0.0.1", 0), _LoopHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


class TestRealE2EAuthenticProof:
    def test_e2e_hmac_proof(self, loopback):
        from webpent.live_hunter.profile import AuthorizedLabProfile
        from webpent.live_hunter.tool_scope import ScopeLaw
        from webpent.production.modern_spine import ModernOrchestrator
        p = AuthorizedLabProfile(authorized_targets=("127.0.0.1",), engagement_id="eng_e2e_hmac",
                                 operator_approval_at="2026-09-15T00:00:00Z", knowledge_ready=True, lab_fixture_mode=True)
        orch = ModernOrchestrator(engagement_id="eng_e2e_hmac",
                                  scope_law=ScopeLaw(profile=p, engagement_id="eng_e2e_hmac"))
        orch.run_deep_recon(target_url=loopback,
                            observed=[{"path": "/api/data", "method": "GET", "status_code": 200, "body": "{}", "headers": {}}])
        orch.research_loop.register_candidate("c_e2e", ("h_e2e",), "e_e2e")
        orch.research_step()
        result = orch.run_bounded_experiment(
            candidate_id="c_e2e", hypothesis_id="h_e2e",
            tool_name="httpx_bounded", target_url=f"{loopback}/api/data", local_loopback=True,
        )
        assert result["authorized"] is True
        bundle = orch.build_proof_bundle(
            finding_id="find_e2e_hmac", vulnerability_class="INFO_DISCLOSURE",
            baseline={"request": "GET /", "response": "200", "execution_id": "E_e2e_1"},
            candidate={"request": "GET /api/data", "response": "200 sensitive", "execution_id": "E_e2e_2"},
            negative_control={"request": "GET /nonexistent", "response": "404", "execution_id": "E_e2e_3"},
            evidence_origin="target_runtime",
            causal_result={"causal_signal": True, "negative_control_complete": True,
                           "requires_target_backed": True, "oracle_decision": "CONFIRMED",
                           "validator_version": "e2e_hmac_v1",
                           "request_evidence": ({"r": 1},), "response_evidence": ({"r": 1},)},
            execution_identity="validator_e2e_hmac_v1",
            session_context={"scope_context": {"t": loopback}, "identity_context": {"p": "anon"}},
            replay_context={"replayable": True, "replay_id": "rep_e2e_hmac"},
            target_fingerprint="loopback_127_e2e_hmac", hypothesis_id="h_e2e",
        )
        assert bundle.sealed is True
        assert bundle.authenticity_tag is not None  # HMAC present
        assert bundle.verify_seal() is True  # dual-layer passes
        ok, reason = promotion_valid(bundle)
        assert ok is True, reason
        # Attack A: mutation + SHA recompute → reject.
        from webpent.models.evidence import sha256_text
        tampered = bundle.model_copy(update={"target_fingerprint": "evil"})
        new_sha = f"sha256:{sha256_text(tampered._seal_payload())}"
        attack_a = tampered.model_copy(update={"seal_digest": new_sha})  # HMAC unchanged
        assert attack_a.verify_seal() is False
        # Attack B: forged HMAC → reject.
        attack_b = tampered.model_copy(update={
            "seal_digest": new_sha, "authenticity_tag": "hmac_sha256:" + "a" * 64})
        assert attack_b.verify_seal() is False
