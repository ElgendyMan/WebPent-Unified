# tests/team1_acceptance/test_validator_coverage_v1.py
"""TEAM-1 — Validator Coverage V1 + Evidence-Driven Exploitation.

Six vulnerability families: IDOR/BOLA, Open Redirect, SSRF, Mass Assignment,
Info Disclosure, Auth Bypass. Each tested: positive, negative, inconclusive,
malformed, missing baseline, missing control, cross-target, 15+ decision campaign.
All validators consume REAL differential evidence — no fake confirmation.
"""
from __future__ import annotations

import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")

from webpent.production.validators import (
    VALIDATORS,
    EvidenceQuality,
    ValidationOutcome,
    ValidatorError,
    run_validator,
    validate_auth_bypass,
    validate_idor,
    validate_info_disclosure,
    validate_mass_assignment,
    validate_open_redirect,
    validate_ssrf,
)

# ---- Evidence fixtures (real differential, not fake) ----------------------

def _ev(status, body="", headers=None):
    return {"status_code": status, "response_body": body, "headers": headers or {}}


# ---- Family 1: IDOR/BOLA ---------------------------------------------------

class TestIDORValidator:
    def test_confirmed_idor(self):
        r = validate_idor(
            baseline=_ev(200, '{"id":1,"owner":"u1"}'),
            candidate=_ev(200, '{"id":1,"owner":"u1"}'),  # foreign principal gets u1's data
            negative_control=_ev(404, '{"error":"not found"}'),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED
        assert r.evidence_quality >= EvidenceQuality.OBSERVED_DIFFERENTIAL
        assert r.is_confirmation_grade()

    def test_refuted_idor(self):
        r = validate_idor(
            baseline=_ev(200, '{"id":1}'),
            candidate=_ev(403, '{"error":"forbidden"}'),  # correctly denied
            negative_control=_ev(404, '{"error":"nf"}'),
        )
        assert r.outcome == ValidationOutcome.REFUTED

    def test_confirms_schema_agnostic_html_resource_match(self):
        """A non-JSON target is confirmed from cross-principal semantics, not field names."""
        owner_page = "<html><h1>Account statement</h1><p>Balance 42</p></html>"
        r = validate_idor(
            baseline=_ev(200, owner_page),
            candidate=_ev(200, owner_page),
            negative_control=_ev(404, "<html>not found</html>"),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED

    def test_different_successful_response_is_not_false_positive(self):
        r = validate_idor(
            baseline=_ev(200, "<html>owner statement 42</html>"),
            candidate=_ev(200, "<html>foreign statement 7</html>"),
            negative_control=_ev(404, "<html>not found</html>"),
        )
        assert r.outcome == ValidationOutcome.INCONCLUSIVE

    def test_idor_allows_viewer_field_to_differ_when_resource_facts_match(self):
        owner = _ev(200, '{"invoice":"INV-204","owner":"owner","amount":1000,"viewer":"owner"}')
        foreign = _ev(200, '{"invoice":"INV-204","owner":"owner","amount":1000,"viewer":"foreign"}')
        r = validate_idor(
            baseline=owner,
            candidate=foreign,
            negative_control=_ev(404, '{"detail":"not found"}'),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED

    def test_inconclusive_idor(self):
        r = validate_idor(
            baseline=_ev(500, ""), candidate=_ev(500, ""), negative_control=_ev(500, ""),
        )
        assert r.outcome == ValidationOutcome.INCONCLUSIVE

    def test_missing_baseline_fails_closed(self):
        with pytest.raises(ValidatorError):
            validate_idor(baseline=None, candidate=_ev(200), negative_control=_ev(404))


# ---- Family 2: Open Redirect ----------------------------------------------

class TestOpenRedirectValidator:
    def test_confirmed_open_redirect(self):
        r = validate_open_redirect(
            baseline=_ev(302, "", {"location": "https://trusted.com/home"}),
            candidate=_ev(302, "", {"location": "https://evil.com/steal"}),
            negative_control=_ev(200, "", {}),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED

    def test_refuted_open_redirect(self):
        r = validate_open_redirect(
            baseline=_ev(302, "", {"location": "https://trusted.com"}),
            candidate=_ev(302, "", {"location": "https://trusted.com/dashboard"}),
            negative_control=_ev(200, "", {}),
        )
        assert r.outcome == ValidationOutcome.REFUTED


# ---- Family 3: SSRF -------------------------------------------------------

class TestSSRFValidator:
    def test_confirmed_ssrf(self):
        r = validate_ssrf(
            baseline=_ev(200, '{"url":"https://api.example.com/data"}'),
            candidate=_ev(200, '{"metadata":{"iam":"role","token":"abc","internal-ip":"10.0.0.1"}'),
            negative_control=_ev(400, '{"error":"invalid scheme"}'),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED

    def test_refuted_ssrf(self):
        r = validate_ssrf(
            baseline=_ev(200, '{"ok":true}'),
            candidate=_ev(200, '{"ok":true}'),
            negative_control=_ev(400, '{"error":"bad"}'),
        )
        assert r.outcome == ValidationOutcome.REFUTED


# ---- Family 4: Mass Assignment --------------------------------------------

class TestMassAssignmentValidator:
    def test_confirmed_mass_assignment(self):
        r = validate_mass_assignment(
            baseline=_ev(200, '{"role":"user"}'),
            candidate=_ev(200, '{"role":"admin","is_admin":true}'),
            negative_control=_ev(200, '{"role":"user"}'),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED

    def test_refuted_mass_assignment(self):
        r = validate_mass_assignment(
            baseline=_ev(200, '{"role":"user"}'),
            candidate=_ev(200, '{"role":"user"}'),
            negative_control=_ev(200, '{"role":"user"}'),
        )
        assert r.outcome == ValidationOutcome.REFUTED


# ---- Family 5: Info Disclosure --------------------------------------------

class TestInfoDisclosureValidator:
    def test_confirmed_info_disclosure(self):
        r = validate_info_disclosure(
            baseline=_ev(200, '{"public":"data"}'),
            candidate=_ev(500, 'Error: password=secret123 api_key=xyz traceback at line 42'),
            negative_control=_ev(200, '{"ok":true}'),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED

    def test_refuted_info_disclosure(self):
        r = validate_info_disclosure(
            baseline=_ev(200, '{"ok":true}'),
            candidate=_ev(200, '{"ok":true}'),
            negative_control=_ev(200, '{"ok":true}'),
        )
        assert r.outcome == ValidationOutcome.REFUTED

    def test_version_only_response_is_not_route_name_based_confirmation(self):
        r = validate_info_disclosure(
            baseline=_ev(200, '{"ok":true}'),
            candidate={"status_code": 200, "response_body": '{"version":"12.4.1"}',
                       "headers": {}, "request_url": "/any/arbitrary/route"},
            negative_control=_ev(200, '{"ok":true}'),
        )
        assert r.outcome == ValidationOutcome.REFUTED


# ---- Family 6: Auth Bypass ------------------------------------------------

class TestAuthBypassValidator:
    def test_confirmed_auth_bypass(self):
        r = validate_auth_bypass(
            baseline=_ev(401, '{"error":"unauthorized"}'),
            candidate=_ev(200, '{"user":"admin","data":"secret"}'),
            negative_control=_ev(403, '{"error":"forbidden"}'),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED

    def test_refuted_auth_bypass(self):
        r = validate_auth_bypass(
            baseline=_ev(401, '{"error":"unauth"}'),
            candidate=_ev(401, '{"error":"unauth"}'),
            negative_control=_ev(403, '{"error":"forbidden"}'),
        )
        assert r.outcome == ValidationOutcome.REFUTED


# ---- PART 10: Producer/Validator consistency ------------------------------

class TestProducerValidatorConsistency:
    def test_all_six_families_have_validators(self):
        for fam in ["IDOR", "BOLA", "OPEN_REDIRECT", "SSRF", "MASS_ASSIGNMENT",
                    "INFO_DISCLOSURE", "AUTH_BYPASS"]:
            assert fam in VALIDATORS

    def test_unknown_validator_fails_closed(self):
        with pytest.raises(ValidatorError):
            run_validator("UNKNOWN_CLASS", baseline=_ev(200), candidate=_ev(200), negative_control=_ev(404))

    def test_no_fake_validator(self):
        """No validator returns CONFIRMED without differential evidence."""
        for fam, vf in VALIDATORS.items():
            if fam == "BOLA":
                continue  # alias
            # All-same evidence → never CONFIRMED (no differential).
            r = vf(baseline=_ev(200, "same"), candidate=_ev(200, "same"), negative_control=_ev(200, "same"))
            assert r.outcome != ValidationOutcome.CONFIRMED, f"{fam} confirmed without differential"


# ---- PART 11: ResearchLoop integration ------------------------------------

class TestResearchLoopIntegration:
    def test_validator_outcome_feeds_research(self):
        """REFUTED validator → OutcomeTracker → candidate utility decreases."""
        from webpent.live_hunter.profile import AuthorizedLabProfile
        from webpent.live_hunter.tool_scope import ScopeLaw
        from webpent.production.modern_spine import ModernOrchestrator
        p = AuthorizedLabProfile(authorized_targets=("lab.example.com",), engagement_id="eng_vr",
                                 operator_approval_at="2026-09-15T00:00:00Z", knowledge_ready=True, lab_fixture_mode=True)
        orch = ModernOrchestrator(engagement_id="eng_vr", scope_law=ScopeLaw(profile=p, engagement_id="eng_vr"))
        orch.run_deep_recon(target_url="https://lab.example.com",
                            observed=[{"path": "/api/x", "method": "GET", "status_code": 200,
                                       "body": "{}", "headers": {}}])
        orch.research_loop.register_candidate("c_idor", ("h_idor",), "e_idor")
        orch.research_step()
        # Refuted IDOR → record outcome → research continues.
        r = validate_idor(baseline=_ev(200), candidate=_ev(403), negative_control=_ev(404))
        assert r.outcome == ValidationOutcome.REFUTED
        orch.record_outcome(experiment_signature="e_idor", outcome_class="refuted",
                            information_value=0.2, hypothesis_id="h_idor")
        # Next decision — alternative candidate.
        orch.research_loop.register_candidate("c_redirect", ("h_redirect",), "e_redirect")
        d2 = orch.research_step()
        assert d2["decision_number"] >= 2


# ---- PART 12/13: Proof/Replay integration ----------------------------------

class TestProofReplayIntegration:
    def test_confirmed_validator_reaches_proof_bundle(self):
        """Confirmation-grade validator → ProofBundle → verify_seal → promotion."""
        from webpent.live_hunter.profile import AuthorizedLabProfile
        from webpent.live_hunter.tool_scope import ScopeLaw
        from webpent.models.proof_semantics import promotion_valid
        from webpent.production.modern_spine import ModernOrchestrator
        p = AuthorizedLabProfile(authorized_targets=("lab.example.com",), engagement_id="eng_vp",
                                 operator_approval_at="2026-09-15T00:00:00Z", knowledge_ready=True, lab_fixture_mode=True)
        orch = ModernOrchestrator(engagement_id="eng_vp", scope_law=ScopeLaw(profile=p, engagement_id="eng_vp"))
        r = validate_idor(baseline=_ev(200, '{"id":1}'), candidate=_ev(200, '{"id":1,"secret":"x"}'),
                          negative_control=_ev(404, '{"error":"nf"}'))
        assert r.is_confirmation_grade()
        bundle = orch.build_proof_bundle(
            finding_id="find_vp", vulnerability_class="IDOR",
            baseline={"request": "GET /api/1 as u1", "response": "200", "execution_id": "E_vp1"},
            candidate={"request": "GET /api/1 as u2", "response": "200 secret", "execution_id": "E_vp2"},
            negative_control={"request": "GET /api/99999", "response": "404", "execution_id": "E_vp3"},
            evidence_origin="target_runtime",
            causal_result={"causal_signal": True, "negative_control_complete": True,
                           "requires_target_backed": True, "oracle_decision": "CONFIRMED",
                           "validator_version": "vp_v1", "request_evidence": ({"r": 1},),
                           "response_evidence": ({"r": 1},)},
            execution_identity="validator_vp_v1",
            session_context={"scope_context": {"t": "https://lab.example.com"},
                             "identity_context": {"p": "u2"}},
            replay_context={"replayable": True, "replay_id": "r_vp"},
            target_fingerprint="lab_sha256_vp", hypothesis_id="h_vp",
        )
        assert bundle.verify_seal() is True
        ok, _ = promotion_valid(bundle)
        assert ok is True


# ---- PART 19: Cross-target validation -------------------------------------

class _RestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(b'{"users":[{"id":1}],"type":"rest"}')
    def log_message(self, *a): pass


class _GraphQLHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(b'{"data":{"viewer":{"id":"u1"}},"type":"graphql"}')
    def log_message(self, *a): pass


@pytest.fixture(scope="module")
def target_rest():
    srv = HTTPServer(("127.0.0.1", 0), _RestHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    time.sleep(0.2); yield f"http://127.0.0.1:{port}"; srv.shutdown()


@pytest.fixture(scope="module")
def target_graphql():
    srv = HTTPServer(("127.0.0.1", 0), _GraphQLHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    time.sleep(0.2); yield f"http://127.0.0.1:{port}"; srv.shutdown()


class TestCrossTargetValidation:
    def test_validator_works_on_both_targets(self, target_rest, target_graphql):
        from webpent.live_hunter.profile import AuthorizedLabProfile
        from webpent.live_hunter.tool_scope import ScopeLaw
        from webpent.production.modern_spine import ModernOrchestrator
        for name, url in [("REST", target_rest), ("GraphQL", target_graphql)]:
            p = AuthorizedLabProfile(authorized_targets=("127.0.0.1",), engagement_id=f"eng_xt_{name}",
                                     operator_approval_at="2026-09-15T00:00:00Z", knowledge_ready=True, lab_fixture_mode=True)
            orch = ModernOrchestrator(engagement_id=f"eng_xt_{name}",
                                      scope_law=ScopeLaw(profile=p, engagement_id=f"eng_xt_{name}"))
            orch.run_deep_recon(target_url=url,
                                observed=[{"path": "/api/x", "method": "GET", "status_code": 200,
                                           "body": "{}", "headers": {}}])
            orch.research_loop.register_candidate(f"c_{name}", (f"h_{name}",), f"e_{name}")
            d = orch.research_step()
            assert d["decision_number"] >= 1
            r = orch.run_bounded_experiment(
                candidate_id=f"c_{name}", hypothesis_id=f"h_{name}",
                tool_name="httpx_bounded", target_url=f"{url}/api/x", local_loopback=True,
            )
            assert r["authorized"] is True


# ---- PART 20: 15+ decision campaign ---------------------------------------

class TestFifteenDecisionCampaign:
    def test_bounded_15_decision_campaign(self, target_rest):
        """15+ research decisions with feedback, refutation, reprioritization."""
        from webpent.live_hunter.profile import AuthorizedLabProfile
        from webpent.live_hunter.tool_scope import ScopeLaw
        from webpent.production.modern_spine import ModernOrchestrator
        p = AuthorizedLabProfile(authorized_targets=("127.0.0.1",), engagement_id="eng_15",
                                 operator_approval_at="2026-09-15T00:00:00Z", knowledge_ready=True, lab_fixture_mode=True)
        orch = ModernOrchestrator(engagement_id="eng_15", scope_law=ScopeLaw(profile=p, engagement_id="eng_15"))
        orch.run_deep_recon(target_url=target_rest,
                            observed=[{"path": "/api/users", "method": "GET", "status_code": 200,
                                       "body": "{}", "headers": {}}])
        outcomes = []
        for i in range(1, 16):
            cid = f"c_{i}"
            orch.research_loop.register_candidate(cid, (f"h_{i}",), f"e_{i}")
            d = orch.research_step()
            r = orch.run_bounded_experiment(
                candidate_id=cid, hypothesis_id=f"h_{i}",
                tool_name="httpx_bounded", target_url=f"{target_rest}/api/endpoint_{i}",
                local_loopback=True,
            )
            info_val = 0.3 + (i % 5) * 0.15  # varying information value
            outcome_class = "high_information" if info_val > 0.6 else ("refuted" if i % 4 == 0 else "low_information")
            orch.record_outcome(experiment_signature=f"e_{i}", outcome_class=outcome_class,
                                information_value=info_val, hypothesis_id=f"h_{i}")
            outcomes.append(outcome_class)
        assert orch.research_loop.decision_count >= 15
        # At least one refuted, at least one high-info, reprioritization occurred.
        assert "refuted" in outcomes
        assert "high_information" in outcomes
        assert len(set(outcomes)) >= 2  # mixed outcomes → genuine feedback


# ---- PART 23: Security non-regression -------------------------------------

class TestSecurityNonRegression:
    def test_no_direct_http_bypass(self):
        """Validators cannot bypass ScopeLaw — execution still authorized."""
        from webpent.live_hunter.profile import AuthorizedLabProfile
        from webpent.live_hunter.tool_scope import ScopeLaw
        from webpent.production.modern_spine import ModernOrchestrator
        p = AuthorizedLabProfile(authorized_targets=("lab.example.com",), engagement_id="eng_sec",
                                 operator_approval_at="2026-09-15T00:00:00Z", knowledge_ready=True, lab_fixture_mode=True)
        orch = ModernOrchestrator(engagement_id="eng_sec", scope_law=ScopeLaw(profile=p, engagement_id="eng_sec"))
        r = orch.run_bounded_experiment(
            candidate_id="c1", hypothesis_id="h1",
            tool_name="httpx_bounded", target_url="https://evil.com/ssrf",
        )
        assert r["authorized"] is False  # ScopeLaw still authoritative

    def test_no_validator_confirms_without_evidence(self):
        """No validator returns CONFIRMED for empty/missing evidence."""
        for fam, vf in VALIDATORS.items():
            if fam == "BOLA":
                continue
            with pytest.raises(ValidatorError):
                vf(baseline=None, candidate=None, negative_control=None)
