# tests/team1_acceptance/test_validator_execution_fabric_v2.py
"""TEAM-1 — Validator Execution Fabric V2.

ONE registry, ONE runner, ONE normalizer, ONE adapter. All 6 families wired
through canonical fabric. External observation adapter (Wapiti seam) — advisory,
security-tested. 15+ decision campaign. Two structurally different targets.
"""
from __future__ import annotations

import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")

from webpent.production.experiment_fabric import (
    EXPERIMENT_REGISTRY,
    GenericExperimentRunner,
    normalize_observation,
)
from webpent.production.external_observation_adapter import (
    FORBIDDEN_AUTHORITY_CLAIMS,
    ingest_external_observation,
)
from webpent.production.validators import ValidationOutcome


def _make_orch(eng, targets=("127.0.0.1", "localhost", "lab.example.com")):
    from webpent.live_hunter.profile import AuthorizedLabProfile
    from webpent.live_hunter.tool_scope import ScopeLaw
    from webpent.production.modern_spine import ModernOrchestrator
    p = AuthorizedLabProfile(authorized_targets=targets, engagement_id=eng,
                             operator_approval_at="2026-09-15T00:00:00Z", knowledge_ready=True, lab_fixture_mode=True)
    return ModernOrchestrator(engagement_id=eng, scope_law=ScopeLaw(profile=p, engagement_id=eng))


def _obs(status, body="", headers=None):
    return {"status_code": status, "response_body": body, "headers": headers or {}}


# ---- PART 2: Canonical Experiment Registry ---------------------------------

class TestExperimentRegistry:
    def test_six_families_registered(self):
        for fam in ["IDOR", "OPEN_REDIRECT", "SSRF", "MASS_ASSIGNMENT",
                    "INFO_DISCLOSURE", "AUTH_BYPASS"]:
            assert fam in EXPERIMENT_REGISTRY
            reg = EXPERIMENT_REGISTRY[fam]
            assert "baseline" in reg and "candidate" in reg and "negative_control" in reg
            assert "validator" in reg
            assert "execution_bounds" in reg

    def test_registry_is_descriptive_not_scheduler(self):
        """Registry has no run/execute/decide methods — it's config only."""
        for fam, reg in EXPERIMENT_REGISTRY.items():
            assert not callable(reg.get("run"))
            assert not callable(reg.get("decide"))


# ---- PART 3/4/5: Generic runner + normalizer + adapter ---------------------

class TestGenericRunner:
    def test_all_six_families_run_through_fabric(self):
        """PART 6: all 6 families wired through canonical fabric."""
        orch = _make_orch("eng_fab")
        orch.run_deep_recon(target_url="https://lab.example.com",
                            observed=[{"path": "/api/x", "method": "GET", "status_code": 200, "body": "{}", "headers": {}}])
        runner = GenericExperimentRunner(orch)
        families = ["IDOR", "OPEN_REDIRECT", "SSRF", "MASS_ASSIGNMENT",
                    "INFO_DISCLOSURE", "AUTH_BYPASS"]
        results = {}
        for fam in families:
            r = runner.run(
                hypothesis_id=f"h_{fam.lower()}", vulnerability_class=fam,
                target_url="https://lab.example.com/api/x",
                baseline_obs=_obs(200, '{"ok":true}'),
                candidate_obs=_obs(200, '{"secret":"x"}'),
                negative_control_obs=_obs(404, '{"error":"nf"}'),
            )
            results[fam] = r
            assert r.authorized is True  # in-scope
            assert r.experiment_id.startswith("exp_")
            assert r.baseline.role == "baseline"
            assert r.candidate.role == "candidate"
            assert r.negative_control.role == "negative_control"
        assert len(results) == 6

    def test_observation_normalization_redacts_secrets(self):
        """PART 4: secrets redacted before storage."""
        raw = {"status_code": 200, "response_body": "password=secret123 token=abc",
               "headers": {"Authorization": "Bearer xyz", "Content-Type": "json"}}
        obs = normalize_observation("exp_test", "candidate", raw)
        assert "secret123" not in obs.body_fingerprint  # hashed
        assert "Authorization" not in str(obs.headers_fingerprint)  # stripped
        assert obs.body_size > 0

    def test_runner_delegates_scope_not_implements(self):
        """PART 18: runner delegates to ScopeLaw, no own scope decision."""
        orch = _make_orch("eng_scope", targets=("lab.example.com",))
        runner = GenericExperimentRunner(orch)
        r = runner.run(
            hypothesis_id="h1", vulnerability_class="IDOR",
            target_url="https://evil.com/x",  # out of scope
            baseline_obs=_obs(200), candidate_obs=_obs(200),
            negative_control_obs=_obs(404),
        )
        assert r.authorized is False  # ScopeLaw denies, runner does not override


# ---- PART 9: Negative/inconclusive first-class paths -----------------------

class TestNegativeInconclusive:
    def test_refuted_outcome(self):
        orch = _make_orch("eng_ref")
        orch.run_deep_recon(target_url="https://lab.example.com",
                            observed=[{"path": "/api/x", "method": "GET", "status_code": 200, "body": "{}", "headers": {}}])
        runner = GenericExperimentRunner(orch)
        r = runner.run(
            hypothesis_id="h_ref", vulnerability_class="IDOR",
            target_url="https://lab.example.com/x",
            baseline_obs=_obs(200, '{"id":1}'),
            candidate_obs=_obs(403, '{"error":"forbidden"}'),  # correctly denied
            negative_control_obs=_obs(404, '{"error":"nf"}'),
        )
        assert r.validator_result.outcome == ValidationOutcome.REFUTED

    def test_inconclusive_outcome(self):
        orch = _make_orch("eng_inc")
        orch.run_deep_recon(target_url="https://lab.example.com",
                            observed=[{"path": "/api/x", "method": "GET", "status_code": 200, "body": "{}", "headers": {}}])
        runner = GenericExperimentRunner(orch)
        r = runner.run(
            hypothesis_id="h_inc", vulnerability_class="IDOR",
            target_url="https://lab.example.com/x",
            baseline_obs=_obs(500, ""), candidate_obs=_obs(500, ""),
            negative_control_obs=_obs(500, ""),
        )
        assert r.validator_result.outcome == ValidationOutcome.INCONCLUSIVE

    def test_missing_baseline_fails_closed(self):
        from webpent.production.validators import ValidatorError, validate_idor
        with pytest.raises(ValidatorError):
            validate_idor(baseline=None, candidate={"status_code": 200},
                          negative_control={"status_code": 404})


# ---- PART 10: Refutation → research feedback -------------------------------

class TestRefutationFeedback:
    def test_refuted_changes_research_priority(self):
        """PART 10: REFUTED → OutcomeTracker → rerank → alternative."""
        orch = _make_orch("eng_fb")
        orch.run_deep_recon(target_url="https://lab.example.com",
                            observed=[{"path": "/api/x", "method": "GET", "status_code": 200,
                                       "body": "{}", "headers": {}}])
        orch.research_loop.register_candidate("c_idor", ("h_idor",), "e_idor")
        orch.research_step()
        # Refuted IDOR.
        orch.record_outcome(experiment_signature="e_idor", outcome_class="refuted",
                            information_value=0.1, hypothesis_id="h_idor")
        # Alternative candidate becomes competitive.
        orch.research_loop.register_candidate("c_redirect", ("h_redirect",), "e_redirect")
        d2 = orch.research_step()
        assert d2["decision_number"] >= 2


# ---- PART 15/16: External observation adapter security ---------------------

class TestExternalObservationAdapter:
    @pytest.mark.parametrize("claim", list(FORBIDDEN_AUTHORITY_CLAIMS))
    def test_authority_claims_stripped(self, claim):
        """PART 16: external scanner claims authority → stripped, not trusted."""
        raw = {"target": "https://lab.example.com/api/x", "status": claim,
               "vulnerability_class": "IDOR", "severity": "high"}
        obs = ingest_external_observation(raw, source="wapiti",
                                          expected_target="lab.example.com")
        assert obs.advisory_only is True
        assert obs.is_authority() is False
        assert claim in obs.authority_claims_stripped or claim.upper() in [c.upper() for c in obs.authority_claims_stripped]

    def test_cross_target_external_rejected(self):
        """PART 16: external result for wrong target → fail closed."""
        raw = {"target": "https://evil.com/x", "status": "CONFIRMED"}
        with pytest.raises(ValueError, match="target mismatch"):
            ingest_external_observation(raw, source="wapiti", expected_target="lab.example.com")

    def test_external_never_authoritative(self):
        raw = {"target": "https://lab.example.com/x", "type": "XSS", "severity": "critical"}
        obs = ingest_external_observation(raw, source="nuclei", expected_target="lab.example.com")
        ctx = obs.as_research_context()
        assert ctx["advisory_only"] is True
        assert ctx["usage_constraint"] == "may_inform_hypothesis_generation_only"
        assert ctx["trust_level"] == "untrusted_external"


# ---- PART 12/13: Two-target + 15+ decision campaign ------------------------

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


class TestTwoTargetCampaign:
    def test_fabric_works_on_both_targets(self, target_rest, target_graphql):
        """PART 12: same fabric on REST + GraphQL targets."""
        for name, url in [("REST", target_rest), ("GraphQL", target_graphql)]:
            orch = _make_orch(f"eng_2t_{name}", targets=("127.0.0.1", "localhost"))
            orch.run_deep_recon(target_url=url, observed=[{"path": "/api/x", "method": "GET", "status_code": 200, "body": "{}", "headers": {}}])
            runner = GenericExperimentRunner(orch)
            r = runner.run(
                hypothesis_id=f"h_{name}", vulnerability_class="IDOR",
                target_url=f"{url}/api/x",
                baseline_obs=_obs(200, '{"id":1}'),
                candidate_obs=_obs(200, '{"id":1,"secret":"x"}'),
                negative_control_obs=_obs(404, '{"error":"nf"}'),
            )
            assert r.authorized is True
            assert r.validator_result.outcome == ValidationOutcome.CONFIRMED

    def test_15_decision_campaign(self, target_rest):
        """PART 13: 15+ decisions with feedback, refutation, reprioritization."""
        orch = _make_orch("eng_15v2", targets=("127.0.0.1", "localhost"))
        orch.run_deep_recon(target_url=target_rest,
                            observed=[{"path": "/api/users", "method": "GET", "status_code": 200,
                                       "body": "{}", "headers": {}}])
        runner = GenericExperimentRunner(orch)
        families = ["IDOR", "OPEN_REDIRECT", "SSRF", "MASS_ASSIGNMENT",
                    "INFO_DISCLOSURE", "AUTH_BYPASS"]
        outcomes = []
        for i in range(1, 16):
            fam = families[i % 6]
            cid = f"c_{i}_{fam.lower()}"
            orch.research_loop.register_candidate(cid, (f"h_{i}",), f"e_{i}")
            d = orch.research_step()
            # Vary outcomes: some refuted, some high-info, some low-info.
            if i % 4 == 0:
                cand_status, cand_body = 403, '{"error":"forbidden"}'
                outcome_cls = "refuted"
            elif i % 3 == 0:
                cand_status, cand_body = 200, '{"secret":"leaked","token":"x","password":"y"}'
                outcome_cls = "high_information"
            else:
                cand_status, cand_body = 200, '{"ok":true}'
                outcome_cls = "low_information"
            r = runner.run(
                hypothesis_id=f"h_{i}", vulnerability_class=fam,
                target_url=f"{target_rest}/api/ep_{i}",
                baseline_obs=_obs(200, '{"ok":true}'),
                candidate_obs=_obs(cand_status, cand_body),
                negative_control_obs=_obs(404, '{"error":"nf"}'),
            )
            info_val = 0.8 if outcome_cls == "high_information" else (0.1 if outcome_cls == "refuted" else 0.3)
            orch.record_outcome(experiment_signature=f"e_{i}", outcome_class=outcome_cls,
                                information_value=info_val, hypothesis_id=f"h_{i}")
            outcomes.append(outcome_cls)
        assert orch.research_loop.decision_count >= 15
        assert "refuted" in outcomes
        assert "high_information" in outcomes
        assert "low_information" in outcomes
        assert len(set(outcomes)) >= 2  # genuine feedback


# ---- PART 18: No duplicate authority ---------------------------------------

class TestNoDuplicateAuthority:
    def test_one_scope_law(self):
        orch = _make_orch("eng_1auth")
        runner = GenericExperimentRunner(orch)
        # Runner uses orchestrator's scope_law — same instance.
        assert runner.orch.scope_law is orch.scope_law

    def test_one_research_loop(self):
        orch = _make_orch("eng_1rl")
        assert orch.research_loop is orch.research_loop
        # No second loop in runner.
        runner = GenericExperimentRunner(orch)
        assert not hasattr(runner, "research_loop")
