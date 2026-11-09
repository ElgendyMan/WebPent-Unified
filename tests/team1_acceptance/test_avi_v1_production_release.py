# tests/team1_acceptance/test_avi_v1_production_release.py
"""TEAM-1 ACCEPTANCE — Autonomous Validation Intelligence V1 → Production RC.

Minimum acceptance criteria (all must pass with runtime evidence):
  - 30 decision autonomous campaign
  - 6 vulnerability families exercised
  - REST target + GraphQL target (real HTTP)
  - confirmed case / refuted case / inconclusive case
  - proof tampering rejection
  - replay tampering rejection
  - no duplicate security authority (one ScopeLaw, one ToolBoundary,
    one PromotionPipeline; external scanners advisory only)
  - anti-fake guarantees (7 rejection gates)
  - deterministic runtime trace proving all 11 stages
"""
from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

os.environ.setdefault(
    "WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890"
)

SIX_FAMILIES = ["IDOR", "OPEN_REDIRECT", "SSRF", "MASS_ASSIGNMENT",
                "INFO_DISCLOSURE", "AUTH_BYPASS"]
MODES = ["confirm", "refute", "inconclusive"]


# ---------------------------------------------------------------------------
# Real target server: REST + GraphQL, differential responses per family/mode.
# ---------------------------------------------------------------------------
def _response_for(mode: str, family: str, role: str):
    """Return (status, body_bytes, headers) for a differential probe."""
    f = family.upper()
    # negative control: independent invalid resource.
    if role == "negative_control":
        if f == "AUTH_BYPASS":
            return 401, b'{"error":"unauthorized"}', {}
        if f == "SSRF":
            return 400, b'{"error":"bad url scheme"}', {}
        return 404, b'{"error":"not_found"}', {}

    if f == "IDOR":
        if mode == "confirm":
            return 200, b'{"id":1,"owner":"alice","data":"secret"}', {}
        if mode == "refute":
            return (200 if role == "baseline" else 403), b'{"error":"forbidden"}', {}
        return 200 if role == "baseline" else 500, b'{"error":"server_error"}', {}

    if f == "AUTH_BYPASS":
        if mode == "confirm":
            if role == "candidate":
                return 200, b'{"private":"data","role":"admin"}', {}
            return 401, b'{"error":"unauthorized"}', {}
        if mode == "refute":
            return 403, b'{"error":"forbidden"}', {}
        return 200, b'{"public":"ok"}', {}

    if f == "SSRF":
        if mode == "confirm" and role == "candidate":
            return 200, b'{"fetched":"metadata iam token secret internal-ip"}', {}
        if mode == "refute":
            return 200, b'{"fetched":"metadata iam token secret"}', {}
        if mode == "inconclusive" and role == "candidate":
            return 200, b'{"fetched":"metadata"}', {}
        return 200, b'{"fetched":"normal_data"}', {}

    if f == "INFO_DISCLOSURE":
        if mode == "confirm" and role == "candidate":
            return 200, b'{"stack":"password secret token api_key traceback"}', {}
        if mode == "refute":
            return 200, b'{"stack":"password secret"}', {}
        if mode == "inconclusive" and role == "candidate":
            return 200, b'{"stack":"password"}', {}
        return 200, b'{"public":"clean"}', {}

    if f == "MASS_ASSIGNMENT":
        if mode == "confirm" and role == "candidate":
            return 200, b'{"user":"alice","role":"admin","is_admin":true}', {}
        if mode == "refute":
            return 200, b'{"user":"alice","role":"user"}', {}
        if mode == "inconclusive":
            return 200, b'{"user":"admin_account"}', {}
        return 200, b'{"user":"alice"}', {}

    if f == "OPEN_REDIRECT":
        if mode == "confirm" and role == "candidate":
            return 302, b'', {"Location": "https://evil.com/steal"}
        if mode == "refute" and role == "candidate":
            return 302, b'', {"Location": "https://trusted.com/home"}
        if mode == "inconclusive":
            return 302, b'', {"Location": "https://evil.com/x"}
        return 200, b'{"ok":true}', {}

    return 200, b'{"ok":true}', {}


class _AVITargetHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        role = qs.get("role", ["baseline"])[0]
        if "variant=candidate" in parsed.query or qs.get("variant") == ["candidate"]:
            role = "candidate"
        if "nonexistent_control" in path:
            role = "negative_control"

        if path.startswith("/graphql"):
            # GraphQL over GET: family/mode encoded in the query string.
            query = qs.get("query", [""])[0]
            mode = next((m for m in MODES if m in query), "confirm")
            family = next((f for f in SIX_FAMILIES if f.lower() in query.lower()), "IDOR")
        else:
            # REST: /{mode}/{family}/...
            parts = [p for p in path.split("/") if p]
            mode = parts[0] if parts and parts[0] in MODES else "confirm"
            family = parts[1].upper() if len(parts) > 1 and parts[1].upper() in SIX_FAMILIES else "IDOR"

        status, body, headers = _response_for(mode, family, role)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def real_avi_target():
    srv = HTTPServer(("127.0.0.1", 0), _AVITargetHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def _make_orchestrator(engagement_id):
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


def _build_hypotheses():
    """36 hypotheses: 6 families × 3 modes × 2 api types (REST + GraphQL)."""
    hyps = []
    i = 0
    for api_type in ("rest", "graphql"):
        for family in SIX_FAMILIES:
            for mode in MODES:
                i += 1
                h = {
                    "id": f"h_{i:02d}_{api_type}_{mode}_{family.lower()}",
                    "vulnerability_class": family,
                    "information_value": 0.5 + (0.01 * i),
                    "api_type": api_type,
                }
                if api_type == "rest":
                    h["path"] = f"/{mode}/{family.lower()}"
                else:
                    h["path"] = "/graphql"
                    h["graphql_query"] = f"query {{ {mode}_{family.lower()} }}"
                hyps.append(h)
    return hyps


# ---------------------------------------------------------------------------
# 1. 30-decision autonomous campaign (real HTTP, REST + GraphQL, 6 families)
# ---------------------------------------------------------------------------
class TestThirtyDecisionCampaign:
    def test_thirty_decisions_full_pipeline(self, real_avi_target, tmp_path):
        orch = _make_orchestrator("eng_avi_30")
        from webpent.production.autonomous_validation_v1 import (
            AutonomousValidationIntelligence,
        )
        avi = AutonomousValidationIntelligence(orch)
        result = avi.run_campaign(
            target_url=real_avi_target,
            hypotheses=_build_hypotheses(),
            max_decisions=30,
        )
        # Persist JSON evidence artifact.
        evidence = {
            "campaign": {k: v for k, v in result.items() if k != "trace_records"},
            "trace_records": result["trace_records"],
        }
        (tmp_path / "avi_30_decision_campaign.json").write_text(
            json.dumps(evidence, indent=2, default=str)
        )

        assert result["decisions_executed"] == 30, result["decisions_executed"]
        families_seen = {d["vulnerability_class"] for d in result["decisions"]
                         if d.get("vulnerability_class")}
        assert families_seen >= set(SIX_FAMILIES), families_seen
        api_types = {d.get("api_type") for d in result["decisions"]}
        assert api_types == {"rest", "graphql"}, api_types
        # Every non-M4-blocked decision executed real HTTP. IDOR/BOLA
        # hypotheses without a vault-bound principal are intentionally blocked
        # before transport by the M4 two-principal policy.
        assert all(
            d.get("real_http_executed")
            for d in result["decisions"]
            if not d.get("stopped") and d.get("vulnerability_class") not in {"IDOR", "BOLA"}
        )
        # Trace full coverage (all 11 stages) + chain integrity.
        assert result["trace"]["full_coverage"] is True
        assert result["trace"]["chain_verified"] is True
        # Security report produced.
        assert "security_report" in result
        assert result["security_report"]["report_version"] == "security_report_v1"
        # At least one promoted and one rejected (mixed outcomes).
        assert result["promoted_count"] >= 1
        assert result["rejected_count"] >= 1

    def test_outcomes_include_confirmed_refuted_inconclusive(self, real_avi_target):
        orch = _make_orchestrator("eng_avi_outcomes")
        from webpent.production.autonomous_validation_v1 import (
            AutonomousValidationIntelligence,
        )
        avi = AutonomousValidationIntelligence(orch)
        result = avi.run_campaign(
            target_url=real_avi_target,
            hypotheses=_build_hypotheses(),
            max_decisions=30,
        )
        outcomes = {d["validator_outcome"] for d in result["decisions"]
                    if d.get("validator_outcome")}
        assert "CONFIRMED" in outcomes, outcomes
        assert "REFUTED" in outcomes, outcomes
        assert "INCONCLUSIVE" in outcomes, outcomes


# ---------------------------------------------------------------------------
# 2. Deterministic runtime trace — proves all required stages.
# ---------------------------------------------------------------------------
class TestDeterministicRuntimeTrace:
    def test_trace_proves_all_required_fields(self, real_avi_target):
        orch = _make_orchestrator("eng_avi_trace")
        from webpent.production.autonomous_validation_v1 import (
            AutonomousValidationIntelligence,
            DeterministicRuntimeTrace,
        )
        avi = AutonomousValidationIntelligence(orch)
        result = avi.run_campaign(
            target_url=real_avi_target,
            hypotheses=_build_hypotheses()[:6],
            max_decisions=6,
        )
        trace = avi.trace
        assert isinstance(trace, DeterministicRuntimeTrace)
        # Prove selected hypothesis id + experiment id + vuln class.
        sel = trace.stages_by_name("experiment_selected")
        assert sel and all("hypothesis_id" in s.proof and "experiment_id" in s.proof
                           and "vulnerability_class" in s.proof for s in sel)
        # Prove real execution happened — EXCEPT for IDOR/BOLA hypotheses,
        # whose M4 two-principal binding is mandatory and uncompromisable.
        # These campaign hypotheses carry no explicit request spec, so they
        # take the legacy path, which D-RED-2 fail-closes for IDOR/BOLA
        # (block_reason "legacy_path_not_m4_authorized_fail_closed"). The
        # explicit-spec IDOR/BOLA path is likewise blocked by D-RED-1 when no
        # principal_alias is supplied (asserted in
        # test_avi_v1_1_real_target_qualification.py). FINAL-CLOSURE RULING,
        # Option 2: the block is the correct, expected outcome for these two
        # families, not a defect. Non-IDOR/BOLA stages must still be real.
        real = trace.stages_by_name("real_execution")
        assert real
        for s in real:
            vuln = s.proof.get("vulnerability_class")
            if vuln in ("IDOR", "BOLA"):
                assert s.proof.get("real_http_executed") is False, (
                    f"IDOR/BOLA stage should be M4-blocked (real_http_executed=False), got {s.proof}"
                )
            else:
                assert s.proof.get("real_http_executed") is True, f"{vuln} stage not real: {s.proof}"
        # Prove validator adapter executed.
        va = trace.stages_by_name("validator_adapter_executed")
        assert va and all(s.proof.get("validator_executed") is True for s in va)
        # Prove evidence quality calculated.
        eq = trace.stages_by_name("evidence_quality_calculated")
        assert eq and all("evidence_quality" in s.proof for s in eq)
        # Prove proof created (sealed + HMAC).
        pc = trace.stages_by_name("proof_created")
        assert pc and any(s.proof.get("sealed") is True and
                          s.proof.get("authenticity_tag_present") is True for s in pc)
        # Prove replay verified stage present.
        assert trace.saw_stage("replay_verified")
        # Prove promotion decision recorded.
        pd = trace.stages_by_name("promotion_decision")
        assert pd and all(s.proof.get("decision") in ("PROMOTED", "REJECTED") for s in pd)
        # Prove research feedback recorded.
        fb = trace.stages_by_name("research_feedback_recorded")
        assert fb and all(s.proof.get("feedback_recorded") is True for s in fb)
        # Chain tamper-evident.
        assert trace.verify_chain() is True


# ---------------------------------------------------------------------------
# 3. Anti-fake guarantees — PromotionPipeline rejects all 7.
# ---------------------------------------------------------------------------
class TestAntiFakeGuarantees:
    def _norm(self, role="baseline", status=200):
        from webpent.production.experiment_fabric import normalize_observation
        return normalize_observation("exp_test", role,
                                     {"status_code": status, "response_body": "x", "headers": {}})

    def test_rejects_synthetic_observations(self):
        from webpent.production.autonomous_validation_v1 import PromotionPipeline
        pp = PromotionPipeline()
        syn = {"synthetic": True, "real_http": False, "body_fingerprint": "a" * 16}
        r = pp.evaluate(baseline_obs=syn, candidate_obs=syn, negative_control_obs=syn,
                        evidence_origin="synthetic_fixture", validator_outcome="CONFIRMED",
                        evidence_quality=5, proof_bundle=None, replay_verified=True)
        assert r.decision.value == "REJECTED"
        assert "real_runtime_observations" in r.gates_failed

    def test_rejects_missing_negative_control(self):
        from webpent.production.autonomous_validation_v1 import PromotionPipeline
        pp = PromotionPipeline()
        b = self._norm("baseline")
        r = pp.evaluate(baseline_obs=b, candidate_obs=b, negative_control_obs=None,
                        evidence_origin="target_runtime", validator_outcome="CONFIRMED",
                        evidence_quality=5, proof_bundle=None, replay_verified=True)
        assert r.decision.value == "REJECTED"
        assert "negative_control_present" in r.gates_failed

    def test_rejects_missing_baseline(self):
        from webpent.production.autonomous_validation_v1 import PromotionPipeline
        pp = PromotionPipeline()
        b = self._norm("candidate")
        nc = self._norm("negative_control")
        r = pp.evaluate(baseline_obs=None, candidate_obs=b, negative_control_obs=nc,
                        evidence_origin="target_runtime", validator_outcome="CONFIRMED",
                        evidence_quality=5, proof_bundle=None, replay_verified=True)
        assert r.decision.value == "REJECTED"
        assert "baseline_present" in r.gates_failed

    def test_rejects_missing_replay(self):
        from webpent.production.autonomous_validation_v1 import PromotionPipeline
        pp = PromotionPipeline()
        b, c, nc = self._norm("baseline"), self._norm("candidate"), self._norm("negative_control")
        r = pp.evaluate(baseline_obs=b, candidate_obs=c, negative_control_obs=nc,
                        evidence_origin="target_runtime", validator_outcome="CONFIRMED",
                        evidence_quality=5, proof_bundle=None, replay_verified=False)
        assert r.decision.value == "REJECTED"
        assert "replay_verified" in r.gates_failed

    def test_rejects_unsigned_proof_bundle(self, real_avi_target):
        from webpent.models.proof_bundle import ProofBundle
        from webpent.production.autonomous_validation_v1 import PromotionPipeline
        pp = PromotionPipeline()
        b, c, nc = self._norm("baseline"), self._norm("candidate"), self._norm("negative_control")
        # Unsealed bundle (no HMAC).
        bundle = ProofBundle(engagement_id="eng_unsigned", finding_id="f_unsigned",
                             hypothesis_id="h1", target_fingerprint="t" * 16,
                             evidence_origin="target_runtime", oracle_decision="CONFIRMED",
                             target_backed=True, negative_control_independent=True,
                             scope_context={"a": 1}, identity_context={"b": 2})
        assert bundle.sealed is False
        r = pp.evaluate(baseline_obs=b, candidate_obs=c, negative_control_obs=nc,
                        evidence_origin="target_runtime", validator_outcome="CONFIRMED",
                        evidence_quality=5, proof_bundle=bundle, replay_verified=True)
        assert r.decision.value == "REJECTED"
        assert "proof_bundle_signed" in r.gates_failed

    def test_rejects_external_scanner_authority(self):
        from webpent.production.autonomous_validation_v1 import PromotionPipeline
        pp = PromotionPipeline()
        b, c, nc = self._norm("baseline"), self._norm("candidate"), self._norm("negative_control")
        for scanner in ("nuclei", "zap", "burp", "sqlmap", "external_scanner", "llm_confidence"):
            r = pp.evaluate(baseline_obs=b, candidate_obs=c, negative_control_obs=nc,
                            evidence_origin="target_runtime", validator_outcome="CONFIRMED",
                            evidence_quality=5, proof_bundle=None, replay_verified=True,
                            verdict_authority=scanner)
            assert r.decision.value == "REJECTED", scanner
            assert "no_external_scanner_authority" in r.gates_failed, scanner

    def test_rejects_confidence_only_promotion(self):
        from webpent.production.autonomous_validation_v1 import PromotionPipeline
        pp = PromotionPipeline()
        b, c, nc = self._norm("baseline"), self._norm("candidate"), self._norm("negative_control")
        # High confidence but validator NOT confirmed → must reject.
        r = pp.evaluate(baseline_obs=b, candidate_obs=c, negative_control_obs=nc,
                        evidence_origin="target_runtime", validator_outcome="INCONCLUSIVE",
                        evidence_quality=1, proof_bundle=None, replay_verified=True,
                        confidence_score=0.99)
        assert r.decision.value == "REJECTED"
        assert "causal_validator_confirmed" in r.gates_failed


# ---------------------------------------------------------------------------
# 4. Tampering rejection — proof tampering + replay tampering.
# ---------------------------------------------------------------------------
class TestTamperingRejection:
    def test_proof_tampering_rejected(self, real_avi_target):
        """A tampered-with sealed ProofBundle fails verify_seal → promotion rejects."""
        from webpent.models.proof_bundle import ProofBundle
        from webpent.production.autonomous_validation_v1 import PromotionPipeline
        b = self._norm("baseline"); c = self._norm("candidate"); nc = self._norm("negative_control")
        bundle = ProofBundle(
            engagement_id="eng_tamper", finding_id="f_tamper", hypothesis_id="h_tamper",
            target_fingerprint="t" * 16, evidence_origin="target_runtime",
            oracle_decision="CONFIRMED", target_backed=True,
            negative_control_independent=True,
            scope_context={"a": 1}, identity_context={"b": 2},
        ).seal(actor="test")
        assert bundle.verify_seal() is True
        # Tamper: flip finding_id (model is frozen — simulate via model_copy).
        tampered = bundle.model_copy(update={"finding_id": "f_tampered_malicious"})
        # Integrity seal now fails (digest covers finding_id).
        assert tampered.verify_seal() is False
        pp = PromotionPipeline()
        r = pp.evaluate(baseline_obs=b, candidate_obs=c, negative_control_obs=nc,
                        evidence_origin="target_runtime", validator_outcome="CONFIRMED",
                        evidence_quality=5, proof_bundle=tampered, replay_verified=True)
        assert r.decision.value == "REJECTED"
        assert "proof_bundle_signed" in r.gates_failed

    def test_replay_tampering_rejected(self, real_avi_target):
        """Tampered raw observation breaks replay digest match → replay_verified False."""
        from webpent.production.autonomous_validation_v1 import ReplayVerifier
        from webpent.production.experiment_fabric import normalize_observation
        raw = {"status_code": 200, "response_body": "original_body", "headers": {}}
        b = normalize_observation("exp_replay", "baseline", raw)
        c = normalize_observation("exp_replay", "candidate", raw)
        nc = normalize_observation("exp_replay", "negative_control", raw)
        # Tamper: change candidate raw body AFTER normalization.
        tampered_candidate = dict(raw, response_body="TAMPERED_BODY_MALICIOUS")
        res = ReplayVerifier.verify(
            experiment_id="exp_replay",
            baseline_raw=raw, candidate_raw=tampered_candidate, negative_control_raw=raw,
            vulnerability_class="IDOR", expected_outcome="INCONCLUSIVE",
            expected_baseline_digest=b.digest(), expected_candidate_digest=c.digest(),
            expected_negative_control_digest=nc.digest(), proof_bundle=None,
        )
        assert res["replay_verified"] is False
        assert res["digests_match"] is False

    def _norm(self, role="baseline", status=200):
        from webpent.production.experiment_fabric import normalize_observation
        return normalize_observation("exp_test", role,
                                     {"status_code": status, "response_body": "x", "headers": {}})


# ---------------------------------------------------------------------------
# 5. No duplicate security authority + production dispatch wiring.
# ---------------------------------------------------------------------------
class TestNoDuplicateAuthorityAndWiring:
    def test_no_second_scopelaw_or_toolboundary_in_avi(self):
        """AVI composes the orchestrator's authorities; creates none of its own."""
        import inspect

        from webpent.production import autonomous_validation_v1 as avi_mod
        src = inspect.getsource(avi_mod)
        # AVI must NOT instantiate ScopeLaw or ToolBoundary itself.
        assert "ScopeLaw(" not in src
        assert "ToolBoundary(" not in src
        # It delegates to orchestrator.run_bounded_experiment (authority there).
        assert "run_bounded_experiment" in src

    def test_single_promotion_authority(self):
        """PromotionPipeline is the SOLE promotion authority; no second promoter."""
        import inspect

        from webpent.production import autonomous_validation_v1 as avi_mod
        src = inspect.getsource(avi_mod)
        assert src.count("class PromotionPipeline") == 1
        # No LLM confirmation authority.
        assert "llm.confirm" not in src.lower()
        assert "mark_confirmed" not in src

    def test_production_dispatch_triggers_avi(self, real_avi_target):
        """run_research_campaign (production dispatch) delegates to AVI — no manual path."""
        orch = _make_orchestrator("eng_avi_dispatch")
        hyps = [{"id": "h_dispatch", "vulnerability_class": "IDOR", "path": "/confirm/idor"}]
        result = orch.run_research_campaign(
            target_url=real_avi_target, hypotheses=hyps, max_steps=3,
        )
        assert result.get("legacy_run_research_campaign_delegated") is True
        assert result.get("manual_path_used") is False
        assert result.get("avi_version") == "autonomous_validation_intelligence_v1"

    def test_graph_research_campaign_node_wired(self):
        """build_graph() routes recon → research_campaign → crawler (AVI-enabled)."""
        from webpent.graph.builder import (
            NODE_CRAWLER,
            NODE_RECON,
            NODE_RESEARCH_CAMPAIGN,
            build_graph,
        )
        g = build_graph(auto_approve=True).get_graph()
        edges = list(g.edges)
        def src(e): return e[0] if isinstance(e, (tuple, list)) else getattr(e, "source", str(e))
        def tgt(e): return e[1] if isinstance(e, (tuple, list)) else getattr(e, "target", str(e))
        incoming = {src(e) for e in edges if tgt(e) == NODE_RESEARCH_CAMPAIGN}
        outgoing = {tgt(e) for e in edges if src(e) == NODE_RESEARCH_CAMPAIGN}
        assert NODE_RECON in incoming
        assert NODE_CRAWLER in outgoing
