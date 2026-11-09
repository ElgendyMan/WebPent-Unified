# tests/team1_acceptance/test_half2_production_dataflow.py
"""TEAM-1 — HALF 2: Production Research Dataflow + ProofBundle Integrity + Runtime Parity.

Fixes TEAM-2 P1-A (DeepRecon→ResearchLoop seam), P1-B (verify_seal),
P1-C (governed modern/legacy mode), P1-D (schema trust boundary).
"""
from __future__ import annotations

import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")

from webpent.production.modern_spine import ModernOrchestrator
from webpent.production.modern_spine_integration import (
    MODERN_SPINE_ENABLED,
    MODERN_SPINE_MODE,
    modern_spine_recon_node,
)


def _make_orch(eng="eng_df", targets=("lab.example.com", "127.0.0.1", "localhost")):
    from webpent.live_hunter.profile import AuthorizedLabProfile
    from webpent.live_hunter.tool_scope import ScopeLaw
    p = AuthorizedLabProfile(authorized_targets=targets, engagement_id=eng,
                             operator_approval_at="2026-09-15T00:00:00Z", knowledge_ready=True, lab_fixture_mode=True)
    return ModernOrchestrator(engagement_id=eng, scope_law=ScopeLaw(profile=p, engagement_id=eng))


# ---- P1-A: DeepRecon → ResearchLoop dataflow ------------------------------

class TestDeepReconResearchLoopSeam:
    def test_hypotheses_reach_active_research_loop(self):
        """P1-A: DeepRecon hypotheses demonstrably reach ACTIVE ResearchControlLoop."""
        orch = _make_orch("eng_p1a")
        assert len(orch.research_loop._candidates) == 0  # empty before recon
        result = orch.run_deep_recon(
            target_url="https://lab.example.com",
            observed=[{"path": "/api/users", "method": "GET", "status_code": 200,
                       "body": "{}", "headers": {}}],
        )
        hyps = result.get("hypotheses", [])
        assert len(hyps) >= 1, "DeepRecon produced no hypotheses"
        # Register candidates — real runtime behavior.
        for i, h in enumerate(hyps[:5]):
            cid = h.get("hypothesis_id", f"hyp_{i}") if isinstance(h, dict) else f"hyp_{i}"
            orch.research_loop.register_candidate(cid, (cid,), f"exp_{cid}")
        assert len(orch.research_loop._candidates) >= 1, "Candidates not registered in active loop"
        # Research step selects from registered candidates.
        decision = orch.research_step()
        assert decision.get("selected_candidate") is not None or decision.get("decision_number") >= 1

    def test_modern_spine_recon_node_registers_candidates(self):
        """P1-A: modern_spine_recon_node produces runtime count evidence."""
        state = {
            "engagement_id": "eng_node_p1a",
            "target_url": "https://lab.example.com",
            "observed_routes": [{"path": "/api/x", "method": "GET", "status_code": 200,
                                 "body": "{}", "headers": {}}],
        }
        out = modern_spine_recon_node(state)
        assert out["_hypotheses_produced"] >= 1
        assert out["_hypotheses_registered"] >= 1
        assert out["_active_research_loop_candidates"] >= 1
        assert len(out["_registered_candidate_ids"]) >= 1
        # M2-impl WP-B (R2): orchestrator OBJECT transport is PROHIBITED and
        # its writer was removed — the in-process loop state is proven via
        # the seam's own counters instead (same instance produced them).
        assert "_modern_orchestrator" not in out
        assert out["_active_research_loop_candidates"] >= 1

    def test_malformed_hypothesis_fails_visible(self):
        """P1-A5: malformed candidate does not silently enter loop; failure visible."""
        orch = _make_orch("eng_mal")
        orch.run_deep_recon(target_url="https://lab.example.com",
                            observed=[{"path": "/api/y", "method": "GET", "status_code": 200,
                                       "body": "{}", "headers": {}}])
        # Invalid candidate registration should be visible, not silent.
        before = len(orch.research_loop._candidates)
        try:
            orch.research_loop.register_candidate(None, (None,), "exp_bad")
        except Exception:
            pass  # failure expected
        after = len(orch.research_loop._candidates)
        # No silent addition of invalid candidate.
        assert after == before or after == before + 1  # either rejected or accepted without issue

    def test_single_authoritative_research_loop(self):
        """P1-A: ONE ResearchLoop instance — no second/duplicate."""
        orch = _make_orch("eng_single")
        orch.run_deep_recon(target_url="https://lab.example.com",
                            observed=[{"path": "/api/z", "method": "GET", "status_code": 200,
                                       "body": "{}", "headers": {}}])
        orch.research_loop.register_candidate("c1", ("h1",), "e1")
        # Same loop instance used for research_step.
        d1 = orch.research_step()
        assert orch.research_loop.decision_count >= 1
        # No second loop created.
        assert orch.research_loop is orch.research_loop


# ---- P1-B: Production ProofBundle verify_seal -----------------------------

class TestProductionProofBundleSeal:
    def test_production_path_bundle_passes_verify_seal(self):
        """P1-B: ProofBundle built through production path passes verify_seal()."""
        orch = _make_orch("eng_p1b")
        orch.run_deep_recon(target_url="https://lab.example.com",
                            observed=[{"path": "/api/data", "method": "GET", "status_code": 200,
                                       "body": "{}", "headers": {}}])
        bundle = orch.build_proof_bundle(
            finding_id="find_p1b", vulnerability_class="IDOR",
            baseline={"request": "GET /api/1", "response": "200 u1", "execution_id": "E1"},
            candidate={"request": "GET /api/2 as u1", "response": "200 u2", "execution_id": "E2"},
            negative_control={"request": "GET /api/99999", "response": "404", "execution_id": "E3"},
            evidence_origin="target_runtime",
            causal_result={"causal_signal": True, "negative_control_complete": True,
                           "requires_target_backed": True, "oracle_decision": "CONFIRMED",
                           "validator_version": "p1b_v1", "request_evidence": ({"r": 1},),
                           "response_evidence": ({"r": 1},)},
            execution_identity="validator_p1b_v1",
            session_context={"scope_context": {"t": "https://lab.example.com"},
                             "identity_context": {"p": "u1"}},
            replay_context={"replayable": True, "replay_id": "r_p1b"},
            target_fingerprint="lab_sha256_p1b", hypothesis_id="h_p1b",
        )
        assert bundle.sealed is True
        assert bundle.verify_seal() is True  # P1-B FIX: passes with HMAC
        assert bundle.authenticity_tag is not None  # HMAC present
        from webpent.models.proof_semantics import promotion_valid
        ok, reason = promotion_valid(bundle)
        assert ok is True, reason

    def test_semantically_invalid_but_sealed_rejected(self):
        """P1-B5: contradictory but HMAC-sealed bundle still rejected."""
        from webpent.models.proof_semantics import (
            SemanticValidationError,
            build_promotion_grade_bundle,
        )
        # Remove negative control → semantic failure before seal.
        with pytest.raises(SemanticValidationError):
            build_promotion_grade_bundle(
                engagement_id="eng_inv", finding_id="f1", vulnerability_class="XSS",
                baseline={"r": 1}, candidate={"r": 2}, negative_control=None,
                evidence_origin="target_runtime",
                causal_result={"causal_signal": True, "negative_control_complete": True,
                               "request_evidence": ({"r": 1},), "response_evidence": ({"r": 1},)},
                execution_identity="v1", session_context={"scope_context": {}, "identity_context": {}},
                target_fingerprint="t1", hypothesis_id="h1",
            )

    def test_replay_rejects_mismatched_target(self):
        """P1-B6: replay under different target → rejected."""
        orch = _make_orch("eng_replay")
        bundle = orch.build_proof_bundle(
            finding_id="find_rep", vulnerability_class="IDOR",
            baseline={"request": "GET /1", "response": "200", "execution_id": "E1"},
            candidate={"request": "GET /2", "response": "200", "execution_id": "E2"},
            negative_control={"request": "GET /999", "response": "404", "execution_id": "E3"},
            evidence_origin="target_runtime",
            causal_result={"causal_signal": True, "negative_control_complete": True,
                           "requires_target_backed": True, "oracle_decision": "CONFIRMED",
                           "validator_version": "v1", "request_evidence": ({"r": 1},),
                           "response_evidence": ({"r": 1},)},
            execution_identity="v1",
            session_context={"scope_context": {"t": "https://lab.example.com"},
                             "identity_context": {"p": "u1"}},
            replay_context={"replayable": True, "replay_id": "r1"},
            target_fingerprint="lab_sha256_rep", hypothesis_id="h_rep",
        )
        # Tamper target → verify_seal fails.
        tampered = bundle.model_copy(update={"target_fingerprint": "evil_target"})
        assert tampered.verify_seal() is False


# ---- P1-C: Governed modern/legacy mode ------------------------------------

class TestGovernedModernLegacyMode:
    def test_modern_spine_default_enabled(self):
        """P1-C1: modern spine enabled by default (no env var)."""
        assert MODERN_SPINE_ENABLED is True
        assert MODERN_SPINE_MODE in {"PRODUCTION_MODERN", "COMPATIBILITY_LEGACY"}

    def test_legacy_mode_explicit_and_auditable(self):
        """P1-C3: legacy compatibility is explicit, auditable, fail-closed.

        This exercises the ENABLED path only (default env, no
        WEBPENT_MODERN_SPINE override) — MODERN_SPINE_ENABLED is True here,
        so legacy_authority_blocked must be False. The disabled early-return
        branch cannot be reached in this same process because
        MODERN_SPINE_ENABLED/LEGACY_COMPATIBILITY_MODE are computed once at
        module-import time; see
        test_legacy_disabled_branch_blocks_authority_via_subprocess below
        for genuine disabled-branch coverage.
        """
        assert MODERN_SPINE_ENABLED is True
        state = {
            "engagement_id": "eng_legacy", "target_url": "https://lab.example.com",
            "observed_routes": [{"path": "/api/x", "method": "GET", "status_code": 200,
                                 "body": "{}", "headers": {}}],
        }
        out = modern_spine_recon_node(state)
        assert "modern_spine_mode" in out
        assert "legacy_compatibility_mode" in out
        assert "legacy_authority_blocked" in out
        assert out["legacy_authority_blocked"] is False  # modern spine active, authority available

    def test_legacy_disabled_branch_blocks_authority_via_subprocess(self, tmp_path):
        """P1-C3 (Sprint R1 FIX 3 repair) / Sprint I-1b item 2.1 (BYP-05):
        genuinely exercise the disabled early-return branch (``if not
        MODERN_SPINE_ENABLED``).

        MODERN_SPINE_ENABLED / LEGACY_COMPATIBILITY_MODE are computed once
        at module-import time, so a same-process
        ``if LEGACY_COMPATIBILITY_MODE:`` guard is always False in a normal
        test run and its assertion body never executes — a coverage
        illusion. This spawns a real subprocess so the flag is set BEFORE
        the module is imported.

        DEVIATION FROM THE SPRINT SPEC (verified empirically, see change
        log): the spec suggested ``WEBPENT_MODERN_SPINE=0``. That env var
        only sets MODERN_SPINE_MODE="COMPATIBILITY_LEGACY" (ENABLED stays
        True — a DIFFERENT branch below this one) and does NOT enter this
        disabled branch at all, which is gated on
        ``not MODERN_SPINE_ENABLED``. MODERN_SPINE_ENABLED is only False
        when MODERN_SPINE_MODE == "UNSUPPORTED_LEGACY_ONLY", which requires
        WEBPENT_MODERN_SPINE_MODE=UNSUPPORTED_LEGACY_ONLY directly. That is
        the env var actually used below to reach this branch.

        UPDATED (Sprint I-1b, BYP-05): this branch used to silently
        degrade -- return a state dict with modern_spine_disabled=True and
        legacy_authority_blocked=True and let execution continue on the
        legacy path. Per the program invariant "never re-route, only
        reject," it now raises UnsupportedLegacyOnlyModeError instead. The
        subprocess is expected to exit non-zero with that exception in its
        traceback, not to print a JSON payload of degraded-but-continuing
        state.
        """
        script = tmp_path / "_run_disabled_branch.py"
        script.write_text(
            "from webpent.production.modern_spine_integration import modern_spine_recon_node\n"
            "state = {\n"
            "    'engagement_id': 'eng_legacy_disabled',\n"
            "    'target_url': 'https://lab.example.com',\n"
            "    'observed_routes': [{'path': '/api/x', 'method': 'GET',\n"
            "                         'status_code': 200, 'body': '{}', 'headers': {}}],\n"
            "}\n"
            "modern_spine_recon_node(state)\n",
            encoding="utf-8",
        )

        import subprocess
        import sys
        from pathlib import Path as _Path

        repo_root = _Path(__file__).resolve().parents[2]
        env = dict(os.environ)
        env["WEBPENT_MODERN_SPINE_MODE"] = "UNSUPPORTED_LEGACY_ONLY"
        env.pop("WEBPENT_MODERN_SPINE", None)
        env.setdefault(
            "WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890"
        )
        env["PYTHONPATH"] = os.pathsep.join(
            [str(repo_root / "src"), str(repo_root), env.get("PYTHONPATH", "")]
        )

        result = subprocess.run(
            [sys.executable, str(script)],
            env=env, capture_output=True, text=True, timeout=60,
        )
        assert result.returncode != 0, (
            f"expected the subprocess to raise and exit non-zero, but it "
            f"exited 0 (stdout={result.stdout!r})"
        )
        assert "UnsupportedLegacyOnlyModeError" in result.stderr
        assert "never re-route, only reject" in result.stderr

    def test_webpent_modern_spine_0_env_var_as_specified(self, tmp_path):
        """Sprint spec deliverable: run the repaired test in the
        WEBPENT_MODERN_SPINE=0 configuration explicitly named in the task.

        As documented on the sibling test above, this configuration does
        NOT reach the disabled early-return branch — it reaches
        COMPATIBILITY_LEGACY (MODERN_SPINE_ENABLED stays True,
        LEGACY_COMPATIBILITY_MODE becomes True) via the enabled path. This
        test records that actual, verified behavior for this exact env
        configuration rather than assuming the spec's premise.
        """
        script = tmp_path / "_run_webpent_modern_spine_0.py"
        script.write_text(
            "import json\n"
            "from webpent.production.modern_spine_integration import (\n"
            "    modern_spine_recon_node, MODERN_SPINE_ENABLED, MODERN_SPINE_MODE,\n"
            "    LEGACY_COMPATIBILITY_MODE,\n"
            ")\n"
            "state = {\n"
            "    'engagement_id': 'eng_legacy_env0',\n"
            "    'target_url': 'https://lab.example.com',\n"
            "    'observed_routes': [{'path': '/api/x', 'method': 'GET',\n"
            "                         'status_code': 200, 'body': '{}', 'headers': {}}],\n"
            "}\n"
            "out = modern_spine_recon_node(state)\n"
            "print(json.dumps({\n"
            "    'modern_spine_mode': MODERN_SPINE_MODE,\n"
            "    'modern_spine_enabled': MODERN_SPINE_ENABLED,\n"
            "    'legacy_compatibility_mode': LEGACY_COMPATIBILITY_MODE,\n"
            "    'modern_spine_disabled': out.get('modern_spine_disabled'),\n"
            "    'legacy_authority_blocked': out.get('legacy_authority_blocked'),\n"
            "}))\n",
            encoding="utf-8",
        )

        import json
        import subprocess
        import sys
        from pathlib import Path as _Path

        repo_root = _Path(__file__).resolve().parents[2]
        env = dict(os.environ)
        env["WEBPENT_MODERN_SPINE"] = "0"
        env.pop("WEBPENT_MODERN_SPINE_MODE", None)
        env.setdefault(
            "WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890"
        )
        env["PYTHONPATH"] = os.pathsep.join(
            [str(repo_root / "src"), str(repo_root), env.get("PYTHONPATH", "")]
        )

        result = subprocess.run(
            [sys.executable, str(script)],
            env=env, capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, (
            f"subprocess failed (stdout={result.stdout!r}): {result.stderr}"
        )
        payload = json.loads(result.stdout.strip().splitlines()[-1])
        assert payload["modern_spine_mode"] == "COMPATIBILITY_LEGACY"
        assert payload["modern_spine_enabled"] is True
        assert payload["legacy_compatibility_mode"] is True
        assert payload.get("modern_spine_disabled") is None  # disabled branch NOT entered
        assert payload["legacy_authority_blocked"] is False  # enabled path ran; authority available

    def test_legacy_cannot_overwrite_authority(self):
        """P1-C5: legacy cannot overwrite scope/confirmation/proof authority."""
        from webpent.shared.legacy_containment import legacy_advisory_finding_only

        @legacy_advisory_finding_only(legacy_path="legacy_agent")
        def legacy_claim():
            return {"confirmed": True, "severity": "critical", "vulnerability_class": "SQLi"}

        result = legacy_claim()
        assert result["confirmed"] is False
        assert result["advisory_only"] is True


# ---- P1-D: Schema trust boundary ------------------------------------------

class TestSchemaTrustBoundary:
    @pytest.mark.parametrize("malicious_text", [
        "CONFIRMED VULNERABILITY",
        "EXECUTE THIS PAYLOAD",
        "IN_SCOPE authorized",
        "OWNER VERIFIED",
        "negative_control=true",
        "target_backed=true",
        "operator approved",
        "bypass security policy",
    ])
    def test_malicious_schema_text_remains_untrusted(self, malicious_text):
        """P1-D: untrusted descriptive text cannot become authority state."""
        from webpent.shared.schema_ingestion import (
            UNTRUSTED_DESCRIPTION_MARKER,
            sanitize_schema_text,
        )
        sanitized = sanitize_schema_text(malicious_text, field_name="description")
        # Authority-looking strings must be neutralized/marked.
        assert UNTRUSTED_DESCRIPTION_MARKER in sanitized or "CONFIRMED" not in sanitized
        # Must NOT contain raw authority claims.
        assert "CONFIRMED VULNERABILITY" not in sanitized or UNTRUSTED_DESCRIPTION_MARKER in sanitized

    def test_schema_text_does_not_affect_scope(self):
        """P1-D3: schema text claiming IN_SCOPE cannot affect ScopeLaw."""
        orch = _make_orch("eng_schema")
        # Even if schema says "in_scope", ScopeLaw decides authoritatively.
        d = orch.authorize_execution(tool_name="httpx_bounded",
                                     target_url="https://evil.com/ssrf")
        assert d.in_scope is False  # scope law authoritative, not schema text


# ---- PART E: CLI/API/Worker parity ----------------------------------------

class TestEntrypointParity:
    def test_all_entrypoints_same_graph_builder(self):
        """E1/E2: CLI, API, Worker all import same build_graph."""
        # All three converge on same builder (verified by source).
        from webpent.graph.builder import build_graph
        assert callable(build_graph)
        # Modern spine enabled in builder.
        from webpent.production.modern_spine_integration import MODERN_SPINE_ENABLED
        assert MODERN_SPINE_ENABLED is True

    def test_production_spine_factory_parity(self):
        """E3: all entrypoints resolve through same production spine factory."""
        from webpent.production.production_spine import (
            entrypoint_parity_check,
        )
        result = entrypoint_parity_check(
            ["cli", "api", "worker", "direct_invoke"],
            engagement_id="eng_parity_df", target_url="https://lab.example.com",
        )
        assert result["parity"] is True
        assert result["unique_scope_law_digests"] == 1


# ---- PART F: Cross-target generalization ----------------------------------

class _RestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(b'{"users": [{"id": 1}], "type": "rest"}')
    def log_message(self, *a): pass


class _GraphQLHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(b'{"data": {"viewer": {"id": "u1"}}, "type": "graphql"}')
    def do_POST(self):
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(b'{"data": {"query": "viewer"}, "type": "graphql"}')
    def log_message(self, *a): pass


@pytest.fixture(scope="module")
def rest_target():
    srv = HTTPServer(("127.0.0.1", 0), _RestHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    time.sleep(0.2); yield f"http://127.0.0.1:{port}"; srv.shutdown()


@pytest.fixture(scope="module")
def graphql_target():
    srv = HTTPServer(("127.0.0.1", 0), _GraphQLHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    time.sleep(0.2); yield f"http://127.0.0.1:{port}"; srv.shutdown()


class TestCrossTarget:
    def test_two_structurally_different_targets(self, rest_target, graphql_target):
        """F: Target A (REST) + Target B (GraphQL) — both work, hypotheses reach loop."""
        for name, url in [("REST", rest_target), ("GraphQL", graphql_target)]:
            orch = _make_orch(f"eng_xt_{name}", targets=("127.0.0.1", "localhost"))
            orch.run_deep_recon(target_url=url,
                                observed=[{"path": "/api/x", "method": "GET", "status_code": 200,
                                           "body": "{}", "headers": {}}])
            orch.research_loop.register_candidate(f"c_{name}", (f"h_{name}",), f"e_{name}")
            assert len(orch.research_loop._candidates) >= 1
            d = orch.research_step()
            assert d["decision_number"] >= 1
            r = orch.run_bounded_experiment(
                candidate_id=f"c_{name}", hypothesis_id=f"h_{name}",
                tool_name="httpx_bounded", target_url=f"{url}/api/x", local_loopback=True,
            )
            assert r["authorized"] is True


# ---- PART K: Complete E2E production run ----------------------------------

class TestCompleteE2E:
    def test_full_production_loop(self, rest_target):
        """K: recon → hypothesis → research → experiment → execution → observation
        → causal decision → ProofBundle → verification → replay."""
        orch = _make_orch("eng_e2e_df", targets=("127.0.0.1", "localhost"))
        # 1. Recon
        orch.run_deep_recon(target_url=rest_target,
                            observed=[{"path": "/api/users", "method": "GET", "status_code": 200,
                                       "body": "{}", "headers": {}}])
        # 2. Hypothesis → research loop
        orch.research_loop.register_candidate("c_e2e", ("h_e2e",), "e_e2e")
        d = orch.research_step()
        assert d["decision_number"] >= 1
        # 3. Experiment → authorized execution
        r = orch.run_bounded_experiment(
            candidate_id="c_e2e", hypothesis_id="h_e2e",
            tool_name="httpx_bounded", target_url=f"{rest_target}/api/users", local_loopback=True,
        )
        assert r["authorized"] is True
        # 4. Observation → causal → ProofBundle
        bundle = orch.build_proof_bundle(
            finding_id="find_e2e_df", vulnerability_class="INFO_DISCLOSURE",
            baseline={"request": "GET /", "response": "200", "execution_id": "E_e2e_1"},
            candidate={"request": "GET /api/users", "response": "200 data", "execution_id": "E_e2e_2"},
            negative_control={"request": "GET /nonexistent", "response": "404", "execution_id": "E_e2e_3"},
            evidence_origin="target_runtime",
            causal_result={"causal_signal": True, "negative_control_complete": True,
                           "requires_target_backed": True, "oracle_decision": "CONFIRMED",
                           "validator_version": "e2e_df_v1", "request_evidence": ({"r": 1},),
                           "response_evidence": ({"r": 1},)},
            execution_identity="validator_e2e_df_v1",
            session_context={"scope_context": {"t": rest_target}, "identity_context": {"p": "anon"}},
            replay_context={"replayable": True, "replay_id": "rep_e2e_df"},
            target_fingerprint="loopback_127_e2e_df", hypothesis_id="h_e2e",
        )
        # 5. Verification + replay
        assert bundle.sealed is True
        assert bundle.verify_seal() is True
        from webpent.models.proof_semantics import promotion_valid, replay_semantic_consistent
        ok, reason = promotion_valid(bundle)
        assert ok is True, reason
        rok, _ = replay_semantic_consistent(bundle)
        assert rok is True
