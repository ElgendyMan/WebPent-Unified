"""Synthetic chain-proof acceptance tests (standalone, no heavy deps).

Runs with:  PYTHONPATH=src python3 -m unittest tests.team1_acceptance.test_chain_proof_synthetic
or:         PYTHONPATH=src python3 tests/team1_acceptance/test_chain_proof_synthetic.py

These tests exercise the frozen ChainEngine against synthetic multi-family
evidence sets with sealed, replay-verified ProofBundles. No HTTP, no LLM, no
live target. SYNTHETIC PROOF ONLY.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault(
    "WEBPENT_AUDIT_SECRET_KEY",
    "chain-proof-test-2026-with-strong-entropy-7b2e9d4f",
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from webpent.agents.chain_engine import (  # noqa: E402
    ChainEngine,
    ChainExecutionResult,
    discover_chains,
)
from webpent.models.proof_bundle import build_proof_bundle  # noqa: E402

EIGHT_GATES = ("g1", "g2", "g3", "g4", "g5", "g6", "g7", "g8")
TARGET = "http://synthetic-chain-test.test"
ENGAGEMENT = "eng-chain-test-001"


def _promoted(fid, family, capabilities=(), severity="5.0", route=None, metadata=None):
    route = route or f"/api/{fid}"
    bundle = build_proof_bundle(
        engagement_id=ENGAGEMENT,
        finding_id=fid,
        hypothesis_id=f"hyp-{fid}",
        target_fingerprint="synthetic-fp",
        scope_context={"target_url": TARGET},
        identity_context={"principal_alias": "owner"},
        evidence=({"status": 200}, {"status": 200}, {"status": 404}),
        evidence_refs=(f"e-{fid}-b", f"e-{fid}-c", f"e-{fid}-n"),
        negative_control={"status": 404},
        baseline={"status": 200},
        request_evidence=({"method": "GET", "path": route},),
        response_evidence=({"status": 200},),
        causal_oracle={"causal_signal": True, "negative_control_complete": True},
        validator_id=f"validator.{family.lower()}.syn",
        validator_version="syn.v1",
        replay_metadata={"replayable": True},
        cleanup_status="not_applicable",
    ).seal()
    return {
        "id": fid,
        "status": "PROMOTED",
        "family": family,
        "target_url": TARGET,
        "engagement_id": ENGAGEMENT,
        "route": route,
        "severity": severity,
        "capabilities": list(capabilities),
        "metadata": dict(metadata or {}),
        "proof_bundle_ref": bundle.bundle_id,
        "proof_bundle": bundle.model_dump(mode="json"),
        "replay_verified": True,
        "promotion": {"decision": "PROMOTED", "gates_passed": list(EIGHT_GATES)},
    }


def _governed_executor(candidate):
    return ChainExecutionResult(
        chain_id=candidate.chain_id,
        status="chain_confirmed",
        confirmed=True,
        reason="M4/AVI/PromotionPipeline passed",
        evidence={"authority": "M4/AVI/PromotionPipeline", "response_digest": "redacted"},
        proof_bundle_ref=f"chain-proof-{candidate.chain_id}",
        replay_verified=True,
        gates_passed=EIGHT_GATES,
    )


class TestChainProofSynthetic(unittest.TestCase):
    def test_info_disclosure_plus_idor_chain_confirmed_critical(self):
        findings = [
            _promoted("disc", "INFO_DISCLOSURE", ("user_ids",), "3.1", "/api/users/list", {"disclosed_resource_id": "1042"}),
            _promoted("idor", "IDOR", ("user_ids", "other_user_data"), "6.5", "/api/users/{id}/profile", {"resource_template": "/api/users/{id}/profile"}),
        ]
        events = []
        engine = ChainEngine(audit_event=lambda n, d: events.append(n))
        candidates = engine.discover(findings)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].pattern, "info_disclosure_to_idor")
        self.assertTrue(candidates[0].prerequisites_met)
        run = engine.execute(candidates, _governed_executor)
        self.assertEqual(run.to_dict()["chains_confirmed"], 1)
        self.assertEqual(len(run.reports), 1)
        self.assertEqual(run.reports[0].combined_severity, "CRITICAL")
        self.assertGreaterEqual(run.reports[0].combined_cvss, 9.0)
        self.assertEqual(events, ["chain.discovered", "chain.executed", "chain.confirmed"])
        self.assertEqual(list(run.reports[0].gates_passed), list(EIGHT_GATES))

    def test_xss_plus_missing_csrf_chain_confirmed_high(self):
        findings = [_promoted("xss", "XSS", ("script_execution",), "5.8", "/search?q=", {"state_changing_endpoint": "/api/profile/update", "csrf_token_absent": True})]
        engine = ChainEngine()
        candidates = engine.discover(findings)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].pattern, "xss_to_csrf_bypass")
        run = engine.execute(candidates, _governed_executor)
        self.assertEqual(len(run.reports), 1)
        self.assertEqual(run.reports[0].combined_severity, "HIGH")
        self.assertGreaterEqual(run.reports[0].combined_cvss, 7.0)

    def test_ssrf_internal_access_chain_confirmed_critical(self):
        findings = [_promoted("ssrf", "SSRF", ("internal_access",), "8.0", "/api/fetch?url=", {"internal_reached": "169.254.169.254"})]
        engine = ChainEngine()
        candidates = engine.discover(findings)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].pattern, "ssrf_to_internal_access")
        run = engine.execute(candidates, _governed_executor)
        self.assertEqual(run.to_dict()["chains_confirmed"], 1)
        self.assertEqual(run.reports[0].combined_severity, "CRITICAL")

    def test_refuse_idor_alone_no_chain(self):
        findings = [_promoted("idor-solo", "IDOR", ("user_ids", "other_user_data"), "6.5")]
        self.assertEqual(discover_chains(findings), ())

    def test_refuse_incompatible_families_no_chain(self):
        findings = [
            _promoted("disc", "INFO_DISCLOSURE", ("user_ids",), "3.0", "/a"),
            _promoted("or", "OPEN_REDIRECT", ("external_redirect",), "4.0", "/b"),
        ]
        self.assertEqual(discover_chains(findings), ())

    def test_refuse_forged_bundle_excluded(self):
        forged = _promoted("f-ssrf", "SSRF", ("internal_access",), "8.0")
        forged["proof_bundle"]["seal_digest"] = "sha256:" + "0" * 64
        forged["proof_bundle"]["authenticity_tag"] = "hmac:" + "0" * 64
        self.assertEqual(discover_chains([forged]), ())

    def test_refuse_executor_bool_without_proof_no_report(self):
        findings = [_promoted("ssrf-np", "SSRF", ("internal_access",), "8.0")]
        engine = ChainEngine()
        candidates = engine.discover(findings)
        self.assertEqual(len(candidates), 1)
        run = engine.execute(candidates, lambda c: {"status": "chain_confirmed", "confirmed": True, "replay_verified": False})
        self.assertEqual(run.reports, ())
        self.assertEqual(run.to_dict()["combined_severity_upgrades"], 0)
        self.assertEqual(run.executions[0].status, "chain_confirmed")

    def test_refuse_no_executor_blocks_chain(self):
        findings = [_promoted("ssrf-ne", "SSRF", ("internal_access",), "8.0")]
        engine = ChainEngine()
        candidates = engine.discover(findings)
        run = engine.execute(candidates, executor=None)
        self.assertEqual(run.executions[0].status, "chain_blocked")
        self.assertEqual(run.reports, ())

    def test_combined_report_markdown_and_json_render(self):
        findings = [_promoted("ssrf-r", "SSRF", ("internal_access",), "8.0")]
        engine = ChainEngine()
        run = engine.execute(engine.discover(findings), _governed_executor)
        report = run.reports[0]
        md = report.to_markdown()
        self.assertIn("Combined severity", md)
        self.assertIn("CRITICAL", md)
        d = report.to_dict()
        self.assertEqual(d["combined_severity"], "CRITICAL")
        self.assertEqual(len(d["gates_passed"]), 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
