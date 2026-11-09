# tests/team1_acceptance/test_sprint_i1_part1_regressions.py
"""Sprint I-1, Part 1 — remediation backlog regression tests.

Covers item 1.1 (experiment_fabric status_code=None crash), item 1.3
(construction-escape fail-closed startup gate), and item 1.4 (protected-key
extension in _combined_recon_node). Item 1.2 (dead-branch deletion) has no
dedicated regression test here by design — it is a confirmed no-op deletion,
verified instead by the existing AVI/fabric acceptance suite (team1_acceptance/
test_fabric_automatic_dispatch.py and friends) producing byte-identical
before/after failures with and without the deleted branch.
"""
from __future__ import annotations

import os

import pytest


class TestExperimentFabricNoneStatusCode:
    """Item 1.1: an observation with status_code=None must not crash."""

    def test_explicit_none_status_code_normalizes_to_zero(self):
        from webpent.production.experiment_fabric import normalize_observation

        # status_code key IS PRESENT with an explicit None value — this is
        # the case dict.get(key, default) does NOT fall through on, since
        # the key exists. Before the 1.1 fix, int(None) raised TypeError.
        raw = {
            "status_code": None,
            "response_body": "",
            "headers": {},
        }
        obs = normalize_observation("exp_1_1_test", "candidate", raw)
        assert obs.status_code == 0

    def test_absent_status_code_still_defaults_to_zero(self):
        """Unchanged prior behavior: key absent entirely still defaults via
        the raw.get(..., raw.get("status", 0)) fallback chain."""
        from webpent.production.experiment_fabric import normalize_observation

        raw = {"response_body": "", "headers": {}}
        obs = normalize_observation("exp_1_1_test_absent", "baseline", raw)
        assert obs.status_code == 0

    def test_real_integer_status_code_unaffected(self):
        from webpent.production.experiment_fabric import normalize_observation

        raw = {"status_code": 404, "response_body": "", "headers": {}}
        obs = normalize_observation("exp_1_1_test_real", "negative_control", raw)
        assert obs.status_code == 404


class TestConstructionEscapeGate:
    """Item 1.3: WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY
    must never be honored in a qualification/staging/production posture,
    and every honored escape must be audit-logged."""

    ESCAPE_VAR = "WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY"
    PROFILE_VARS = ("WEBPENT_ENVIRONMENT_PROFILE", "ENVIRONMENT_PROFILE", "environment_profile")

    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch):
        monkeypatch.delenv(self.ESCAPE_VAR, raising=False)
        for v in self.PROFILE_VARS:
            monkeypatch.delenv(v, raising=False)
        yield

    def test_escape_unset_is_a_noop(self):
        from webpent.shared.preflight import enforce_construction_escape_gate

        report = enforce_construction_escape_gate()
        assert report["status"] == "ok — escape not set"

    def test_escape_set_in_lab_is_honored_and_audit_logged(self, monkeypatch, caplog):
        import logging

        from webpent.shared.preflight import enforce_construction_escape_gate

        monkeypatch.setenv(self.ESCAPE_VAR, "1")
        with caplog.at_level(logging.WARNING, logger="webpent.shared.preflight"):
            report = enforce_construction_escape_gate()
        assert "honored" in report["status"]
        assert any("construction_escape_honored" in r.message for r in caplog.records)

    @pytest.mark.parametrize("profile", ["production", "staging", "qualification"])
    def test_escape_set_in_strict_profile_fails_closed(self, monkeypatch, profile):
        from webpent.shared.preflight import enforce_construction_escape_gate

        monkeypatch.setenv(self.ESCAPE_VAR, "1")
        monkeypatch.setenv("WEBPENT_ENVIRONMENT_PROFILE", profile)
        with pytest.raises(SystemExit):
            enforce_construction_escape_gate()

    def test_strict_profile_alone_without_escape_does_not_raise(self, monkeypatch):
        """Only the *combination* of escape+strict is refused — a strict
        deployment with the escape unset must start normally."""
        from webpent.shared.preflight import enforce_construction_escape_gate

        monkeypatch.setenv("WEBPENT_ENVIRONMENT_PROFILE", "production")
        report = enforce_construction_escape_gate()
        assert report["status"] == "ok — escape not set"

    def test_any_profile_alias_is_honored_fail_closed(self, monkeypatch):
        """Fail-closed by design: any of the three environment_profile
        aliases indicating a strict posture is enough to trip the gate,
        independent of which one config.settings.Settings itself would
        treat as authoritative."""
        from webpent.shared.preflight import enforce_construction_escape_gate

        monkeypatch.setenv(self.ESCAPE_VAR, "1")
        monkeypatch.setenv("ENVIRONMENT_PROFILE", "staging")
        with pytest.raises(SystemExit):
            enforce_construction_escape_gate()

    def test_run_preflight_includes_construction_escape_check(self, monkeypatch):
        """The full run_preflight() report (used by api/app.py and
        workers/pentest_worker.py) carries this check automatically."""
        from webpent.shared.preflight import run_preflight

        report = run_preflight()
        assert "construction_escape" in report
        assert "status" in report["construction_escape"]

    def test_run_preflight_fails_closed_too(self, monkeypatch):
        from webpent.shared.preflight import run_preflight

        monkeypatch.setenv(self.ESCAPE_VAR, "1")
        monkeypatch.setenv("WEBPENT_ENVIRONMENT_PROFILE", "production")
        with pytest.raises(SystemExit):
            run_preflight()


class TestCombinedReconProtectedKeys:
    """Item 1.4: legacy recon output must not clobber modern-spine-produced
    hypotheses / candidate_hypotheses."""

    def test_legacy_cannot_clobber_hypotheses_or_candidate_hypotheses(self, monkeypatch):
        os.environ.setdefault(
            "WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890"
        )
        from webpent.graph import builder as builder_mod

        def fake_modern(state):
            out = dict(state)
            out["modern_spine_active"] = True
            out["legacy_recon_advisory_only"] = True
            out["hypotheses"] = ["MODERN_HYP_A"]
            out["candidate_hypotheses"] = ["MODERN_CAND_A"]
            return out

        def fake_legacy(state):
            return {
                "hypotheses": ["LEGACY_HYP_CLOBBER"],
                "candidate_hypotheses": ["LEGACY_CAND_CLOBBER"],
                "some_other_legacy_field": "legacy_value",
            }

        monkeypatch.setattr(builder_mod, "modern_spine_recon_node", fake_modern)
        monkeypatch.setattr(builder_mod, "recon_node", fake_legacy)

        graph = builder_mod.build_graph()
        node = graph.nodes["recon"]
        state = {
            "engagement_id": "eng_1_4_test",
            "target_url": "https://lab.example.com",
            "url": "https://lab.example.com",
        }
        out = node.invoke(state)

        # Protected: modern values survive the legacy merge.
        assert out.get("hypotheses") == ["MODERN_HYP_A"]
        assert out.get("candidate_hypotheses") == ["MODERN_CAND_A"]
        # Sanity: non-protected legacy fields still merge through normally
        # (proves the fix didn't accidentally wall off ALL legacy output).
        assert out.get("some_other_legacy_field") == "legacy_value"
