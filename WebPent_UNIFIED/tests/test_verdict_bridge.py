"""Accountability Spine — verdict bridge tests (Round 4, red-first).

The bridge couples the AVI campaign loop to the 47-day Verdict Protocol:
a pre-flight gate (real targets require a frozen pre-registration) and
an auto-registration bridge (promoted findings land in the verdict
workspace with real evidence, via the verdict tool's CLI subprocess —
zero imports, package isolation preserved).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VERDICT_DIR = REPO_ROOT / "verdict"


def _verdict_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(VERDICT_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _cli(ws: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "verdict_tool.cli", "--path", str(ws), *args],
        cwd=VERDICT_DIR, env=_verdict_env(),
        capture_output=True, text=True, check=check,
    )


@pytest.fixture()
def ws(tmp_path) -> Path:
    """An initialized verdict workspace with a FROZEN pre-registration."""
    w = tmp_path / "verdict_ws"
    _cli(w, "init")
    _cli(w, "pre-registration", "predict", "--findings", "1", "10",
         "--acceptance", "0.2", "0.8")
    _cli(w, "pre-registration", "done")
    return w


@pytest.fixture()
def unfrozen_ws(tmp_path) -> Path:
    w = tmp_path / "verdict_ws_unfrozen"
    _cli(w, "init")
    return w


def _set_workspace_env(monkeypatch, path: Path | None) -> None:
    if path is None:
        monkeypatch.delenv("WEBPENT_VERDICT_WORKSPACE", raising=False)
    else:
        monkeypatch.setenv("WEBPENT_VERDICT_WORKSPACE", str(path))


def _campaign_result(promoted: bool = True) -> dict:
    """A minimal campaign result shaped like AVI's run_campaign output."""
    finding = {
        "finding_id": "fid_0001",
        "hypothesis_id": "h_1",
        "vulnerability_class": "SQLI",
        "experiment_id": "exp_1",
        "evidence_quality": 5,
        "bundle_id": "bundle_abc123",
        "seal_digest": "deadbeef" * 8,
        "promotion": {"decision": "PROMOTED", "gates_passed": [
            "real_runtime_observations", "causal_validator_confirmed"]},
        "replay_verified": True,
        "proof_trace": {"bundle_id": "bundle_abc123", "promotion": "PROMOTED"},
    }
    return {
        "avi_version": "AVI_V1.2",
        "target_url_digest": "abcdef1234567890",
        "decisions_executed": 3,
        "promoted_count": 1 if promoted else 0,
        "rejected_count": 0,
        "security_report": {
            "promoted_findings": [finding] if promoted else [],
            "rejected_findings": [],
        },
    }


# ---------------------------------------------------------------------------
# The pre-flight gate
# ---------------------------------------------------------------------------
class TestVerdictPreflight:
    def test_blocks_uninitialized_workspace(self, tmp_path, monkeypatch):
        from webpent.production.verdict_bridge import VerdictGateError, verdict_preflight
        _set_workspace_env(monkeypatch, tmp_path / "no_such_ws")
        with pytest.raises(VerdictGateError, match="workspace"):
            verdict_preflight("https://real-target.example.com/api/")

    def test_blocks_unfrozen_prereg(self, unfrozen_ws, monkeypatch):
        from webpent.production.verdict_bridge import VerdictGateError, verdict_preflight
        _set_workspace_env(monkeypatch, unfrozen_ws)
        with pytest.raises(VerdictGateError, match="pre-registration"):
            verdict_preflight("https://real-target.example.com/api/")

    def test_allows_frozen_prereg(self, ws, monkeypatch):
        from webpent.production.verdict_bridge import verdict_preflight
        _set_workspace_env(monkeypatch, ws)
        decision = verdict_preflight("https://real-target.example.com/api/")
        assert decision["gate"] == "pass"
        assert decision["pre_registered"] is True
        assert decision["workspace"] == str(ws)

    def test_exempt_loopback(self, tmp_path, monkeypatch):
        from webpent.production.verdict_bridge import verdict_preflight
        _set_workspace_env(monkeypatch, tmp_path / "no_such_ws")
        for url in ("http://127.0.0.1:8080/api/",
                    "http://localhost:3000/",
                    "http://[::1]:9000/gql"):
            decision = verdict_preflight(url)
            assert decision["gate"] == "exempt_loopback", url

    def test_escape_is_recorded_not_silent(self, tmp_path, monkeypatch):
        from webpent.production.verdict_bridge import verdict_preflight
        _set_workspace_env(monkeypatch, tmp_path / "no_such_ws")
        monkeypatch.setenv("WEBPENT_REQUIRE_VERDICT_PREREG", "0")
        decision = verdict_preflight("https://real-target.example.com/api/")
        assert decision["gate"] == "escape"
        assert decision["escape_used"] is True

    def test_detects_tampered_state(self, ws, monkeypatch):
        from webpent.production.verdict_bridge import VerdictGateError, verdict_preflight
        _set_workspace_env(monkeypatch, ws)
        state_file = ws / ".verdict" / "state.json"
        state = json.loads(state_file.read_text())
        state["pre_registered"] = True  # forged GO attempt
        state_file.write_text(json.dumps(state))
        with pytest.raises(VerdictGateError, match="tampered|modified"):
            verdict_preflight("https://real-target.example.com/api/")


# ---------------------------------------------------------------------------
# The registration bridge
# ---------------------------------------------------------------------------
class TestRegisterCampaignFindings:
    def test_registers_promoted_finding_via_cli(self, ws, monkeypatch):
        from webpent.production.verdict_bridge import register_campaign_findings
        _set_workspace_env(monkeypatch, ws)
        summary = register_campaign_findings(_campaign_result())
        assert summary["registered"] == ["fid_0001"]
        assert summary["promoted_total"] == 1
        # The finding is visible to the verdict tool itself.
        out = _cli(ws, "findings", "list").stdout
        assert "fid_0001" in out

    def test_writes_real_evidence_files(self, ws, monkeypatch):
        from webpent.production.verdict_bridge import register_campaign_findings
        _set_workspace_env(monkeypatch, ws)
        register_campaign_findings(_campaign_result())
        evidence = ws / "evidence" / "fid_0001.json"
        assert evidence.is_file()
        payload = json.loads(evidence.read_text())
        assert payload["bundle_id"] == "bundle_abc123"
        assert payload["promotion"]["decision"] == "PROMOTED"
        assert payload["source"] == "avi_campaign"

    def test_second_run_skips_duplicates_safely(self, ws, monkeypatch):
        from webpent.production.verdict_bridge import register_campaign_findings
        _set_workspace_env(monkeypatch, ws)
        register_campaign_findings(_campaign_result())
        summary = register_campaign_findings(_campaign_result())
        assert summary["registered"] == []
        assert summary["skipped"] == ["fid_0001"]
        assert summary["blocked"] == []

    def test_registration_failure_is_recorded_not_raised(self, ws, monkeypatch):
        from webpent.production import verdict_bridge
        _set_workspace_env(monkeypatch, ws)

        def _refuse(*args, **kwargs):
            raise verdict_bridge.VerdictRegistrationError(
                "verdict CLI refused registration: integrity check failed")

        monkeypatch.setattr(verdict_bridge, "_register_via_cli", _refuse)
        summary = verdict_bridge.register_campaign_findings(_campaign_result())
        assert summary["registered"] == []
        assert len(summary["blocked"]) == 1
        assert "reason" in summary["blocked"][0]

    def test_zero_promoted_is_a_clean_noop(self, ws, monkeypatch):
        from webpent.production.verdict_bridge import register_campaign_findings
        _set_workspace_env(monkeypatch, ws)
        summary = register_campaign_findings(_campaign_result(promoted=False))
        assert summary["registered"] == [] and summary["promoted_total"] == 0

    def test_bridge_imports_nothing_from_verdict_package(self):
        source = (REPO_ROOT / "src" / "webpent" / "production"
                  / "verdict_bridge.py").read_text()
        assert "import verdict_tool" not in source
        assert "from verdict_tool" not in source

    def test_finding_id_path_traversal_is_blocked(self, ws, monkeypatch):
        """WG-R4.1: a crafted finding_id must not place evidence outside
        the evidence directory or smuggle a traversal id into the ledger."""
        from webpent.production.verdict_bridge import register_campaign_findings
        _set_workspace_env(monkeypatch, ws)
        result = _campaign_result()
        result["security_report"]["promoted_findings"][0]["finding_id"] = (
            "../escaped_evil")
        summary = register_campaign_findings(result)
        assert summary["registered"] == []
        assert len(summary["blocked"]) == 1
        assert "finding_id" in summary["blocked"][0]["reason"]
        assert not (ws / "escaped_evil.json").exists()
        assert not (ws / "evidence" / "escaped_evil.json").exists()

    def test_no_orphan_evidence_on_refusal(self, ws, monkeypatch):
        """WG-R4.2: evidence must not outlive its registration — a refused
        registration must leave no evidence artifact behind to mislead the
        day-14 re-test."""
        from webpent.production import verdict_bridge
        _set_workspace_env(monkeypatch, ws)

        def _refuse(*args, **kwargs):
            raise verdict_bridge.VerdictRegistrationError("refused")

        monkeypatch.setattr(verdict_bridge, "_register_via_cli", _refuse)
        summary = verdict_bridge.register_campaign_findings(_campaign_result())
        assert summary["blocked"]
        assert summary["evidence_files"] == []
        assert not (ws / "evidence" / "fid_0001.json").exists()


# ---------------------------------------------------------------------------
# Wiring: the campaign dispatch path uses the bridge
# ---------------------------------------------------------------------------
class TestCampaignWiring:
    def test_campaign_result_carries_verdict_bridge_block(self, monkeypatch):
        """Loopback target (exempt) — the result still records the gate."""
        _set_workspace_env(monkeypatch, None)
        monkeypatch.delenv("WEBPENT_REQUIRE_VERDICT_PREREG", raising=False)
        from webpent.live_hunter.profile import AuthorizedLabProfile
        from webpent.live_hunter.tool_scope import ScopeLaw
        from webpent.production.modern_spine import ModernOrchestrator
        profile = AuthorizedLabProfile(
            authorized_targets=("127.0.0.1", "localhost"),
            engagement_id="eng_verdict_bridge",
            operator_approval_at="2026-09-15T00:00:00Z",
            knowledge_ready=True,
        )
        orch = ModernOrchestrator(
            engagement_id="eng_verdict_bridge",
            scope_law=ScopeLaw(profile=profile, engagement_id="eng_verdict_bridge"),
        )
        hyps = [{
            "id": "vb_h1", "vulnerability_class": "SQLI", "path": "/api/items",
            "method": "GET", "param": "q", "payload": "' OR 1=1--",
        }]
        result = orch.run_autonomous_validation_campaign(
            target_url="http://127.0.0.1:9/vb", hypotheses=hyps, max_decisions=1)
        assert "verdict_bridge" in result
        assert result["verdict_bridge"]["gate"]["gate"] == "exempt_loopback"


# ---------------------------------------------------------------------------
# Round 5: recipe capture + the re-test dispatch engine
# ---------------------------------------------------------------------------
def _finding_with_sequence() -> dict:
    finding = _campaign_result()["security_report"]["promoted_findings"][0]
    finding["experiment_id"] = "exp_sqli_v1"
    finding["request_sequence"] = [
        {"role": "baseline", "method": "GET", "url": "http://t.example/api/items"},
        {"role": "candidate", "method": "GET",
         "url": "http://t.example/api/items?q=' OR 1=1--"},
        {"role": "negative_control", "method": "GET",
         "url": "http://t.example/api/items?q=safe"},
    ]
    return finding


class TestReplayRecipeCapture:
    def test_evidence_payload_carries_replay_recipe(self, ws, monkeypatch):
        from webpent.production.verdict_bridge import register_campaign_findings
        _set_workspace_env(monkeypatch, ws)
        result = _campaign_result()
        result["security_report"]["promoted_findings"] = [_finding_with_sequence()]
        register_campaign_findings(result)
        payload = json.loads((ws / "evidence" / "fid_0001.json").read_text())
        recipe = payload["replay_recipe"]
        assert [r["role"] for r in recipe["roles"]] == [
            "baseline", "candidate", "negative_control"]
        assert recipe["roles"][1]["method"] == "GET"
        assert "' OR 1=1--" in recipe["roles"][1]["url"]
        assert recipe["experiment_id"] == "exp_sqli_v1"
        assert recipe["vulnerability_class"] == "SQLI"

    def test_evidence_without_request_sequence_has_null_recipe(self, ws, monkeypatch):
        from webpent.production.verdict_bridge import register_campaign_findings
        _set_workspace_env(monkeypatch, ws)
        register_campaign_findings(_campaign_result())
        payload = json.loads((ws / "evidence" / "fid_0001.json").read_text())
        assert payload["replay_recipe"] is None


class TestDispatchRetest:
    def _register_with_recipe(self, ws, monkeypatch):
        from webpent.production.verdict_bridge import register_campaign_findings
        _set_workspace_env(monkeypatch, ws)
        result = _campaign_result()
        result["security_report"]["promoted_findings"] = [_finding_with_sequence()]
        summary = register_campaign_findings(result)
        assert summary["registered"] == ["fid_0001"]
        return summary

    @staticmethod
    def _executor(differs: bool = True, fail: bool = False):
        calls = []

        def _run(method: str, url: str) -> dict:
            if fail:
                raise OSError("transport down")
            calls.append((method, url))
            status = 500 if (differs and "1=1" in url) else 200
            return {"status_code": status, "body": f"resp-{status}"}

        _run.calls = calls
        return _run

    def test_dispatch_retest_reads_recipes_from_workspace_evidence(
            self, ws, monkeypatch):
        self._register_with_recipe(ws, monkeypatch)
        from webpent.production.verdict_bridge import dispatch_retest
        _set_workspace_env(monkeypatch, ws)
        ex = self._executor()
        summary = dispatch_retest(target_url="http://127.0.0.1:9/rt",
                                  executor=ex)
        assert summary["dispatched"] == ["fid_0001"]
        assert len(ex.calls) == 3

    def test_dispatch_retest_blocks_real_target_without_frozen_prereg(
            self, unfrozen_ws, monkeypatch):
        self._register_with_recipe(unfrozen_ws, monkeypatch)
        from webpent.production.verdict_bridge import VerdictGateError, dispatch_retest
        _set_workspace_env(monkeypatch, unfrozen_ws)
        with pytest.raises(VerdictGateError, match="pre-registration"):
            dispatch_retest(target_url="https://real-target.example.com/api/",
                            executor=self._executor())

    def test_dispatch_retest_loopback_exempt(self, ws, monkeypatch):
        self._register_with_recipe(ws, monkeypatch)
        from webpent.production.verdict_bridge import dispatch_retest
        _set_workspace_env(monkeypatch, ws)
        summary = dispatch_retest(target_url="http://127.0.0.1:9/rt",
                                  executor=self._executor())
        assert summary["gate"]["gate"] == "exempt_loopback"
        assert summary["dispatched"] == ["fid_0001"]

    def test_dispatch_retest_executes_triple_and_records_observations(
            self, ws, monkeypatch):
        self._register_with_recipe(ws, monkeypatch)
        from webpent.production.verdict_bridge import dispatch_retest
        _set_workspace_env(monkeypatch, ws)
        ex = self._executor(differs=True)
        dispatch_retest(target_url="http://127.0.0.1:9/rt", executor=ex)
        # recipe order preserved
        assert ex.calls == [("GET", "http://t.example/api/items"),
                            ("GET", "http://t.example/api/items?q=' OR 1=1--"),
                            ("GET", "http://t.example/api/items?q=safe")]
        evidence = json.loads(
            (ws / "evidence" / "fid_0001.retest.json").read_text())
        obs = evidence["observations"]
        assert [o["role"] for o in obs] == [
            "baseline", "candidate", "negative_control"]
        assert obs[0]["status_code"] == 200 and obs[1]["status_code"] == 500
        import hashlib
        assert obs[1]["response_digest"] == hashlib.sha256(
            b"resp-500").hexdigest()

    def test_dispatch_retest_writes_retest_evidence_file(self, ws, monkeypatch):
        self._register_with_recipe(ws, monkeypatch)
        from webpent.production.verdict_bridge import dispatch_retest
        _set_workspace_env(monkeypatch, ws)
        dispatch_retest(target_url="http://127.0.0.1:9/rt",
                        executor=self._executor())
        evidence = json.loads(
            (ws / "evidence" / "fid_0001.retest.json").read_text())
        assert evidence["source"] == "retest_dispatch"
        assert evidence["finding_id"] == "fid_0001"
        assert evidence["candidate_differs_from_baseline"] is True

    def test_dispatch_retest_missing_recipe_is_typed_blocker(
            self, ws, monkeypatch):
        # register TWO findings: one with a recipe, one without
        from webpent.production.verdict_bridge import register_campaign_findings
        _set_workspace_env(monkeypatch, ws)
        result = _campaign_result()
        findings = [_finding_with_sequence()]
        no_recipe = dict(_campaign_result()["security_report"]
                         ["promoted_findings"][0])
        no_recipe["finding_id"] = "fid_0002"
        findings.append(no_recipe)
        result["security_report"]["promoted_findings"] = findings
        assert register_campaign_findings(result)["registered"] == [
            "fid_0001", "fid_0002"]
        from webpent.production.verdict_bridge import dispatch_retest
        _set_workspace_env(monkeypatch, ws)
        summary = dispatch_retest(target_url="http://127.0.0.1:9/rt",
                                  executor=self._executor())
        assert summary["dispatched"] == ["fid_0001"]
        assert [b["finding"] for b in summary["blocked"]] == ["fid_0002"]
        assert "recipe" in summary["blocked"][0]["reason"]
        assert not (ws / "evidence" / "fid_0002.retest.json").exists()

    def test_dispatch_retest_executor_failure_is_typed_blocker(
            self, ws, monkeypatch):
        self._register_with_recipe(ws, monkeypatch)
        from webpent.production.verdict_bridge import dispatch_retest
        _set_workspace_env(monkeypatch, ws)
        summary = dispatch_retest(target_url="http://127.0.0.1:9/rt",
                                  executor=self._executor(fail=True))
        assert summary["dispatched"] == []
        assert summary["blocked"] and "transport down" in \
            summary["blocked"][0]["reason"]
        assert not (ws / "evidence" / "fid_0001.retest.json").exists()

    def test_dispatch_retest_never_invokes_classify(self, ws, monkeypatch):
        self._register_with_recipe(ws, monkeypatch)
        from webpent.production.verdict_bridge import dispatch_retest
        _set_workspace_env(monkeypatch, ws)
        dispatch_retest(target_url="http://127.0.0.1:9/rt",
                        executor=self._executor())
        source = (REPO_ROOT / "src" / "webpent" / "production"
                  / "verdict_bridge.py").read_text()
        # No invocation: the CLI arg pair used for registration exists, but
        # no command list ever contains the classify subcommand.
        assert '"findings", "classify"' not in source
        assert "'findings', 'classify'" not in source
        evidence = json.loads(
            (ws / "evidence" / "fid_0001.retest.json").read_text())
        # Observations only: no classification/severity keys, no "confirmed".
        assert "classification" not in evidence
        assert "severity" not in evidence
        assert "confirmed" not in json.dumps(evidence)

    def test_dispatch_retest_summary_carries_operator_handoff(
            self, ws, monkeypatch):
        self._register_with_recipe(ws, monkeypatch)
        from webpent.production.verdict_bridge import dispatch_retest
        _set_workspace_env(monkeypatch, ws)
        summary = dispatch_retest(target_url="http://127.0.0.1:9/rt",
                                  executor=self._executor())
        cmd = summary["operator_handoff"]["fid_0001"]
        assert "findings classify fid_0001" in cmd
        assert "-e" in cmd and "fid_0001.retest.json" in cmd
        assert "fid_0001.json" in cmd
        assert "<classification>" in cmd and "<severity_confirmed>" in cmd

    def test_dispatch_retest_requires_target_and_executor(self, ws, monkeypatch):
        self._register_with_recipe(ws, monkeypatch)
        from webpent.production.verdict_bridge import dispatch_retest
        _set_workspace_env(monkeypatch, ws)
        with pytest.raises(ValueError, match="target_url"):
            dispatch_retest(executor=self._executor())
        with pytest.raises(ValueError, match="executor"):
            dispatch_retest(target_url="http://127.0.0.1:9/rt")
