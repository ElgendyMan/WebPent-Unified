# tests/test_vulnbox_benchmark.py
"""2026-10-25 proposals, Proposal 6 — vulnerable-apps benchmark harness.

Mini-scale: three fixture modes served on loopback, the REAL probe
nodes run against them with production flags ON, findings flow through
the canonical validators, and the confusion matrix is scored against
the planted ground truth.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "src")):
    if p not in sys.path:
        sys.path.insert(0, p)

fx = importlib.import_module("webpent.benchmark.fixtures")
va = importlib.import_module("webpent.benchmark.fixtures.vulnbox_app")
ms = importlib.import_module("webpent.benchmark.metrics_store")
settings_mod = importlib.import_module("webpent.config.settings")

import json  # noqa: E402

from starlette.testclient import TestClient  # noqa: E402
import pytest  # noqa: E402


# ---------------------------------------------------------------------------
# Fixture app behavior (direct, without the pipeline)
# ---------------------------------------------------------------------------
class TestVulnboxApp:
    def test_unknown_mode_rejected(self):
        with pytest.raises(ValueError):
            va.build_vulnbox_app("nope")

    def test_graphql_introspection_exposed(self):
        app = va.build_vulnbox_app("graphql")
        client = TestClient(app)
        with client:
            resp = client.post("/graphql", json={"query": "{ __schema { types { name } } }"})
        assert resp.status_code == 200
        assert resp.json()["data"]["__schema"]["types"]

    def test_graphql_error_channel_has_no_suggestions(self):
        app = va.build_vulnbox_app("graphql")
        client = TestClient(app)
        with client:
            resp = client.post("/graphql", json={"query": "{ xuserx }"})
        assert "did you mean" not in resp.text.lower()

    def test_web_cache_poisoning_two_request_proof(self):
        app = va.build_vulnbox_app("web")
        client = TestClient(app)
        with client:
            baseline = client.get("/")
            poison = client.get("/", headers={"X-Forwarded-Host": "evil.example"})
            victim = client.get("/")
            control = client.get("/?webpent_control_probe=1")
        assert "evil.example" not in baseline.text
        assert "evil.example" in poison.text
        assert victim.headers.get("x-cache") == "HIT"
        assert "evil.example" in victim.text  # served from cache, unpoisoned request
        assert "evil.example" not in control.text

    def test_web_prototype_pollution_reflection_vs_benign(self):
        app = va.build_vulnbox_app("web")
        client = TestClient(app)
        with client:
            candidate = client.get("/?__proto__[webpent_probe]=mkr")
            control = client.get("/?benign[webpent_probe]=mkr")
        assert "mkr" in candidate.text
        assert "mkr" not in control.text

    def test_clean_mode_confirms_nothing(self):
        app = va.build_vulnbox_app("clean")
        client = TestClient(app)
        with client:
            poison = client.get("/", headers={"X-Forwarded-Host": "evil.example"})
            victim = client.get("/")
            pp = client.get("/?__proto__[webpent_probe]=mkr")
        assert "evil.example" not in victim.text
        assert "mkr" not in pp.text
        assert poison.status_code == 200

    def test_request_counter_counts(self):
        app = va.build_vulnbox_app("web")
        client = TestClient(app)
        with client:
            client.get("/"); client.get("/"); client.get("/")
        assert app.state.request_count["requests"] == 3


# ---------------------------------------------------------------------------
# Full pipeline campaign (real probe nodes -> canonical validators)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def campaign_report():
    return fx.run_vulnbox_campaign()


class TestVulnboxCampaign:
    def test_graphql_target_confirms_introspection(self, campaign_report):
        result = next(r for r in campaign_report.results if r.mode == "graphql")
        assert result.confirmed == ("graphql_introspection_exposure",)
        assert result.validator_errors == ()

    def test_web_target_confirms_both_web_vulns(self, campaign_report):
        result = next(r for r in campaign_report.results if r.mode == "web")
        assert result.confirmed == ("cache_poisoning", "prototype_pollution")
        assert result.validator_errors == ()

    def test_clean_target_zero_confirmed(self, campaign_report):
        result = next(r for r in campaign_report.results if r.mode == "clean")
        assert result.confirmed == ()

    def test_confusion_matrix_perfect_at_planted_scale(self, campaign_report):
        assert campaign_report.fn == ()
        assert campaign_report.fp == ()
        assert len(campaign_report.tp) == 3  # introspection + cache + pollution

    def test_report_serializes(self, campaign_report):
        payload = json.dumps(campaign_report.as_dict())
        assert "graphql_introspection_exposure" in payload


# ---------------------------------------------------------------------------
# Metrics store
# ---------------------------------------------------------------------------
class TestMetricsStore:
    def test_roundtrip_and_history(self, campaign_report):
        store = ms.VulnboxMetricsStore(":memory:")
        try:
            run_id = store.record_report(campaign_report)
            assert run_id == campaign_report.run_id
            latest = store.latest()
            assert latest is not None
            assert latest["run_id"] == run_id
            assert "cache_poisoning" in latest["tp"]
            assert len(store.history(limit=5)) == 1
        finally:
            store.close()

    def test_history_records_regression_timeline(self, campaign_report):
        store = ms.VulnboxMetricsStore(":memory:")
        try:
            store.record_report(campaign_report)
            degraded = fx.VulnboxBenchmarkReport(
                run_id="degraded01",
                results=(),
                tp=("cache_poisoning",),
                fp=(),
                fn=("prototype_pollution", "graphql_introspection_exposure"),
            )
            store.record_report(degraded)
            history = store.history(limit=2)
            assert history[0]["run_id"] == "degraded01"
            assert "prototype_pollution" in history[0]["fn"]
        finally:
            store.close()


# ---------------------------------------------------------------------------
# Flag gating
# ---------------------------------------------------------------------------
class TestFlagGating:
    def test_flag_defaults_off(self):
        s = settings_mod.Settings()
        assert s.enable_benchmark_gate is False

    def test_smoke_mode_runs_no_nodes(self):
        report = fx.run_vulnbox_campaign(("clean",), run_nodes=False)
        assert report.tp == () and report.fp == () and report.fn == ()
        assert report.results[0].probe_nodes_run == ()
