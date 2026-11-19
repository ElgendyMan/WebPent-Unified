"""IMPLEMENTATION-team regression tests for the P0 / Phase-2 fixes.

Each test pins one fix from the implementation brief:
  * IMPL P0-A — scan-registry reads the GLOBAL database even inside a
    target-workspace activation (sibling-thread split-brain), and the
    workspace-scoped OOB callback fails closed when the thread cannot be
    resolved (no default-database fallback).
  * IMPL P0-C — a Refuted finding always wins its fingerprint group on the
    read-side projection (no read-path resurrection), and the "Not Scanned"
    finding only fires when the seed URL produced ZERO hypotheses.
  * IMPL P0-D — the keyword-path prior is complementary only: generic
    structural producers run first and keep the portfolio slot for their
    class.
  * IMPL P0-F — the httpx scope gate refuses to spawn a subprocess when
    every input domain was dropped.
  * IMPL Phase 2-G — the smart-campaigns replan router enforces the
    evidence-monotonic law (each extra round must add deterministic
    evidence).
  * IMPL Phase 2-H — legacy lesson retrieval is narrowed to the current
    engagement (cross-target poisoning isolation).
"""

from __future__ import annotations

import types
import uuid

import pytest

import webpent.agents.hypothesis_analyzer.agent as ha
import webpent.shared.target_workspace_context as twc
import webpent.tools.recon.httpx as httpx_mod
from webpent.agents.hypothesis_analyzer.agent import hypothesis_node
from webpent.api.scan_registry import (
    get_thread_ids_by_engagement_id,
    register_scan,
)
from webpent.config.settings import get_settings
from webpent.graph.builder import (
    NODE_SMART_CAMPAIGNS,
    NODE_STRATEGIST,
    route_after_smart_campaigns_execution,
)
from webpent.models.findings import Finding, Severity
from webpent.models.targets import Target
from webpent.shared.engagement_scope import clear_engagement_target_hosts
from webpent.shared.finding_aggregation import aggregate_findings


@pytest.fixture(autouse=True)
def _offline_env(monkeypatch):
    """Keep the tier hermetic: offline LLM/RAG/auth, no external calls."""
    monkeypatch.setenv("LLM_ENABLED", "false")
    monkeypatch.setenv("EMBEDDINGS_OFFLINE", "true")
    monkeypatch.setenv("DISABLE_RAG", "true")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("FFUF_ENABLED", "false")
    monkeypatch.setenv("WEBHOOK_ENABLED", "false")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _hyp_state(url: str, skip_recon: bool = True) -> dict:
    return {
        "target": Target(url=url),
        "hypotheses": [],
        "crawled_data": {"endpoints": [], "forms": []},
        "skip_recon": skip_recon,
        "thread_id": str(uuid.uuid4()),
        "client_id": "impl-client",
        "engagement_id": "impl-engagement",
    }


# ---------------------------------------------------------------------------
# IMPL P0-A — scan-registry global-DB resolution under workspace activation
# ---------------------------------------------------------------------------


def test_registry_reads_global_db_under_workspace_activation(
    tmp_path, monkeypatch
):
    registry_url = f"sqlite:///{tmp_path}/registry.sqlite3"
    monkeypatch.setenv("WEBPENT_DATABASE_URL", registry_url)
    get_settings.cache_clear()

    assert register_scan(
        "thread-1",
        "task-1",
        target_url="http://t.example",
        engagement_id="eng-impl-1",
        owner_username="owner",
        client_id="client",
    )

    # Simulate an active target workspace: get_db_manager() with no URL
    # would now resolve to the WORKSPACE database (the pre-fix defect read
    # the registry from there and found nothing).
    fake_workspace = types.SimpleNamespace(
        database_url=f"sqlite:///{tmp_path}/workspace.sqlite3"
    )
    monkeypatch.setattr(
        twc, "get_active_target_workspace", lambda: fake_workspace
    )

    threads = get_thread_ids_by_engagement_id(
        "eng-impl-1", owner_username="owner", client_id="client"
    )
    assert threads == ["thread-1"], (
        "registry lookup under workspace activation must read the GLOBAL "
        "default database, not the workspace's empty scan_engagements copy"
    )


# ---------------------------------------------------------------------------
# IMPL P0-A — OOB callback fails closed on unresolvable thread
# ---------------------------------------------------------------------------


def test_oob_unknown_thread_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBPENT_DATABASE_URL", f"sqlite:///{tmp_path}/api.sqlite3")
    monkeypatch.setenv("WEBPENT_OOB_CALLBACK_SECRET", "impl-test-secret")
    # Sprint R1 FIX 2: the OOB confirmation route is now fail-closed-by-
    # default (separate from the secret above). This test exercises the
    # "unknown thread" logic inside the route, so the route itself must be
    # explicitly enabled first — otherwise every request 404s before ever
    # reaching the thread-lookup code this test targets.
    monkeypatch.setenv("WEBPENT_OOB_CONFIRM_ROUTE_ENABLED", "1")
    get_settings.cache_clear()

    from fastapi.testclient import TestClient

    from webpent.api.app import app

    client = TestClient(app)
    response = client.get(f"/api/oob/{uuid.uuid4()}/{uuid.uuid4()}/tok")
    assert response.status_code == 404
    assert "workspace could not" in response.json()["detail"], (
        "a 3-segment OOB callback whose thread has no registry record must "
        "fail closed instead of falling back to the default database"
    )


# ---------------------------------------------------------------------------
# IMPL P0-C — Refuted terminal precedence on the read-side projection
# ---------------------------------------------------------------------------


def _finding(title: str, level: str, vuln_class: str = "sqli", **extra) -> Finding:
    return Finding(
        title=title,
        description="impl test finding",
        severity=Severity.HIGH,
        confidence_level=level,
        vuln_class=vuln_class,
        url="http://t.example/x",
        tool_name="impl-test",
        payload="",
        reasoning="",
        **extra,
    )


def test_refuted_wins_its_fingerprint_group():
    refuted = _finding("SQLi at x", "Refuted")
    newer_tentative = _finding("SQLi at x", "Pending")

    projected = aggregate_findings([refuted, newer_tentative])
    assert len(projected) == 1
    assert projected[0].confidence_level == "Refuted", (
        "a newer tentative duplicate must not resurrect a refuted claim on "
        "the read path"
    )


def test_non_refuted_group_keeps_historical_strongest_wins():
    poorer = _finding("SQLi at x", "Pending")
    richer = _finding("SQLi at x", "Pending", business_impact="full takeover")
    projected = aggregate_findings([poorer, richer])
    assert len(projected) == 1
    assert projected[0].business_impact == "full takeover"  # strongest wins


# ---------------------------------------------------------------------------
# IMPL P0-C/D — "Not Scanned" only fires when the seed produced nothing
# ---------------------------------------------------------------------------


def test_not_scanned_suppressed_when_generic_producer_covers_seed():
    url = "https://10.1.2.3:9000/records?next=/dashboard"
    result = hypothesis_node(_hyp_state(url))
    findings = result.get("findings") or []
    assert not [f for f in findings if str(f.title).startswith("Not Scanned")], (
        "generic producers covered this seed — 'Not Scanned' would be a "
        "misleading operator signal"
    )
    assert any(h.vuln_class == "open_redirect" for h in result["hypotheses"])


def test_not_scanned_emitted_when_seed_has_zero_coverage():
    url = "http://10.1.2.3:9000/plainpage"
    result = hypothesis_node(_hyp_state(url))
    findings = result.get("findings") or []
    assert any(str(f.title).startswith("Not Scanned") for f in findings), (
        "a paramless, keywordless seed under skip_recon must still surface "
        "the explicit Not Scanned signal (no silent findings=[])"
    )


# ---------------------------------------------------------------------------
# IMPL P0-D — keyword-path prior is complementary to generic producers
# ---------------------------------------------------------------------------


def test_path_prior_suppressed_when_generic_producer_covered_class(monkeypatch):
    url = "https://10.1.2.3/orders/12345/"
    # The generic path-parameter producer already emits sqli for this URL
    # shape (pinned in test_team1_non_dvwa_hypotheses). The keyword-path
    # prior must NOT claim the same (url, class) slot. The path classifier
    # is a nested closure that delegates to the module-level
    # _classify_by_url_path, so patch that.
    monkeypatch.setattr(
        ha,
        "_classify_by_url_path",
        lambda u: ("sqli", "stub path reason") if str(u) == url else None,
    )
    result = hypothesis_node(_hyp_state(url))
    sqli = [
        h
        for h in result["hypotheses"]
        if h.vuln_class == "sqli"
        and str(h.target_url).rstrip("/") == url.rstrip("/")
    ]
    assert len(sqli) == 1, "exactly one hypothesis per (url, class) slot"
    assert "generic structural" in str(sqli[0].origin_detail), (
        "the generic structural producer must own the slot; the DVWA-shaped "
        "keyword table may not take priority over structural signals"
    )


# ---------------------------------------------------------------------------
# IMPL P0-F — httpx scope gate skips the subprocess when all is dropped
# ---------------------------------------------------------------------------


def test_httpx_scope_gate_skips_subprocess_when_all_dropped(monkeypatch):
    clear_engagement_target_hosts()

    def _boom(*args, **kwargs):
        raise AssertionError(
            "subprocess must not be spawned when no in-scope domains remain"
        )

    monkeypatch.setattr(httpx_mod, "run_command", _boom)
    assert httpx_mod.run_httpx(["internal.example.com", "10.0.0.5"]) == []


# ---------------------------------------------------------------------------
# IMPL Phase 2-G — smart-campaigns replan router is evidence-monotonic
# ---------------------------------------------------------------------------


def _replan_state(**replanning_overrides) -> dict:
    replanning = {
        "status": "executed",
        "round": 1,
        "max_replan_rounds": 3,
        "replan_requested": True,
        "replan_evidence_start": 1,
        "replan_evidence_end": 2,
    }
    replanning.update(replanning_overrides)
    return {"smart_replanning": replanning}


def test_smart_replan_continues_only_on_evidence_growth():
    gate = route_after_smart_campaigns_execution
    assert gate(_replan_state()) == NODE_SMART_CAMPAIGNS
    # No deterministic evidence added during the round -> no replan.
    assert (
        gate(_replan_state(replan_evidence_end=1)) == NODE_STRATEGIST
    )
    # Missing markers (pre-fix in-flight checkpoints) fail closed.
    assert (
        gate(_replan_state(replan_evidence_start=0, replan_evidence_end=0))
        == NODE_STRATEGIST
    )
    # Round budget exhausted.
    assert gate(_replan_state(round=3)) == NODE_STRATEGIST
    # No replan requested at all.
    assert (
        gate(_replan_state(replan_requested=False)) == NODE_STRATEGIST
    )


# ---------------------------------------------------------------------------
# IMPL Phase 2-H — legacy lesson retrieval is engagement-scoped
# ---------------------------------------------------------------------------


def test_legacy_lesson_retrieval_is_engagement_scoped(monkeypatch):
    monkeypatch.setenv("ENABLE_MEMORY_BOUNDARY", "false")
    get_settings.cache_clear()

    captured: dict = {}

    class _FakeVector:
        def search_lessons(self, query, k=3, *, client_id=None, engagement_id=None):
            captured.update(
                query=query, k=k, client_id=client_id, engagement_id=engagement_id
            )
            return []

    monkeypatch.setattr(ha, "get_vector_store_manager", lambda: _FakeVector())

    hypothesis_node(_hyp_state("http://10.1.2.3:9000/plainpage"))

    assert captured.get("client_id") == "impl-client"
    assert captured.get("engagement_id") == "impl-engagement", (
        "legacy lesson retrieval must be narrowed to the current engagement "
        "so target A lessons cannot poison target B within one client"
    )
