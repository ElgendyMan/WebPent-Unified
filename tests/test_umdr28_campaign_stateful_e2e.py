"""UM-DR-28 tests — the CAMPAIGN end-to-end proof for source-driven
stateful discovery.

This is the directive-§5.3 evidence: the capability runs through the
REAL production path, not a standalone harness:

  1. NODE level — the real ``family_execution_node`` (the node the
     production builder wires behind ``enable_family_execution_spine``)
     invoked with a REAL campaign state (crawled_data built from an
     ACTUAL crawl of the controlled target's OpenAPI document — the
     channel the frozen schema-ingestion path populates) and a REAL
     http executor, against a LIVE controlled target with a
     structurally DIFFERENT route grammar (no own/target/ctrl
     triplets, unguessable hex tokens, cross-directory decoy,
     out-of-scope area).
  2. LANGGRAPH level — a minimal StateGraph wired with the REAL
     ``wire_family_execution`` (execution_sandbox → family_execution →
     validator, the same additive wiring the builder performs),
     invoked through the LangGraph runtime: super-step semantics,
     channel merging, the node's update visible to successors.
  3. BUILDER level — the production ``build_graph`` with the spine
     flag on contains the family_execution node (the wiring the node
     lives inside).

Negative controls: flag off ⇒ nothing runs; safe accounts never
confirm; the decoy never confirms; out-of-scope cases are refused
before any request; DELETE-carrying sources are refused by the prober.

HONESTY: the controlled target is team-authored (author-known corpus);
this proves CAMPAIGN INTEGRATION and structural generalization, NOT
independent validation.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


target_module = _load_module(
    "campaign_stateful_target", ROOT / "benchmarks" / "campaign_stateful_target.py"
)


@pytest.fixture()
def live_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), target_module.LedgerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    target_module.reset_state()
    yield base
    target_module.reset_state()
    server.shutdown()
    server.server_close()


def _register_engagement_target(base: str):
    """Register the controlled target as THE engagement target — the
    production allowlist path that lets the SSRF-pinned default
    executor reach a loopback lab target exactly as it reaches an
    operator-declared target in a real engagement."""
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )

    token = set_engagement_target_hosts(base)
    return token, clear_engagement_target_hosts


@pytest.fixture()
def engagement(live_target):
    token, clear = _register_engagement_target(live_target)
    yield live_target
    clear(token)


def _campaign_state(base: str) -> dict:
    """Build the campaign state the way the production graph does: the
    OpenAPI document ACTUALLY crawled from the target, folded into the
    crawled_data channel the frozen schema-ingestion path writes.
    NOTE: no http_executor injection — the production node builds the
    SSRF-pinned default executor itself, and the engagement-scope
    registration (the fixture above) is what authorizes the target."""
    document = httpx.get(f"{base}/openapi.json", timeout=5).json()
    openapi_routes = []
    for path, operations in document["paths"].items():
        for method in operations:
            openapi_routes.append({"method": method.upper(), "path": path})
    return {
        "target_id": "ledger-target",
        "engagement_id": "umdr28-e2e",
        "base_url": base,
        "target_url": base,
        "crawled_data": {"openapi_routes": openapi_routes},
        "allowed_endpoints": ["/api/ledger"],
        "is_production": False,
        "findings": [],
    }


# ---------------------------------------------------------------------------
# 1. flags
# ---------------------------------------------------------------------------

class TestFlags:
    def test_stateful_discovery_flag_defaults_off(self):
        from webpent.config.settings import get_settings

        assert get_settings().enable_stateful_discovery is False

    def test_node_reports_disabled_without_flag(self, engagement, monkeypatch):
        from webpent.config.settings import get_settings
        from webpent.families.execution_node import family_execution_node

        monkeypatch.setattr(get_settings(), "enable_stateful_discovery", False)
        state = _campaign_state(engagement)
        out = family_execution_node(state)
        assert out["stateful_discovery"]["enabled"] is False

    def test_node_fail_soft_when_executor_missing(self, monkeypatch):
        from webpent.config.settings import get_settings
        from webpent.families.execution_node import family_execution_node

        monkeypatch.setattr(get_settings(), "enable_stateful_discovery", True)
        state = {
            "target_id": "t", "engagement_id": "e", "base_url": "http://127.0.0.1:1",
            "crawled_data": {"openapi_routes": [
                {"method": "GET", "path": "/a/items/i_1"},
                {"method": "GET", "path": "/a/items/i_2"},
                {"method": "GET", "path": "/a/items/i_3"},
            ]},
        }
        # no executor injected and the default one cannot reach anything:
        # the discovery must degrade honestly, never fake.
        out = family_execution_node(state)
        summary = out["stateful_discovery"]
        assert summary["enabled"] is True
        assert summary.get("confirmed", 0) == 0


# ---------------------------------------------------------------------------
# 2. the node-level campaign end-to-end (the production path)
# ---------------------------------------------------------------------------

class TestCampaignNodeE2E:
    def test_full_campaign_path_confirms_with_provenance(self, engagement, monkeypatch):
        from webpent.config.settings import get_settings
        from webpent.families.execution_node import family_execution_node

        monkeypatch.setattr(get_settings(), "enable_stateful_discovery", True)
        state = _campaign_state(engagement)
        out = family_execution_node(state)

        summary = out["stateful_discovery"]
        assert summary["enabled"] is True
        assert "error" not in summary, summary.get("error")

        # cases mined from the observed surface (7 api + 2 internal)
        assert summary["cases_mined"] == 9
        # the out-of-scope area is refused BEFORE any request
        assert summary["cases_scope_refused"] == 2
        assert any(r.startswith("/internal/") for r in summary["scope_refusals"])

        # the three ground-truth vulnerable accounts confirm; safe stay clean
        confirmed = {
            p["candidate"]: p for p in summary["per_case"]
            if p["verdict"] == "CONFIRMED"
        }
        assert sorted(confirmed) == [
            "/api/ledger/accounts/acct_3",
            "/api/ledger/accounts/acct_5",
            "/api/ledger/accounts/acct_6",
        ]
        for path, case in confirmed.items():
            assert case["phase"] == 2
            assert case["transition_origin"] == "observed"
            assert case["transitions_applied"], path
            assert case["requests"] > 0

        # the compositional case carries its FULL application chain
        compositional = confirmed["/api/ledger/accounts/acct_6"]
        assert len(compositional["transitions_applied"]) == 2

        # the findings survived the node's adversarial review + self-verify
        findings = out.get("findings") or []
        stateful_findings = [
            f for f in findings
            if (f.evidence or {}).get("detection") == "stateful_discovery"
        ]
        assert len(stateful_findings) == 3
        by_url = {f.url: f for f in stateful_findings}
        assert by_url[f"{engagement}/api/ledger/accounts/acct_3"].vuln_class == "idor"
        assert by_url[f"{engagement}/api/ledger/accounts/acct_5"].vuln_class == "auth_bypass"
        assert by_url[f"{engagement}/api/ledger/accounts/acct_6"].vuln_class == "idor"

        # provenance + evidence integrity on one finding
        evidence = by_url[f"{engagement}/api/ledger/accounts/acct_6"].evidence
        assert evidence["confirmation_authority"] == "cqa_v2.guarded_causal_evaluate"
        assert len(evidence["transitions_applied"]) == 2
        trace = evidence["evidence_trace"]
        assert trace and [s["step"] for s in trace] == sorted(s["step"] for s in trace)
        assert any(s["kind"] == "transition" for s in trace)
        assert any(s["kind"] == "read" for s in trace)
        # the adversarial-review evidence fields are REAL observations
        assert evidence["foreign_tenant_identifiers"]
        assert evidence["post_replay_session_check"]["post_transition"] is True

        # the budget is reported and bounded
        assert 0 < summary["requests_issued"] <= 360

    def test_transition_tokens_come_from_the_surface_not_a_grammar(self, live_target):
        """The target's transition routes carry unguessable hex tokens —
        the legacy name grammar cannot find them; only the observed
        surface can (the discovery-generalization property, now proven
        inside the campaign path)."""
        document = httpx.get(f"{live_target}/openapi.json", timeout=5).json()
        transition_routes = [
            p for p in document["paths"] if "/accounts/" in p
            and any(m == "post" for m in document["paths"][p])
        ]
        assert len(transition_routes) == 5
        for route in transition_routes:  # /api/ledger/accounts/settle_9f3a1_3
            verb = route.rsplit("/", 1)[-1].split("_")[0]
            assert verb not in ("state", "transition", "activate", "flag")

    def test_safe_accounts_and_decoy_never_confirm(self, engagement, monkeypatch):
        from webpent.config.settings import get_settings
        from webpent.families.execution_node import family_execution_node

        monkeypatch.setattr(get_settings(), "enable_stateful_discovery", True)
        state = _campaign_state(engagement)
        out = family_execution_node(state)
        summary = out["stateful_discovery"]
        confirmed_paths = {
            p["candidate"] for p in summary["per_case"]
            if p["verdict"] == "CONFIRMED"
        }
        for safe in (2, 4, 7, 8):
            assert f"/api/ledger/accounts/acct_{safe}" not in confirmed_paths
        findings = out.get("findings") or []
        assert not any(
            "bulk_reconcile" in str(getattr(f, "url", ""))
            for f in findings
        )

    def test_evidence_report_written(self, engagement, monkeypatch):
        from webpent.config.settings import get_settings
        from webpent.families.execution_node import family_execution_node

        monkeypatch.setattr(get_settings(), "enable_stateful_discovery", True)
        state = _campaign_state(engagement)
        out = family_execution_node(state)
        summary = out["stateful_discovery"]
        report = {
            "window": "UM-DR-28",
            "level": "campaign node e2e (family_execution_node, real state, "
                     "real executor, live controlled target)",
            "population": "campaign_stateful_target (team-authored, "
                          "author-known) — NOT an independent holdout",
            "cases_mined": summary["cases_mined"],
            "cases_probed": summary["cases_probed"],
            "cases_scope_refused": summary["cases_scope_refused"],
            "confirmed": summary["confirmed"],
            "verdicts": summary["verdicts"],
            "requests_issued": summary["requests_issued"],
            "ground_truth": {
                "/api/ledger/accounts/acct_3": "vulnerable (IDOR after settle)",
                "/api/ledger/accounts/acct_5": "vulnerable (alias escalation after commit)",
                "/api/ledger/accounts/acct_6": "vulnerable (compositional pend+close)",
                "acct_2/acct_4/acct_7/acct_8": "safe",
                "internal/*": "out of scope (must be refused)",
            },
            "limitations": [
                "team-authored controlled target (the honesty boundary)",
                "a full 45-node LLM campaign run requires operator "
                "credentials; the LangGraph-level proof below covers the "
                "runtime integration through the real wiring function",
            ],
        }
        path = ROOT / "reports" / "qualification" / "umdr28_campaign_e2e.json"
        path.write_text(json.dumps(report, indent=2))
        assert path.exists()


# ---------------------------------------------------------------------------
# 3. the LangGraph runtime level (the real wiring function)
# ---------------------------------------------------------------------------

class TestLangGraphRuntime:
    def test_real_wiring_runs_inside_the_graph_runtime(self, engagement, monkeypatch):
        from langgraph.graph import END, START, StateGraph

        from webpent.config.settings import get_settings
        from webpent.families.execution_node import wire_family_execution
        from webpent.state.state import PentestState

        monkeypatch.setattr(get_settings(), "enable_stateful_discovery", True)
        campaign_state = _campaign_state(engagement)

        graph = StateGraph(PentestState)
        graph.add_node("execution_sandbox", lambda s: {})
        graph.add_node("validator", lambda s: {})
        graph.add_edge(START, "execution_sandbox")
        graph.add_edge("validator", END)
        wire_family_execution(graph)   # the REAL production wiring
        compiled = graph.compile()
        result = compiled.invoke(
            campaign_state, config={"recursion_limit": 50}
        )

        # the node ran inside the LangGraph runtime; its DECLARED
        # channels survive (the R2-graph-03 lesson — undeclared keys
        # would be silently dropped, so the summary channel is declared
        # in PentestState and the findings land on the merge channel)
        summary = result.get("stateful_discovery") or {}
        assert summary.get("enabled") is True
        assert summary.get("confirmed") == 3
        findings = result.get("findings") or []
        assert len([
            f for f in findings
            if (f.evidence or {}).get("detection") == "stateful_discovery"
        ]) == 3

    def test_production_builder_contains_the_node_when_spine_on(self, monkeypatch):
        from webpent.graph import builder as graph_builder

        monkeypatch.setattr(graph_builder, "_family_execution_enabled", lambda: True)
        compiled = graph_builder.build_graph(auto_approve=True)
        assert "family_execution" in set(getattr(compiled, "nodes", {}) or {})


# ---------------------------------------------------------------------------
# 4. adversarial: the prober's method-safety boundary inside the campaign
# ---------------------------------------------------------------------------

class TestMethodSafety:
    def test_delete_candidates_are_refused_inside_the_campaign_path(self):
        from webpent.production.stateful_discovery import mine_probe_cases
        from webpent.production.stateful_probe import StatefulCaseProber
        from webpent.production.transition_sources import ObservedSurfaceSource

        inventory = [
            {"method": "GET", "path": "/r/objs/o_1"},
            {"method": "GET", "path": "/r/objs/o_2"},
            {"method": "GET", "path": "/r/objs/o_3"},
            {"method": "DELETE", "path": "/r/objs/wipe_2"},  # destructive candidate
        ]
        cases = mine_probe_cases(inventory)
        assert cases
        sent = []

        class Client:
            def get(self, path, headers=None):
                sent.append(("GET", path))
                return SimpleNamespace(
                    status_code=403, text='{"granted": false, "actor": "attacker"}',
                    headers={"X-Actor-Echo": "attacker"})

            def post(self, path, headers=None):
                sent.append(("POST", path))
                return SimpleNamespace(status_code=200, text="{}", headers={})

            def request(self, method, path, headers=None):
                sent.append((method, path))
                return SimpleNamespace(status_code=200, text="{}", headers={})

        source = ObservedSurfaceSource(inventory)
        out = StatefulCaseProber(
            Client(), base_url="http://t", transition_source=source
        ).probe(cases[0])
        methods_issued = {m for m, _ in sent}
        assert "DELETE" not in methods_issued   # never issued — evidence safety
        assert out.verdict != "CONFIRMED"
