"""UM-DR-31 — campaign end-to-end + ablation over a controlled target.

The UM-DR-31 §9.3/§9.4 evidence, at three levels:

1. CAMPAIGN E2E — the complete research loop through the REAL
   production nodes: research_loop (signal inventory → deduplicated
   hypotheses → pool) followed by the real family_execution_node
   (stateful discovery with the planner's priority hints) against a
   LIVE controlled two-directory target, fresh state per arm.
2. ABLATION — the directive's four arms under IDENTICAL conditions
   (same target, same budget ceiling of 36 requests, same scope):
   baseline (no loop), coverage-only, invariant-only, full loop. The
   measurable contribution: the invariant/workflow input's priority
   ordering directs the constrained budget at the signal-rich
   directory and reaches the ground truth the alphabetical baseline
   cannot; coverage-only enriches the pool but cannot reorder
   execution (its measurable is the generated hypotheses).
3. LANGGRAPH RUNTIME — one graph run through the real
   wire_family_execution preceded by the real research_loop node over
   the real PentestState: the loop's hypotheses and the hinted
   stateful summary land on their declared channels in the SAME run.

Negative behavior: safe objects never confirm in any arm; the
out-of-scope area is refused before any request; the full-budget
sanity arm confirms exactly the ground truth (hints create no false
positives); the feedback pass generates nothing new for a cell the
run closed.

HONESTY: the controlled target is team-authored (author-known); the
ablation population is this fixture alone. It proves CAMPAIGN
INTEGRATION and the measurable contribution of each loop input under
a constrained budget — NOT independent validation and NOT real-world
recall/precision.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

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
    "campaign_research_target", ROOT / "benchmarks" / "campaign_research_target.py"
)

#: The ablation budget: high enough to probe every case's phase-1 yet
#: low enough that the alphabetical order clips the ground-truth case's
#: phase-2 (measured on this target: unhinted 36 ⇒ 0 confirmed,
#: hinted 36 ⇒ 1 confirmed — same cases, same ceiling, ordering only).
ABLATION_BUDGET = 36

#: The ground truth of the controlled target (see its module docstring).
GROUND_TRUTH_VULNERABLE = "/api/zzz/vaults/vlt_3"


@pytest.fixture()
def live_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), target_module.VaultHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    target_module.reset_state()
    yield base
    target_module.reset_state()
    server.shutdown()
    server.server_close()


@pytest.fixture()
def engagement(live_target):
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )

    token = set_engagement_target_hosts(live_target)
    yield live_target
    clear_engagement_target_hosts(token)


def _campaign_state(base: str, *, signals: str) -> dict:
    """Build the campaign state the way the production graph does: the
    OpenAPI document ACTUALLY crawled from the target, folded into the
    crawled_data channel, plus the research signal channels per arm.

    Arm signal sets (the ablation's ONLY difference between arms):
      none       — no research evidence channels populated
      coverage   — one open coverage-ledger cell (idor:vaults)
      invariant  — the observed cross-identity seal transition + its
                   authorization-context invariant candidate
      full       — both of the above
    """
    document = httpx.get(f"{base}/openapi.json", timeout=5).json()
    openapi_routes = [
        {"method": method.upper(), "path": path}
        for path, operations in document["paths"].items()
        for method in operations
    ]
    state: dict = {
        "target_id": "vault-target",
        "engagement_id": "umdr31-e2e",
        "base_url": base,
        "target_url": base,
        "crawled_data": {"openapi_routes": openapi_routes},
        "allowed_endpoints": ["/api/"],
        "is_production": False,
        "findings": [],
        "invariant_review": [],
        "workflow_observations": [],
        "hypotheses": [],
    }
    if signals in ("coverage", "full"):
        state["campaign_ledger"] = {"entries": [
            {"key": "idor:vaults", "status": "not_scanned"},
        ]}
    if signals in ("invariant", "full"):
        seal_route = next(
            r["path"] for r in openapi_routes
            if r["method"] == "POST" and "/seal_" in r["path"]
        )
        # the observed cross-identity transition (the workflow-
        # understanding channel shape) and its invariant candidate
        state["workflow_observations"] = [{
            "fingerprint": "ab12cd34ef56ab12",
            "workflow_key": "vault-lifecycle",
            "transition_key": "seal",
            "source_ref": f"openapi:{seal_route}",
            "endpoint": f"{base}{seal_route}",
            "method": "POST",
            "from_state": "open",
            "to_state": "sealed",
            "authorization_boundary": "cross_identity",
            "scope_decision": "allowed",
            "evidence_refs": ["crawl:seal"],
            "identity_context": [],
        }]
        state["invariant_review"] = [{
            "target_id": "vault-target",
            "engagement_id": "umdr31-e2e",
            "observation_fingerprint": "ab12cd34ef56ab12",
            "invariant": "authorization_context_must_be_present",
            "status": "candidate_violation",
            "reason": "a cross-identity transition lacks identity context",
            "evidence_refs": ["crawl:seal"],
            "required_validation": [
                "target_backed_causal_signal",
                "independent_negative_control",
                "sealed_replayable_proof_bundle",
            ],
        }]
    return state


class _FlagBlock:
    """Set the production flags for one arm, restore after."""

    def __init__(self, *, loop: bool, stateful: bool = True,
                 stateful_budget: int = 360):
        self.loop = loop
        self.stateful = stateful
        self.stateful_budget = stateful_budget

    def __enter__(self):
        from webpent.config.settings import get_settings

        self._settings = get_settings()
        self._saved = {
            "enable_adaptive_research_loop": self._settings.enable_adaptive_research_loop,
            "enable_stateful_discovery": self._settings.enable_stateful_discovery,
            "enable_family_execution_spine": self._settings.enable_family_execution_spine,
            "stateful_discovery_max_requests": (
                self._settings.stateful_discovery_max_requests
            ),
        }
        self._settings.enable_adaptive_research_loop = self.loop
        self._settings.enable_stateful_discovery = self.stateful
        self._settings.enable_family_execution_spine = self.stateful
        self._settings.stateful_discovery_max_requests = self.stateful_budget
        return self

    def __exit__(self, *exc):
        for key, value in self._saved.items():
            setattr(self._settings, key, value)
        return False


def _run_arm(base: str, *, signals: str, loop: bool, max_requests: int) -> dict:
    """One ablation arm: research pass then the real execution node."""
    from webpent.families.execution_node import family_execution_node
    from webpent.production.adaptive_research import research_loop_node

    target_module.reset_state()
    state = _campaign_state(base, signals=signals)
    with _FlagBlock(loop=loop, stateful_budget=max_requests):
        # research pass (flag-gated: a no-op when loop=False)
        update = research_loop_node(state)
        if update:
            state["hypotheses"] = list(update.get("hypotheses", []))
            state["research_loop"] = update["research_loop"]
        # the real production execution node (stateful discovery with
        # the planner's hints, behind its own flags)
        out = family_execution_node(state)

    telemetry = dict(state.get("research_loop") or {})
    summary = dict(out.get("stateful_discovery") or {})
    findings = out.get("findings") or []
    return {
        "signals": signals,
        "loop": loop,
        "hypotheses_generated": int(telemetry.get("hypotheses_generated_total") or 0),
        "hypothesis_origins": sorted({
            str(getattr(h, "origin", ""))
            for h in state.get("hypotheses") or []
        }),
        "cases_mined": int(summary.get("cases_mined") or 0),
        "cases_probed": int(summary.get("cases_probed") or 0),
        "cases_scope_refused": int(summary.get("cases_scope_refused") or 0),
        "confirmed": int(summary.get("confirmed") or 0),
        "confirmed_paths": sorted(
            p["candidate"] for p in summary.get("per_case", [])
            if p.get("verdict") == "CONFIRMED"
        ),
        "requests_issued": int(summary.get("requests_issued") or 0),
        "request_budget": max_requests,
        "research_hints_applied": bool(summary.get("research_hints_applied")),
        "findings_count": len(findings),
        "finding_urls": sorted(str(getattr(f, "url", "")) for f in findings),
    }


# ---------------------------------------------------------------------------
# 1. the campaign end-to-end (full loop through the real nodes)
# ---------------------------------------------------------------------------

class TestCampaignEndToEnd:
    def test_full_loop_reaches_ground_truth_under_tight_budget(self, engagement):
        arm = _run_arm(
            engagement, signals="full", loop=True, max_requests=ABLATION_BUDGET
        )
        # the loop generated evidence-backed hypotheses from BOTH inputs
        assert arm["hypotheses_generated"] == 2
        assert arm["hypothesis_origins"] == ["coverage_gap", "invariant"]
        # the stateful execution ran with the planner's priority hints
        assert arm["research_hints_applied"] is True
        # the ground truth was reached within the SAME budget the
        # baseline cannot reach it in (the ablation below)
        assert arm["confirmed"] == 1
        assert arm["confirmed_paths"] == [GROUND_TRUTH_VULNERABLE]
        assert arm["findings_count"] == 1
        assert arm["finding_urls"] == [f"{engagement}{GROUND_TRUTH_VULNERABLE}"]
        # bounds respected, out-of-scope refused before any request
        assert 0 < arm["requests_issued"] <= ABLATION_BUDGET
        assert arm["cases_scope_refused"] == 2

    def test_safe_objects_never_confirm_in_any_arm(self, engagement):
        for signals, loop in (("none", False), ("coverage", True),
                              ("invariant", True), ("full", True)):
            arm = _run_arm(
                engagement, signals=signals, loop=loop,
                max_requests=ABLATION_BUDGET * 3,  # generous budget
            )
            assert arm["request_budget"] == ABLATION_BUDGET * 3
            for safe in ("rec_2", "rec_3", "rec_4", "vlt_2", "vlt_4"):
                assert not any(
                    path.endswith(safe) for path in arm["confirmed_paths"]
                ), (signals, arm["confirmed_paths"])
            # with a generous budget every arm confirms EXACTLY the
            # ground truth — the hints create no false positives
            assert arm["confirmed_paths"] == [GROUND_TRUTH_VULNERABLE]

    def test_out_of_scope_refused_before_any_request(self, engagement):
        arm = _run_arm(
            engagement, signals="full", loop=True, max_requests=ABLATION_BUDGET
        )
        assert arm["cases_scope_refused"] == 2
        assert not any(
            "/internal/" in path for path in arm["confirmed_paths"]
        )

    def test_feedback_closes_the_covered_cell(self, engagement):
        """AC-08: after execution, the coverage update changes the next
        research decision — a cell the run closed generates nothing."""
        from webpent.families.execution_node import family_execution_node
        from webpent.production.adaptive_research import research_loop_node

        target_module.reset_state()
        state = _campaign_state(engagement, signals="full")
        with _FlagBlock(loop=True):
            first = research_loop_node(state)
            state["hypotheses"] = list(first.get("hypotheses", []))
            state["research_loop"] = first["research_loop"]
            family_execution_node(state)
        # the run's outcome: the idor cell is now conclusively resolved
        # (tool_confirmed) and the invariant hypothesis was promoted by
        # the evidence — simulate the honest ledger update the proof
        # pipeline writes, then re-run the loop
        state["campaign_ledger"] = {"entries": [
            {"key": "idor:vaults", "status": "tool_confirmed"},
        ]}
        state["hypotheses"] = [
            {**h.model_dump(mode="json"), "status": "promoted"}
            if hasattr(h, "model_dump") else dict(h)
            for h in state["hypotheses"]
        ]
        with _FlagBlock(loop=True):
            second = research_loop_node(state)
        # nothing new is justified: the cell is confirmed, the
        # invariant hypothesis is closed
        assert "hypotheses" not in second
        detail = second["research_loop"]["last_iteration_detail"]
        assert detail["generated"] == 0


# ---------------------------------------------------------------------------
# 2. the ablation (UM-DR-31 §9.4 — same target, same ceiling, four arms)
# ---------------------------------------------------------------------------

class TestAblation:
    def test_ablation_matrix_measures_each_input_contribution(self, engagement):
        baseline = _run_arm(
            engagement, signals="none", loop=False, max_requests=ABLATION_BUDGET
        )
        coverage = _run_arm(
            engagement, signals="coverage", loop=True, max_requests=ABLATION_BUDGET
        )
        invariant = _run_arm(
            engagement, signals="invariant", loop=True, max_requests=ABLATION_BUDGET
        )
        full = _run_arm(
            engagement, signals="full", loop=True, max_requests=ABLATION_BUDGET
        )

        # baseline: no loop, no signals — the alphabetical probing
        # order spends the budget on the safe directory
        assert baseline["hypotheses_generated"] == 0
        assert baseline["research_hints_applied"] is False
        assert baseline["confirmed"] == 0

        # coverage-only: the pool is enriched AND — the UM-DR-31.1
        # scheduling fix — the coverage cell's surface context now
        # carries execution priority: the surface hint ("vaults" from
        # "idor:vaults") orders the constrained budget at the
        # signal-surface directory and the ground truth is reached
        # within the SAME ceiling the alphabetical baseline cannot.
        # (UM-DR-31 measured this arm at 0 confirmed — the bottleneck
        # the §6.1 correction removes. Ordering only: same cases, same
        # budget, same scope checks; no confidence/authority change.)
        assert coverage["hypotheses_generated"] == 1
        assert coverage["hypothesis_origins"] == ["coverage_gap"]
        assert coverage["research_hints_applied"] is True
        assert coverage["confirmed"] == 1
        assert coverage["confirmed_paths"] == [GROUND_TRUTH_VULNERABLE]

        # invariant-only: the observed cross-identity transition yields
        # BOTH a planner hypothesis AND the execution priority — the
        # ground truth is reached within the same ceiling
        assert invariant["hypotheses_generated"] == 1
        assert invariant["hypothesis_origins"] == ["invariant"]
        assert invariant["research_hints_applied"] is True
        assert invariant["confirmed"] == 1
        assert invariant["confirmed_paths"] == [GROUND_TRUTH_VULNERABLE]

        # full: both inputs — the union of the contributions
        assert full["hypotheses_generated"] == 2
        assert full["research_hints_applied"] is True
        assert full["confirmed"] == 1
        assert full["confirmed_paths"] == [GROUND_TRUTH_VULNERABLE]

        # identical conditions across arms (the ablation's validity):
        # same ceiling, same mined surface, and NO out-of-scope
        # confirmation in any arm (the scope-refusal COUNT differs
        # honestly between arms: the unhinted order exhausts the budget
        # before the internal cases reach the scope checkpoint, the
        # hinted order reaches it — recorded in the report, not
        # over-asserted here)
        for arm in (baseline, coverage, invariant, full):
            assert arm["request_budget"] == ABLATION_BUDGET
            assert arm["requests_issued"] <= ABLATION_BUDGET
            assert arm["cases_mined"] == 8
            assert not any(
                path.startswith("/internal") for path in arm["confirmed_paths"]
            )
        # the hinted arms DID reach the out-of-scope checkpoint and
        # refused both internal cases before any request
        assert invariant["cases_scope_refused"] == 2
        assert full["cases_scope_refused"] == 2
        assert coverage["cases_scope_refused"] == 2

    def test_ablation_report_written(self, engagement, tmp_path):
        # UM-DR-31.1 R2/F02: this test writes ONLY into tmp_path. The
        # historical v0.37.0 artifact at reports/qualification/ was
        # mutated post-release (commit 2ad93aa) because the test used to
        # write the repo-tracked path as a side effect — with random
        # fixture ports baked in, every re-run drifted the committed
        # evidence. The committed artifact is now generated ONLY by the
        # explicit release-time command (scripts/build_umdr31_ablation_artifact.py).
        arms = {
            label: _run_arm(
                engagement, signals=signals, loop=loop,
                max_requests=ABLATION_BUDGET,
            )
            for label, signals, loop in (
                ("baseline", "none", False),
                ("coverage_only", "coverage", True),
                ("invariant_only", "invariant", True),
                ("full_loop", "full", True),
            )
        }
        report = {
            "window": "UM-DR-31",
            "level": "campaign ablation (research_loop + family_execution_node, "
                     "real state, real executor, live controlled target)",
            "population": "campaign_research_target (team-authored, "
                          "author-known two-directory fixture) — NOT an "
                          "independent holdout",
            "conditions": {
                "request_budget": ABLATION_BUDGET,
                "cases_mined": 8,
                "scope_refused": 2,
                "arms_differ_only_in": "which research evidence channels are "
                                       "populated + the loop flag",
            },
            "arms": arms,
            "ground_truth": {
                GROUND_TRUTH_VULNERABLE: "vulnerable (IDOR after seal)",
                "rec_2/rec_3/rec_4/vlt_2/vlt_4": "safe (never confirmed in any arm)",
                "internal/*": "out of scope (refused before any request)",
            },
            "finding": (
                "Under a budget that cannot cover both directories, the "
                "invariant/workflow input's priority ordering reaches the "
                "ground truth (1 confirmed) where the alphabetical baseline "
                "confirms nothing; the coverage input's measurable is BOTH "
                "pool enrichment AND — the UM-DR-31.1 scheduling fix — "
                "execution priority via the coverage surface hint (the "
                "UM-DR-31 window measured this arm at 0 confirmed; the "
                "identical budget now reaches the ground truth). "
                "Same cases, same ceiling, same scope checks — ordering only."
            ),
            "limitations": [
                "team-authored fixture (the honesty boundary)",
                "single-fixture population — no generalization claim",
                "a full 45-node LLM campaign run requires operator "
                "credentials; the LangGraph-level proof below covers the "
                "runtime integration through the real wiring function",
            ],
        }
        path = tmp_path / "umdr31_ablation.json"
        path.write_text(json.dumps(report, indent=2))
        assert path.exists()
        parsed = json.loads(path.read_text())
        assert parsed["window"] == "UM-DR-31"
        assert set(parsed["arms"]) == {
            "baseline", "coverage_only", "invariant_only", "full_loop",
        }


# ---------------------------------------------------------------------------
# 3. the LangGraph runtime level (one run, both real nodes)
# ---------------------------------------------------------------------------

class TestLangGraphRuntime:
    def test_research_loop_then_family_execution_in_one_run(self, engagement):
        from langgraph.graph import END, START, StateGraph

        from webpent.families.execution_node import wire_family_execution
        from webpent.production.adaptive_research import research_loop_node
        from webpent.state.state import PentestState

        with _FlagBlock(loop=True):
            campaign_state = _campaign_state(engagement, signals="full")
            graph = StateGraph(PentestState)
            graph.add_node("research_loop", research_loop_node)
            graph.add_node("execution_sandbox", lambda s: {})
            graph.add_node("validator", lambda s: {})
            graph.add_edge(START, "research_loop")
            graph.add_edge("research_loop", "execution_sandbox")
            graph.add_edge("validator", END)
            wire_family_execution(graph)  # the REAL production wiring
            compiled = graph.compile()
            result = compiled.invoke(campaign_state, config={"recursion_limit": 60})

        # the loop's hypotheses landed on the pool channel ...
        pool = result.get("hypotheses") or []
        assert sorted(getattr(h, "origin", "") for h in pool) == [
            "coverage_gap", "invariant"
        ]
        # ... its telemetry survived channel filtering ...
        telemetry = result.get("research_loop") or {}
        assert telemetry.get("hypotheses_generated_total") == 2
        # ... and the execution consumed the priority hints in the SAME
        # run (the planner→execution data flow through real state)
        summary = result.get("stateful_discovery") or {}
        assert summary.get("research_hints_applied") is True
        assert summary.get("confirmed") == 1
        findings = result.get("findings") or []
        assert [
            str(getattr(f, "url", "")) for f in findings
        ] == [f"{engagement}{GROUND_TRUTH_VULNERABLE}"]
        evidence = getattr(findings[0], "evidence", {}) or {}
        # the confirmation authority is unchanged and named
        assert evidence.get("confirmation_authority") == (
            "cqa_v2.guarded_causal_evaluate"
        )

    def test_flag_off_keeps_umdr28_behavior(self, engagement):
        from langgraph.graph import END, START, StateGraph

        from webpent.families.execution_node import wire_family_execution
        from webpent.state.state import PentestState

        with _FlagBlock(loop=False):  # stateful ON, research loop OFF
            campaign_state = _campaign_state(engagement, signals="full")
            graph = StateGraph(PentestState)
            graph.add_node("execution_sandbox", lambda s: {})
            graph.add_node("validator", lambda s: {})
            graph.add_edge(START, "execution_sandbox")
            graph.add_edge("validator", END)
            wire_family_execution(graph)
            compiled = graph.compile()
            result = compiled.invoke(campaign_state, config={"recursion_limit": 60})

        # UM-DR-28 behavior: stateful runs, no hints, no research
        # hypotheses, no research telemetry
        summary = result.get("stateful_discovery") or {}
        assert summary.get("research_hints_applied") is False
        assert not (result.get("hypotheses") or [])
        assert not (result.get("research_loop") or {})
