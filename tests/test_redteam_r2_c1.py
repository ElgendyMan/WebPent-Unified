"""RED-TEAM ROUND 2 — C1 batch, fail-first (0.34.0 window).

Every test below was written BEFORE its fix and fails on the 0.33.0
baseline; each corresponds to one Critical/High finding from
docs/RED_TEAM_ROUND2_20261102.md section 2:

    R2-graph-01  recon node returns full state -> append-only channels
                 duplicated -> budget governor consumed count inflated
    R2-graph-02  route_after_hypothesis can return NODE_STRATEGIST under
                 budget pressure, but the conditional-edge map has no key
    R2-graph-03  scope_drift_approved never declared in PentestState ->
                 langgraph channel filtering drops it -> HITL dead end
    R2-graph-04  unified_hunt imports nonexistent webpent.shared.checkpoints
                 -> checkpointer silently None -> silent truncation in HITL
    R2-jc-01     disabled skeptic/judge leave the _UNSET sentinel seated ->
                 AttributeError in close()
    R2-jc-02     clamp01 on USD-domain ranking keys -> alphabetical order
    R2-jc-03     canonical_json(default=str) -> PYTHONHASHSEED-dependent
                 context_hash for set-valued contexts
    R2-dojo-01   wrong answers inflate TrainingSession.score without bound
    R2-econ-01   naive last_transition -> TypeError in auto_transition
    R2-prism-01  record_outcome accepts evidence from another campaign
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 2, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# R2-graph-01
# ---------------------------------------------------------------------------

def test_recon_node_returns_delta_not_full_state(monkeypatch):
    from webpent.graph import builder

    state = {
        "node_step_trace": [{"seq": i, "node": f"n{i}"} for i in range(4)],
        "consulted_lessons": [{"summary": "l"}],
        "findings": [],
    }
    monkeypatch.setattr(builder, "MODERN_SPINE_ENABLED", False)
    monkeypatch.setattr(builder, "recon_node", lambda s: {"recon_summary": {"n": 1}})
    node = builder._make_combined_recon_node("")
    update = node(state)
    assert "node_step_trace" not in update, (
        "recon node must not re-send the append-only trace channel"
    )
    assert "consulted_lessons" not in update
    assert update.get("recon_summary") == {"n": 1}


def test_trace_wrap_merge_does_not_duplicate_append_only_channels(monkeypatch):
    from webpent.graph import builder
    from webpent.state.reducers import merge_lists

    state = {"node_step_trace": [{"seq": i, "node": f"n{i}"} for i in range(4)]}
    monkeypatch.setattr(builder, "MODERN_SPINE_ENABLED", False)
    monkeypatch.setattr(builder, "recon_node", lambda s: ({}))
    wrapped = builder._trace_wrap("recon", builder._make_combined_recon_node(""))
    update = wrapped(state)
    merged = merge_lists(
        state.get("node_step_trace"), update.get("node_step_trace")
    )
    assert len(merged) == 5, f"append-only channel duplicated: {len(merged)}"


# ---------------------------------------------------------------------------
# R2-graph-02
# ---------------------------------------------------------------------------

def test_hypothesis_router_pressure_return_is_wired():
    from webpent.graph import builder

    pressure_state = {
        "node_step_trace": [{"seq": i, "node": "n"} for i in range(40)]
    }
    route = builder.route_after_hypothesis(pressure_state)
    assert route in builder.HYPOTHESIS_PATH_MAP, (
        f"router returned unwired destination {route!r} under budget pressure"
    )


def test_hypothesis_path_map_covers_every_router_return():
    from webpent.graph import builder

    assert {builder.NODE_ACCESS_CONTROL, builder.NODE_REPORTER,
            builder.NODE_STRATEGIST} <= set(builder.HYPOTHESIS_PATH_MAP)


# ---------------------------------------------------------------------------
# R2-graph-03
# ---------------------------------------------------------------------------

def test_scope_drift_approval_is_a_declared_channel():
    from webpent.state.state import PentestState

    assert "scope_drift_approved" in PentestState.__annotations__


def test_scope_drift_approval_survives_channel_filtering():
    langgraph = pytest.importorskip("langgraph")
    from langgraph.graph import END, START, StateGraph  # noqa: F401
    from webpent.state.state import PentestState

    g = StateGraph(PentestState)
    g.add_node("probe", lambda s: {"scope_drift_approved": True})
    g.add_edge(START, "probe")
    g.add_edge("probe", END)
    out = g.compile().invoke({})
    assert out.get("scope_drift_approved") is True, (
        "undeclared state keys are dropped by langgraph channel filtering"
    )


# ---------------------------------------------------------------------------
# R2-graph-04
# ---------------------------------------------------------------------------

def test_unified_hunt_imports_the_real_checkpointer_home():
    import inspect

    import webpent.cli.unified_hunt as uh
    from webpent.graph import checkpoints as gcp

    assert "webpent.shared.checkpoints" not in inspect.getsource(uh)
    assert uh.get_checkpointer is gcp.get_checkpointer, (
        "unified_hunt must bind graph.checkpoints.get_checkpointer, "
        f"got {uh.get_checkpointer!r}"
    )


def test_hitl_without_checkpointer_fails_loud():
    import inspect

    import webpent.cli.unified_hunt as uh

    with pytest.raises(RuntimeError, match="checkpointer"):
        uh._resolve_checkpointer_for_run(False, None)
    # headless mode (auto_approve=True) still runs without a checkpointer
    assert uh._resolve_checkpointer_for_run(True, None) is None
    sentinel = object()
    assert uh._resolve_checkpointer_for_run(False, lambda: sentinel) is sentinel
    # the run must actually route through the fail-loud resolver
    assert "_resolve_checkpointer_for_run(auto_approve, get_checkpointer)" in (
        inspect.getsource(uh.run_unified_hunt)
    )


# ---------------------------------------------------------------------------
# R2-jc-01
# ---------------------------------------------------------------------------

def test_close_with_roles_disabled_in_config(tmp_path):
    from webpent.jc.chamber import CouncilChamber
    from webpent.jc.contracts import Argument

    cfg = tmp_path / "council.yaml"
    cfg.write_text(
        "council:\n  require_skeptic: false\n  require_judge: false\n",
        encoding="utf-8",
    )
    ch = CouncilChamber(config_path=cfg, now=NOW)
    session = ch.convene("disable test?", {"k": 1})
    for i in range(3):
        ch.submit_argument(
            session.session_id,
            Argument(
                advocate_id=f"a{i}", claim=f"c{i}", evidence=[],
                reasoning="r", confidence=0.5, alternatives=["x"],
                timestamp=NOW,
            ),
        )
    verdict = ch.close(session.session_id)
    assert verdict.action == "none"
    assert verdict.escalate is True


# ---------------------------------------------------------------------------
# R2-jc-02
# ---------------------------------------------------------------------------

def test_economist_ranks_by_raw_value_usd():
    from webpent.jc.advocates import EconomistAdvocate

    arg = EconomistAdvocate().argue({"findings_value": [
        {"finding_id": "alpha", "value_usd": 60.0},
        {"finding_id": "zulu", "value_usd": 1_000_000.0},
    ]})
    assert arg is not None
    assert "zulu" in arg.claim, f"wrong pick: {arg.claim}"


def test_tactician_ranks_by_raw_ev_per_hour():
    from webpent.jc.advocates import TacticianAdvocate

    arg = TacticianAdvocate().argue({"ev_schedule": [
        {"target_id": "alpha", "ev_per_hour": 2.0},
        {"target_id": "zulu", "ev_per_hour": 50.0},
    ]})
    assert arg is not None
    assert "zulu" in arg.claim, f"wrong pick: {arg.claim}"


def test_adapter_picks_the_raw_best_alternative_lane():
    from webpent.jc.advocates import AdapterAdvocate

    arg = AdapterAdvocate().argue({
        "ev_per_hour_now": {"a": 1.0, "b": 5.0, "y": 2.0},
        "ev_per_hour_week_ago": {"a": 4.0, "b": 3.0, "y": 3.0},
    })
    assert arg is not None
    assert "lane b" in arg.claim, f"wrong pick: {arg.claim}"


# ---------------------------------------------------------------------------
# R2-jc-03
# ---------------------------------------------------------------------------

def test_canonical_json_orders_sets_deterministically():
    from webpent.jc.contracts import canonical_json, context_hash

    assert canonical_json({"b", "a"}) == canonical_json(["a", "b"])
    assert context_hash({"ports": {"a", "b"}}) == context_hash(
        {"ports": ["a", "b"]}
    )


def test_context_hash_stable_across_hash_seeds():
    from webpent.jc.contracts import context_hash  # noqa: F401

    script = (
        "from webpent.jc.contracts import context_hash; "
        "print(context_hash({'open_ports': {'22', '8080', '443'}}))"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.environ.get("PYTHONPATH", "src")
    hashes = []
    for seed in ("0", "1"):
        proc = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True,
            env={**env, "PYTHONHASHSEED": seed}, cwd=str(REPO_ROOT),
        )
        assert proc.returncode == 0, proc.stderr
        hashes.append(proc.stdout.strip())
    assert hashes[0] == hashes[1] and len(hashes[0]) == 64


# ---------------------------------------------------------------------------
# R2-dojo-01
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def dojo_library():
    from webpent.dojo.scenario_library import ScenarioLibrary

    return ScenarioLibrary.load_dir("config/dojo/scenarios")


def test_wrong_answers_cannot_inflate_score(dojo_library):
    from webpent.dojo.trainer import TrainingSession

    session = TrainingSession(dojo_library, ["sqli-01"], dojo_dir=None)
    wrong = {"vuln_class": "x", "location": "y", "signature": "z"}
    for _ in range(5):
        session.answer(wrong)
    scenario = dojo_library.get("sqli-01")
    session.answer({
        "vuln_class": scenario.vuln_class,
        "location": scenario.location,
        "signature": scenario.signature,
    })
    assert session.score() <= 100.0
    assert session.score() == 100.0


def test_hint_cost_still_applies_after_wrong_attempts(dojo_library):
    from webpent.dojo.trainer import TrainingSession

    session = TrainingSession(dojo_library, ["sqli-01"], dojo_dir=None)
    scenario = dojo_library.get("sqli-01")
    session.answer({"vuln_class": "x", "location": "y", "signature": "z"})
    session.request_hint()
    session.answer({
        "vuln_class": scenario.vuln_class,
        "location": scenario.location,
        "signature": scenario.signature,
    })
    assert session.score() == 90.0


# ---------------------------------------------------------------------------
# R2-econ-01
# ---------------------------------------------------------------------------

def test_auto_transition_survives_naive_last_transition(tmp_path):
    from webpent.econ.portfolio import AutoContext, PortfolioManager

    path = tmp_path / "portfolio.yaml"
    path.write_text(
        "targets:\n"
        "  - target_id: t1\n"
        "    program_id: p\n"
        "    state: WATCHING\n"
        "    last_transition: 2026-01-01T00:00:00\n",
        encoding="utf-8",
    )
    manager = PortfolioManager(now=NOW, log_path=tmp_path / "log.jsonl")
    portfolio = manager.load(path)
    assert "t1" in portfolio.targets
    applied = manager.auto_transition(portfolio, AutoContext(now=NOW))
    assert isinstance(applied, list)


def test_loaded_naive_last_transition_is_utc_normalized(tmp_path):
    from webpent.econ.portfolio import PortfolioManager

    path = tmp_path / "portfolio.yaml"
    path.write_text(
        "targets:\n"
        "  - target_id: t1\n"
        "    program_id: p\n"
        "    state: WATCHING\n"
        "    last_transition: 2026-01-01T00:00:00\n",
        encoding="utf-8",
    )
    portfolio = PortfolioManager(now=NOW, log_path=tmp_path / "log.jsonl").load(path)
    assert portfolio.targets["t1"].last_transition.tzinfo is not None


# ---------------------------------------------------------------------------
# R2-prism-01
# ---------------------------------------------------------------------------

def test_outcome_rejects_evidence_from_other_campaign(tmp_path):
    from webpent.prism.errors import PrismLawError
    from webpent.prism.ledger import CampaignLedger
    from webpent.prism.scorer import EvidenceScorer
    from webpent.prism.taxonomy import EvidenceTaxonomy

    taxonomy = EvidenceTaxonomy(REPO_ROOT / "config" / "prism" / "taxonomy.yaml")
    scorer = EvidenceScorer(
        REPO_ROOT / "config" / "prism" / "scorer_weights.yaml", taxonomy
    )
    ledger = CampaignLedger(tmp_path / "l.db")
    try:
        campaign_a = ledger.open_campaign("a.example", "pa")
        campaign_b = ledger.open_campaign("b.example", "pb")
        profile = taxonomy.profile(
            evidence_hash="a" * 64, source="probe",
            signal_kind="direct_response", strength="strong",
            reproducibility="deterministic",
            corroboration="independent_multiple", rationale="payload echoed",
        )
        evidence_id = ledger.record_evidence(
            campaign_a, profile, scorer.score(profile)
        )
        with pytest.raises(PrismLawError):
            ledger.record_outcome(campaign_b, evidence_id, "confirmed")
    finally:
        ledger.close()
