"""Tests for the VIP autonomous-campaign layer (2026-10-24).

Covers three layers:
  1. shared/detector_hardening — the tracked unicode_homoglyph_padding
     detector escape is CLOSED by the hardened extractor (proven via
     run_red_vs_blue, the same loop that found it).
  2. autonomous/vip_orchestrator — the perceive → plan → act → verify
     → replan loop: memory-based skipping, optimizer priority and
     deeper spawning, drift replan, N-day queueing, reviewer
     downgrade, executor-crash containment, cycle capping.
  3. autonomous/campaign_ledger — JSONL append-only audit trail,
     fail-soft on unwritable paths, bounded reads.
"""
from __future__ import annotations

import json

import pytest

from webpent.autonomous import (
    CampaignInput,
    CampaignLedger,
    VipOrchestrator,
    VipOrchestratorConfig,
    run_vip_campaign,
)
from webpent.autonomous.vip_orchestrator import _noop_executor
from webpent.learning.attack_memory import AdaptiveStrategyOptimizer, AttackMemory
from webpent.production.validators import extract_ssrf_indicators
from webpent.shared.detector_hardening import (
    extract_ssrf_indicators_hardened,
    fold_evasion_padding,
)
from webpent.shared.red_vs_blue import (
    RedVsBlueReport,
    EvasionAttemptResult,
    run_red_vs_blue,
)
from webpent.shared.surface_evidence_graph import build_surface_evidence_graph

# ---------------------------------------------------------------------------
# Layer 1 — detector hardening
# ---------------------------------------------------------------------------

SEED = "GET http://169.254.169.254/latest/meta-data/"


def test_homoglyph_padding_escapes_raw_detector():
    """The red-team finding, pinned: the raw frozen detector misses
    the U+200B-padded payload that the evasion registry generates."""
    from webpent.shared.red_vs_blue import generate_evasion_mutations

    mutated = generate_evasion_mutations(SEED)["unicode_homoglyph_padding"]
    assert "\u200b" in mutated
    assert extract_ssrf_indicators(mutated) == frozenset()
    assert extract_ssrf_indicators(SEED) != frozenset()


def test_hardened_detector_closes_homoglyph_escape():
    """The hardened extractor catches exactly the payload that escaped,
    and run_red_vs_blue (the finding loop) reports zero escapes."""
    from webpent.shared.red_vs_blue import generate_evasion_mutations

    mutated = generate_evasion_mutations(SEED)["unicode_homoglyph_padding"]
    assert extract_ssrf_indicators_hardened(mutated) == extract_ssrf_indicators(SEED)
    report = run_red_vs_blue(
        seed_payload=SEED,
        seed_payload_label="ssrf_metadata",
        detector=extract_ssrf_indicators_hardened,
    )
    assert report.escaped_techniques == []
    assert report.escape_rate == 0.0


def test_fold_evasion_padding_is_pass_through_on_clean_text():
    assert fold_evasion_padding("localhost 10.0.0.5") == "localhost 10.0.0.5"
    assert fold_evasion_padding(None) == ""
    assert fold_evasion_padding("") == ""
    # Only zero-width characters are folded — visible text is untouched.
    assert fold_evasion_padding("a\u200bb\u200cc\u200dd\ufeffe\u2060f") == "abcdef"
    assert fold_evasion_padding("a\u00a0b") == "a\u00a0b"  # nbsp kept


def test_hardened_detector_agrees_with_raw_on_unpadded_inputs():
    """No regression: on text with no padding the hardened extractor
    returns exactly what the frozen one returns."""
    for value in (SEED, "localhost admin", "metadata.google.internal", "hello world"):
        assert extract_ssrf_indicators_hardened(value) == extract_ssrf_indicators(value)


# ---------------------------------------------------------------------------
# Layer 2 — orchestrator
# ---------------------------------------------------------------------------

def _cfg(**kw) -> VipOrchestratorConfig:
    kw.setdefault("enable_selfcheck", False)
    return VipOrchestratorConfig(**kw)


def _input(scenarios: list[str], **kw) -> CampaignInput:
    kw.setdefault("crawled_data", {"endpoints": ["https://lab.test/a"]})
    kw.setdefault("scenarios", scenarios)
    kw.setdefault("target", "https://lab.test/a")
    return CampaignInput(**kw)


def test_memory_skip_drops_scenario_after_threshold_failures():
    orch = VipOrchestrator(_cfg())
    for _ in range(3):
        orch.attack_memory.record(
            scenario_id="sqli_union", endpoint="https://lab.test/a",
            outcome="failed", reason="timeout",
        )
    perception = orch.perceive(_input(["sqli_union"]))
    actions = orch.plan(_input(["sqli_union"]), perception)
    assert [a.target for a in actions if a.kind == "scenario"] == []


def test_optimizer_priority_and_deeper_spawn_shape_the_plan():
    orch = VipOrchestrator(_cfg())
    orch.optimizer.record_success("winner")
    orch.optimizer.record_failure("loser")
    perception = orch.perceive(_input(["winner", "loser"]))
    actions = orch.plan(_input(["winner", "loser"]), perception)
    by_target = {a.target: a for a in actions if a.kind == "scenario"}
    assert by_target["winner"].priority > by_target["loser"].priority
    assert by_target["winner"].rationale == "optimizer_deeper_spawn"


def test_kev_correlation_queued_with_high_priority():
    orch = VipOrchestrator(_cfg())
    # NOTE: the feed must use the finterprint's CANONICAL product name
    # (apache_httpd), as documented on correlate_cves.
    feed = [{"cve_id": "CVE-2021-41773", "product": "apache_httpd",
             "version_lte": "2.4.49", "severity": "critical", "kev": True}]
    inp = _input([], headers={"Server": "Apache/2.4.49"}, cve_feed=feed)
    perception = orch.perceive(inp)
    corrs = perception["cve_correlations"]
    assert corrs and corrs[0]["cve_id"] == "CVE-2021-41773"
    assert corrs[0]["advisory_only"] is True and corrs[0]["does_not_confirm"] is True
    actions = orch.plan(inp, perception)
    kev = [a for a in actions if a.kind == "kev_correlation"]
    assert kev and kev[0].target == "CVE-2021-41773" and kev[0].priority == 0.9


def test_drift_triggers_replan_action():
    orch = VipOrchestrator(_cfg())
    baseline = build_surface_evidence_graph({"endpoints": ["https://lab.test/a"]})
    inp = _input(["scenario_x"], crawled_data={"endpoints": ["https://lab.test/a", "https://lab.test/new-admin"]})
    inp.baseline_graph = baseline
    perception = orch.perceive(inp)
    assert perception["has_drift"] is True
    assert perception["drift_high_priority"] >= 1
    actions = orch.plan(inp, perception)
    assert any(a.kind == "drift_followup" and a.priority == 0.95 for a in actions)


def test_reviewer_downgrades_unsupported_confirmation():
    orch = VipOrchestrator(_cfg())
    results = [{
        "action": {"kind": "scenario", "target": "ep", "scenario_id": "s1"},
        "outcome": "confirmed",
        "evidence": {},  # no benign explanation refuted → reviewer must downgrade
    }]
    verification = orch.verify(0, results)
    assert verification["downgraded"] == 1
    assert results[0]["review_downgraded"] is True
    assert results[0]["outcome"] == "needs_review"
    # And the memory recorded it (needs_review outcome).
    assert any(e.outcome == "needs_review" for e in orch.attack_memory.entries.values())


def test_confirmed_finding_with_refuting_evidence_stands():
    orch = VipOrchestrator(_cfg())
    evidence = {
        "baseline_differs": True,
        "artifact_freshly_generated": True,
        "state_changed_by_test": True,
        "response_varies_with_identity": True,
    }
    results = [{
        "action": {"kind": "scenario", "target": "ep", "scenario_id": "s1"},
        "outcome": "confirmed", "evidence": evidence,
    }]
    verification = orch.verify(0, results)
    assert verification["downgraded"] == 0
    assert "review_downgraded" not in results[0]


def test_executor_crash_is_contained_to_one_action():
    orch = VipOrchestrator(_cfg())

    def bad_executor(action):
        if action["scenario_id"] == "boom":
            raise RuntimeError("executor exploded")
        return {"outcome": "confirmed", "evidence": {
            "baseline_differs": True, "artifact_freshly_generated": True,
            "state_changed_by_test": True, "response_varies_with_identity": True,
        }}

    summary = orch.run_cycle(0, _input(["boom", "fine"]), executor=bad_executor)
    outcomes = {r["action"]["scenario_id"]: r["outcome"] for r in summary["results"]}
    assert outcomes["boom"] == "failed"
    assert outcomes["fine"] == "confirmed"


def test_noop_executor_marks_not_executed():
    summary = VipOrchestrator(_cfg()).run_cycle(0, _input(["s1"]))
    assert summary["results"][0]["outcome"] == "not_executed"
    assert _noop_executor({})["outcome"] == "not_executed"


def test_max_cycles_caps_loop_and_rollup():
    inputs = [_input(["s1"]) for _ in range(10)]
    rollup = run_vip_campaign(inputs, config=_cfg(max_cycles=3))
    assert rollup["cycles_run"] == 3
    assert rollup["total_actions"] == 3


def test_selfcheck_reports_zero_escapes_with_hardened_detector():
    orch = VipOrchestrator(VipOrchestratorConfig(enable_selfcheck=True))
    check = orch.selfcheck(0)
    assert check["selfcheck"] == "ran"
    assert check["escape_rate"] == 0.0
    assert check["escaped_techniques"] == []


def test_selfcheck_feeds_escapes_to_postmortem(monkeypatch):
    """If a future regression re-opens an escape, the loop records it
    in the postmortem store (the durable half of red-vs-blue)."""
    fake_report = RedVsBlueReport(seed_payload_label="x", attempts=[
        EvasionAttemptResult(
            seed_payload_label="x", technique="unicode_homoglyph_padding",
            detected_on_seed=True, detected_on_mutation=False, escaped=True,
        ),
    ])
    recorded = []
    class _Manager:
        def record_missed_finding(self, **kw):
            recorded.append(kw)
            return "id-1"
    monkeypatch.setattr(
        "webpent.autonomous.vip_orchestrator.run_red_vs_blue",
        lambda **kw: fake_report,
    )
    orch = VipOrchestrator(VipOrchestratorConfig(
        enable_selfcheck=True, postmortem_manager=_Manager(),
    ))
    check = orch.selfcheck(0)
    assert check["escaped_techniques"] == ["unicode_homoglyph_padding"]
    assert len(recorded) == 1
    assert recorded[0]["detector_name"] == "extract_ssrf_indicators_hardened"


def test_perceive_is_fail_soft_on_garbage_input():
    orch = VipOrchestrator(_cfg())
    perception = orch.perceive(CampaignInput(crawled_data={"surface_records": "not-a-list"}, scenarios=[]))
    assert "shared_parameters" in perception
    assert "cve_correlation_error" in perception or perception["cve_correlations"] == []


def test_shared_parameters_become_second_order_candidates():
    orch = VipOrchestrator(_cfg())
    crawled = {"endpoints": [
        {"url": "https://lab.test/a?uid=1"},
        {"url": "https://lab.test/b?uid=2"},
    ]}
    inp = _input([], crawled_data=crawled)
    perception = orch.perceive(inp)
    names = {p["name"] for p in perception["shared_parameters"]}
    assert "uid" in names
    actions = orch.plan(inp, perception)
    second = [a for a in actions if a.kind == "second_order_param"]
    assert any(a.target == "uid" for a in second)


# ---------------------------------------------------------------------------
# Layer 3 — campaign ledger
# ---------------------------------------------------------------------------

def test_ledger_records_and_reads_back(tmp_path):
    ledger = CampaignLedger(tmp_path / "ledger.jsonl")
    ledger.record("perceive", 0, shared_parameters=2)
    ledger.record("plan", 0, action_count=3)
    steps = ledger.read_steps()
    assert [s["step"] for s in steps] == ["perceive", "plan"]
    assert steps[0]["shared_parameters"] == 2
    assert steps[1]["action_count"] == 3


def test_ledger_fail_soft_on_unwritable_path(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    ledger = CampaignLedger(blocker / "sub" / "ledger.jsonl")
    # mkdir fails because parent is a file → disabled, never raises.
    ledger.record("plan", 0)
    assert ledger.enabled is False
    assert ledger.read_steps() == []


def test_ledger_disabled_without_path():
    ledger = CampaignLedger(None)
    ledger.record("plan", 0)  # no-op, never raises
    assert ledger.enabled is False
    assert ledger.read_steps() == []


def test_campaign_writes_full_ledger_trail(tmp_path):
    ledger_path = tmp_path / "campaign.jsonl"
    rollup = run_vip_campaign(
        [_input(["s1"]), _input(["s1"])],
        config=_cfg(), ledger_path=str(ledger_path),
    )
    steps = CampaignLedger(ledger_path).read_steps()
    kinds = [s["step"] for s in steps]
    assert kinds[0] == "perceive"
    assert "campaign_rollup" in kinds
    assert rollup["campaign_id"].startswith("vip-campaign")
    # Every step line is valid JSON with ts/step/cycle keys.
    for line in ledger_path.read_text().splitlines():
        entry = json.loads(line)
        assert {"ts", "step", "cycle"} <= set(entry)


def test_ledger_never_stores_raw_seed_payload(tmp_path):
    ledger_path = tmp_path / "campaign.jsonl"
    run_vip_campaign(
        [_input(["s1"])],
        config=VipOrchestratorConfig(enable_selfcheck=True),
        ledger_path=str(ledger_path),
    )
    text = ledger_path.read_text()
    assert "169.254.169.254" not in text
    assert "meta-data" not in text
