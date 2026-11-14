# tests/test_portfolio_manager.py
"""Track 12 item 1 — program portfolio management (EV ordering +
unified budget with per-campaign / per-client limits)."""

from __future__ import annotations

import json

from webpent.production.portfolio_manager import (
    AdmissionVerdict,
    BudgetCaps,
    PortfolioManager,
    ProgramEstimate,
)


def make_manager(**caps) -> PortfolioManager:
    return PortfolioManager(caps=BudgetCaps(**caps))


def prog(name, client, reward, prob, cost):
    return ProgramEstimate(
        program_name=name,
        client_id=client,
        expected_reward=reward,
        success_probability=prob,
        estimated_cost=cost,
    )


class TestExpectedValueOrdering:
    def test_rank_by_ev_desc_then_name(self):
        mgr = make_manager()
        mgr.register_program(prog("bbb", "c1", reward=1000, prob=0.5, cost=100))  # EV 400
        mgr.register_program(prog("aaa", "c1", reward=1000, prob=0.5, cost=100))  # EV 400
        mgr.register_program(prog("zzz", "c2", reward=900, prob=0.2, cost=50))    # EV 130
        ranked = mgr.rank_programs()
        names = [p.program_name for p, _ in ranked]
        assert names[0] == "aaa"          # tie on EV → name asc (stable)
        assert names[1] == "bbb"
        assert names[-1] == "zzz"
        assert ranked[0][1] == 400.0

    def test_probability_clamped(self):
        p = prog("x", "c1", reward=100, prob=1.7, cost=10)
        assert p.expected_value == 90.0
        p2 = prog("y", "c1", reward=100, prob=-0.5, cost=10)
        assert p2.expected_value == -10.0


class TestUnifiedBudget:
    def test_admit_within_caps(self):
        mgr = make_manager(total_budget=1000, per_client_budget=500, per_campaign_cap=400)
        mgr.register_program(prog("site-a", "c1", 800, 0.6, 300))
        decision = mgr.admit("c1", "site-a", "camp-1")
        assert decision.verdict is AdmissionVerdict.ADMITTED

    def test_denied_campaign_cap(self):
        mgr = make_manager(per_campaign_cap=200)
        mgr.register_program(prog("big", "c1", 900, 0.9, 500))
        decision = mgr.admit("c1", "big", "camp-1")
        assert decision.verdict is AdmissionVerdict.DENIED_CAMPAIGN_CAP

    def test_denied_client_budget_at_admission(self):
        mgr = make_manager(per_client_budget=400)
        mgr.register_program(prog("a", "c1", 300, 0.8, 300))
        assert mgr.admit("c1", "a", "k1").verdict is AdmissionVerdict.ADMITTED
        recorded, reason = mgr.record_spend("c1", "k1", 300)
        assert recorded is True
        # Second campaign would exceed the client budget.
        assert mgr.admit("c1", "a", "k2").verdict is AdmissionVerdict.DENIED_CLIENT_BUDGET

    def test_denied_total_budget(self):
        mgr = make_manager(total_budget=350)
        mgr.register_program(prog("a", "c1", 300, 0.8, 200))
        mgr.register_program(prog("b", "c2", 300, 0.8, 200))
        assert mgr.admit("c1", "a", "k1").verdict is AdmissionVerdict.ADMITTED
        mgr.record_spend("c1", "k1", 200)
        assert mgr.admit("c2", "b", "k2").verdict is AdmissionVerdict.DENIED_TOTAL_BUDGET

    def test_record_spend_fail_closed(self):
        mgr = make_manager(per_client_budget=100)
        assert mgr.record_spend("c1", "k1", 60)[0] is True
        recorded, reason = mgr.record_spend("c1", "k2", 60)
        assert recorded is False
        assert "per-client" in reason
        # Nothing was recorded by the refused call.
        assert mgr.budget_snapshot()["spend_by_client"]["c1"] == 60

    def test_unknown_program_denied(self):
        mgr = make_manager()
        decision = mgr.admit("ghost-client", "ghost-program", "k1")
        assert decision.verdict is AdmissionVerdict.DENIED_PROGRAM_UNKNOWN

    def test_zero_caps_disable_limits(self):
        mgr = make_manager()  # all caps 0 → unlimited
        mgr.register_program(prog("a", "c1", 10, 0.1, 10_000_000))
        assert mgr.admit("c1", "a", "k1").verdict is AdmissionVerdict.ADMITTED


class TestAuditAndSnapshot:
    def test_snapshot_is_identifier_level_only(self, tmp_path):
        mgr = make_manager(total_budget=100)
        mgr.register_program(prog("site", "c1", 50, 0.5, 10))
        mgr.admit("c1", "site", "k1")
        mgr.record_spend("c1", "k1", 10)
        blob = json.dumps(mgr.budget_snapshot())
        assert "payload" not in blob and "url" not in blob
        snap = mgr.budget_snapshot()
        assert snap["total_spend"] == 10
        assert snap["registered_programs"] == 1

    def test_audit_log_written(self, tmp_path):
        log = tmp_path / "audit" / "portfolio.jsonl"
        mgr = make_manager(per_campaign_cap=100)
        mgr.register_program(prog("huge", "c1", 5, 0.5, 500))
        decision = mgr.admit("c1", "huge", "k1")
        assert mgr.append_audit_log(log, decision) is True
        record = json.loads(log.read_text().strip().splitlines()[0])
        assert record["verdict"] == "denied_campaign_cap"
        assert record["ts"].endswith("Z")

    def test_audit_log_never_raises(self, tmp_path):
        blocker = tmp_path / "blocker"
        blocker.write_text("file")
        mgr = make_manager()
        decision = mgr.admit("c", "p", "k")
        assert mgr.append_audit_log(blocker / "x" / "y.jsonl", decision) is False
