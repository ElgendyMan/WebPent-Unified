"""U-14 In-Run Adaptation tests.

Restored after the workspace reset. 8 tests over
``webpent.brain.adaptation.AdaptationEngine``:

  * Priors update (2 tests):
      - record_outcome updates the family base rate via the scheduler.
      - the recorded AdaptationEvent has both before- and after-EV
        tables (the logging gate invariant).
  * Strategy switch (3 tests):
      - switch fires when negative streak >= EV_COLLAPSE_THRESHOLD.
      - switch respects SWITCH_COOLDOWN (no switch during cooldown).
      - switch picks "logic" for auth-shaped classes, "nahamsec" for
        everything else.
  * Budget reallocation (3 tests):
      - reallocate_budget delegates to scheduler.allocate_budget and
        records a budget_reallocation event.
      - reallocate_budget clamps remaining_budget to total_budget.
      - check_spend_le_cap enforces the total-budget ceiling.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
os.environ.setdefault("CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
os.environ.setdefault("WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.brain.adaptation import (  # noqa: E402
    AdaptationEngine,
    EV_COLLAPSE_THRESHOLD,
    SWITCH_COOLDOWN,
)
from webpent.brain.ev_scheduler import (  # noqa: E402
    EVScheduler,
    FAMILY_BASE_RATES,
)


def _hyp(*, id: str, vc: str = "SSRF", cost: int = 10) -> dict:
    return {
        "id": id,
        "vulnerability_class": vc,
        "estimated_cost": cost,
        "estimated_llm_calls": 0,
        "recon_signal_matches": 1,
        "lesson_priors": 1.0,
        "chain_potential": 1.0,
    }


# ---------------------------------------------------------------------------
# Priors update (2 tests)
# ---------------------------------------------------------------------------
class TestPriorsUpdate:
    def test_record_outcome_updates_family_base_rate(self):
        """record_outcome(promoted) calls scheduler.update_base_rate and
        the family's base rate moves toward the observed success rate.
        """
        sched = EVScheduler()
        engine = AdaptationEngine(sched, total_budget=100)
        old_rate = FAMILY_BASE_RATES["XSS"]
        engine.record_outcome("XSS", "promoted")
        new_rate = FAMILY_BASE_RATES["XSS"]
        # The base rate must change (move toward observed=1.0).
        assert new_rate != old_rate
        assert new_rate > old_rate  # promoted ⇒ rate increases

    def test_record_outcome_event_has_before_and_after_ev_tables(self):
        """Every AdaptationEvent recorded by record_outcome has both a
        before-EV and after-EV table — the logging-gate invariant.
        """
        sched = EVScheduler()
        engine = AdaptationEngine(sched, total_budget=100)
        engine.record_outcome("SSRF", "refuted")
        events = engine.get_events()
        assert events
        for event in events:
            assert event.has_ev_table(), (
                f"event {event.mechanism} missing EV table — logging gate violated"
            )
        assert engine.check_logging_gate() is True


# ---------------------------------------------------------------------------
# Strategy switch (3 tests)
# ---------------------------------------------------------------------------
class TestStrategySwitch:
    def test_switch_fires_on_ev_collapse(self):
        """After EV_COLLAPSE_THRESHOLD consecutive negatives AND
        SWITCH_COOLDOWN turns since the last switch, the engine
        switches strategy.
        """
        sched = EVScheduler()
        engine = AdaptationEngine(sched, total_budget=100)
        # Pump negatives to hit the threshold.
        for _ in range(EV_COLLAPSE_THRESHOLD):
            engine.record_outcome("SSRF", "refuted")
        events = engine.get_events()
        mechanisms = [e.mechanism for e in events]
        assert "strategy_switch" in mechanisms, (
            "strategy_switch event must fire after EV_COLLAPSE_THRESHOLD negatives"
        )

    def test_switch_respects_cooldown(self):
        """No strategy switch fires before SWITCH_COOLDOWN turns since
        the last switch. We hit the collapse threshold once (first
        switch fires), then pump (SWITCH_COOLDOWN - 1) more negatives
        — the cooldown blocks a second switch.
        """
        sched = EVScheduler()
        engine = AdaptationEngine(sched, total_budget=100)
        # Hit the collapse threshold once — first switch fires.
        for _ in range(EV_COLLAPSE_THRESHOLD):
            engine.record_outcome("SSRF", "refuted")
        first_switch_count = sum(1 for e in engine.get_events() if e.mechanism == "strategy_switch")
        assert first_switch_count == 1
        # Pump (SWITCH_COOLDOWN - 1) more negatives — still inside the
        # cooldown window, so the second switch must NOT fire.
        for _ in range(SWITCH_COOLDOWN - 1):
            engine.record_outcome("SSRF", "refuted")
        second_switch_count = sum(1 for e in engine.get_events() if e.mechanism == "strategy_switch")
        assert second_switch_count == 1, (
            "strategy_switch must not fire during SWITCH_COOLDOWN window"
        )

    def test_switch_picks_logic_for_auth_classes(self):
        """For auth-shaped vuln classes (IDOR/BOLA/AUTH_BYPASS), the
        switch target is "logic"; for everything else, "nahamsec".
        """
        sched = EVScheduler()
        engine_logic = AdaptationEngine(sched, total_budget=100)
        for _ in range(EV_COLLAPSE_THRESHOLD):
            engine_logic.record_outcome("IDOR", "refuted")
        assert engine_logic._current_strategy == "logic"

        sched2 = EVScheduler()
        engine_nahamsec = AdaptationEngine(sched2, total_budget=100)
        for _ in range(EV_COLLAPSE_THRESHOLD):
            engine_nahamsec.record_outcome("SSRF", "refuted")
        assert engine_nahamsec._current_strategy == "nahamsec"


# ---------------------------------------------------------------------------
# Budget reallocation (3 tests)
# ---------------------------------------------------------------------------
class TestBudgetReallocation:
    def test_reallocate_budget_delegates_to_scheduler(self):
        """reallocate_budget returns the same grants the scheduler's
        allocate_budget would produce, and records a
        budget_reallocation event.
        """
        sched = EVScheduler()
        engine = AdaptationEngine(sched, total_budget=100)
        ranked = sched.rank([_hyp(id="h-a"), _hyp(id="h-b")])
        grants = engine.reallocate_budget(ranked, remaining_budget=50)
        # Same shape as scheduler.allocate_budget output.
        assert len(grants) == 2
        for g in grants:
            assert "hypothesis_id" in g and "budget" in g
        # A budget_reallocation event was recorded.
        assert any(e.mechanism == "budget_reallocation" for e in engine.get_events())

    def test_reallocate_budget_clamps_to_total_budget(self):
        """When remaining_budget exceeds total_budget, it is clamped to
        total_budget before allocation.
        """
        sched = EVScheduler()
        engine = AdaptationEngine(sched, total_budget=30)
        ranked = sched.rank([_hyp(id="h-a"), _hyp(id="h-b")])
        # Pass an absurd remaining_budget — must be clamped.
        grants = engine.reallocate_budget(ranked, remaining_budget=99999)
        assert sum(g["budget"] for g in grants) <= 30

    def test_check_spend_le_cap_enforces_total_budget(self):
        """check_spend_le_cap returns True when total_spent <= cap,
        False when total_spent exceeds cap.
        """
        sched = EVScheduler()
        engine = AdaptationEngine(sched, total_budget=50)
        assert engine.check_spend_le_cap(50) is True
        assert engine.check_spend_le_cap(49) is True
        assert engine.check_spend_le_cap(51) is False
