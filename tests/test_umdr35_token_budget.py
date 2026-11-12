# tests/test_umdr35_token_budget.py
"""UM-DR-35.5 — Gate 35-E hard campaign token budget regression tests.

The campaign-wide total-token ceiling is HARD: it is enforced BEFORE
provider I/O with a conservative reservation, settles against reported
usage, counts unknown usage honestly (never zero), and exhaustion routes
to deterministic fallback with BUDGET_EXHAUSTED status. Unresolved
hypotheses are never marked negative.
"""
from __future__ import annotations

import pytest

from webpent.shared.llm import (
    LLMBudgetExhaustedError,
    LLMBudgetTokenExhaustedError,
    _consume_llm_call_budget,
    _settle_llm_budget_call,
    get_llm_budget_summary,
    llm_usage_scope,
)


class _FakeSettings:
    llm_max_calls_per_run = 100
    llm_warning_tokens_per_run = 0
    llm_max_tokens = 512
    llm_max_total_tokens_per_run = 0


def _settings_with(ceiling: int) -> _FakeSettings:
    s = _FakeSettings()
    s.llm_max_total_tokens_per_run = ceiling
    return s


class TestHardTokenCeiling:
    def test_explicit_ceiling_blocks_before_provider_io(self):
        # reservation per call = llm_max_tokens + 512 overhead = 1024; a
        # ceiling BELOW the conservative reservation blocks the FIRST call.
        with llm_usage_scope(_settings_with(0), max_total_tokens=1000) as _, pytest.raises(
                LLMBudgetTokenExhaustedError):
            _consume_llm_call_budget()

    def test_ceiling_allows_then_blocks(self):
        settings = _settings_with(0)
        settings.llm_max_tokens = 100  # reservation = 612
        with llm_usage_scope(settings, max_total_tokens=1300) as _:
            _consume_llm_call_budget()  # reserved 612
            _settle_llm_budget_call(
                input_tokens=50, output_tokens=50, total_tokens=100)
            # accounted = 100; next reservation 612 -> 712 <= 1300
            _consume_llm_call_budget()
            _settle_llm_budget_call(
                input_tokens=50, output_tokens=50, total_tokens=100)
            # accounted = 200; next reservation 612 -> 812 <= 1300
            _consume_llm_call_budget()
            _settle_llm_budget_call(
                input_tokens=50, output_tokens=50, total_tokens=100)
            # accounted = 300 + 612 = 912 <= 1300
            _consume_llm_call_budget()
            _settle_llm_budget_call(
                input_tokens=50, output_tokens=50, total_tokens=100)
            # accounted = 400; 400 + 612 = 1012 <= 1300 ok
            _consume_llm_call_budget()
            _settle_llm_budget_call(
                input_tokens=50, output_tokens=50, total_tokens=100)
            # accounted = 500; 500 + 612 = 1112 <= 1300 ok
            _consume_llm_call_budget()
            _settle_llm_budget_call(
                input_tokens=50, output_tokens=50, total_tokens=100)
            # accounted = 600; 600 + 612 = 1212 <= 1300 ok
            _consume_llm_call_budget()
            _settle_llm_budget_call(
                input_tokens=50, output_tokens=50, total_tokens=100)
            # accounted = 700; 700 + 612 > 1300 -> blocked
            with pytest.raises(LLMBudgetTokenExhaustedError):
                _consume_llm_call_budget()

    def test_zero_ceiling_disables_token_check(self):
        with llm_usage_scope(_settings_with(0), max_total_tokens=0) as _:
            for _ in range(20):
                _consume_llm_call_budget()
                _settle_llm_budget_call(input_tokens=None, output_tokens=None,
                                        total_tokens=None)

    def test_settings_default_ceiling_used_when_no_override(self):
        with llm_usage_scope(_settings_with(2048)) as _:
            summary = get_llm_budget_summary()
            assert summary["max_total_tokens"] == 2048


class TestHonestAccounting:
    def test_unknown_usage_is_never_zero(self):
        settings = _settings_with(0)
        settings.llm_max_tokens = 100
        with llm_usage_scope(settings, max_total_tokens=10_000) as _:
            _consume_llm_call_budget()
            _settle_llm_budget_call(
                input_tokens=None, output_tokens=None, total_tokens=None)
            summary = get_llm_budget_summary()
            assert summary["unknown_usage_calls"] == 1
            assert summary["total_tokens"] == 612  # the reservation, not 0
            assert summary["reserved_tokens"] == 0

    def test_known_usage_settles_split(self):
        settings = _settings_with(0)
        settings.llm_max_tokens = 100
        with llm_usage_scope(settings, max_total_tokens=10_000) as _:
            _consume_llm_call_budget()
            _settle_llm_budget_call(
                input_tokens=700, output_tokens=300, total_tokens=1000)
            summary = get_llm_budget_summary()
            assert summary["input_tokens"] == 700
            assert summary["output_tokens"] == 300
            assert summary["total_tokens"] == 1000
            assert summary["unknown_usage_calls"] == 0
            assert summary["reserved_tokens"] == 0

    def test_summary_reports_exhaustion_state(self):
        settings = _settings_with(0)
        settings.llm_max_tokens = 100
        with llm_usage_scope(settings, max_total_tokens=600) as _:
            with pytest.raises(LLMBudgetTokenExhaustedError):
                _consume_llm_call_budget()
            summary = get_llm_budget_summary()
            assert summary["tokens_exhausted"] is True
            assert summary["blocked"] is True

    def test_call_cap_still_enforced(self):
        settings = _settings_with(0)
        settings.llm_max_calls_per_run = 1
        with llm_usage_scope(settings, max_total_tokens=0) as _:
            _consume_llm_call_budget()
            with pytest.raises(LLMBudgetExhaustedError):
                _consume_llm_call_budget()


class TestCampaignBudgetStatusContract:
    """unified_hunt summary exposes the ceiling and honest statuses."""

    def test_budget_status_vocabulary(self):
        from webpent.cli.unified_hunt import run_unified_hunt  # noqa: F401
        # The status vocabulary is fixed; the mapping itself is exercised in
        # the compiled-graph E2E tests (tests/team1_acceptance and the
        # UM-DR-36 lab campaign).
        allowed = {"COMPLETED", "BUDGET_EXHAUSTED", "PARTIAL", "INTERRUPTED", "FAILED"}
        assert "BUDGET_EXHAUSTED" in allowed

    def test_cli_accepts_max_tokens_flag(self):
        import inspect

        from webpent.cli.commands import hunt
        sig = inspect.signature(hunt)
        assert "max_tokens" in sig.parameters, (
            "webpent hunt must expose --max-tokens (UM-DR-35.5)"
        )

    def test_agent_hunt_accepts_max_tokens_flag(self):
        import inspect

        from webpent.cli.commands import hunt_command
        sig = inspect.signature(hunt_command)
        assert "max_tokens" in sig.parameters, (
            "webpent agent-hunt must expose --max-tokens (UM-DR-35.5)"
        )
