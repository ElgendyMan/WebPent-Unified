# tests/test_model_tiering.py
"""PROPOSALS_ULTIMATE_V2 §9 (2026-10-30) test suite: model tiering.

Covers the deterministic task->tier table (every LLMTask member
resolved, unknown tasks conservatively to ``strong``), tier-model
resolution with automatic fallback (unconfigured tier, pool-declared
unavailability), the fail-closed refusals (flag off, both tiers
unconfigured), flag parsing (``provider/model`` and bare names), the
provider-funnel tier classification, and per-tier spend accounting in
the spend governor — including that tier counters never affect the
spend cap.
"""

from __future__ import annotations

import pytest

from webpent.config.settings import Settings, activate_settings, get_settings
from webpent.llm_researcher import tiering
from webpent.llm_researcher.task_router import LLMTask
from webpent.llm_researcher.tiering import (
    TIER_FAST,
    TIER_STRONG,
    UNCLASSIFIED_TIER,
    ModelTieringError,
    TASK_TIER_TABLE,
    model_tier_of,
    note_tiered_call,
    parse_tier_flag,
    resolve_tier_model,
    tier_for_task,
)
from webpent.safety import spend_governor


# ---------------------------------------------------------------------------
# Deterministic task->tier table.
# ---------------------------------------------------------------------------


class TestTaskTierTable:
    def test_every_llm_task_member_resolved(self) -> None:
        for task in LLMTask:
            assert tier_for_task(task.value) in {TIER_FAST, TIER_STRONG}

    def test_exploration_tasks_are_fast(self) -> None:
        for task in (
            "recon_analyze_page",
            "web_recon_search",
            "endpoint_extract",
            "output_analyze",
        ):
            assert tier_for_task(task) == TIER_FAST

    def test_reasoning_tasks_are_strong(self) -> None:
        for task in ("hypothesis_generate", "payload_select", "code_exploit_write"):
            assert tier_for_task(task) == TIER_STRONG

    def test_unknown_task_is_strong(self) -> None:
        # Never silently downgrade an unseen task to the cheap model.
        assert tier_for_task("totally_new_task") == TIER_STRONG
        assert tier_for_task("") == TIER_STRONG

    def test_deterministic(self) -> None:
        assert all(
            tier_for_task(t) == tier_for_task(t) for t in TASK_TIER_TABLE
        )


# ---------------------------------------------------------------------------
# Flag parsing.
# ---------------------------------------------------------------------------


class TestParseTierFlag:
    def test_provider_model(self) -> None:
        assert parse_tier_flag("zai/glm-4.7-flash") == ("zai", "glm-4.7-flash")

    def test_bare_name_defaults_openai(self) -> None:
        assert parse_tier_flag("glm-4.7-flash") == ("openai", "glm-4.7-flash")

    def test_empty_is_none(self) -> None:
        assert parse_tier_flag("") is None
        assert parse_tier_flag("   ") is None


# ---------------------------------------------------------------------------
# Resolution: deterministic route, fallback, fail-closed refusals.
# ---------------------------------------------------------------------------


class TestResolveTierModel:
    KW = dict(
        enable_model_tiering=True,
        model_tier_fast="zai/glm-4.7-flash",
        model_tier_strong="zai/glm-4.7-max",
    )

    def test_flag_off_refused(self) -> None:
        with pytest.raises(ModelTieringError, match="model_tiering_flag_off"):
            resolve_tier_model(
                "recon_analyze_page",
                enable_model_tiering=False,
                model_tier_fast="a/m",
                model_tier_strong="b/m",
            )

    def test_both_tiers_unconfigured_refused(self) -> None:
        with pytest.raises(
            ModelTieringError, match="model_tier_no_models_configured"
        ):
            resolve_tier_model(
                "recon_analyze_page",
                enable_model_tiering=True,
                model_tier_fast="",
                model_tier_strong="",
            )

    def test_exploration_routes_fast(self) -> None:
        route = resolve_tier_model("endpoint_extract", **self.KW)
        assert (route.tier, route.provider, route.model) == (
            TIER_FAST, "zai", "glm-4.7-flash",
        )
        assert route.fell_back is False

    def test_reasoning_routes_strong(self) -> None:
        route = resolve_tier_model("code_exploit_write", **self.KW)
        assert (route.tier, route.model) == (TIER_STRONG, "glm-4.7-max")
        assert route.fell_back is False

    def test_deterministic_repeats(self) -> None:
        first = resolve_tier_model("payload_select", **self.KW)
        for _ in range(5):
            assert resolve_tier_model("payload_select", **self.KW) == first

    def test_fallback_when_tier_unconfigured(self) -> None:
        # fast tier has no model: exploration falls back to the strong
        # tier's configured model, never to an invented default.
        route = resolve_tier_model(
            "recon_analyze_page",
            enable_model_tiering=True,
            model_tier_fast="",
            model_tier_strong="zai/glm-4.7-max",
        )
        assert route.fell_back is True
        assert route.model == "glm-4.7-max"
        assert "fell_back_to_strong" in route.reason

    def test_fallback_when_pool_marks_unavailable(self) -> None:
        class _Pool:
            def available(self, provider: str, model: str) -> bool:
                return model != "glm-4.7-flash"  # fast model down

        route = resolve_tier_model("output_analyze", pool=_Pool(), **self.KW)
        assert route.fell_back is True
        assert route.model == "glm-4.7-max"

    def test_no_fallback_when_pool_confirms(self) -> None:
        class _Pool:
            def available(self, provider: str, model: str) -> bool:
                return True

        route = resolve_tier_model("output_analyze", pool=_Pool(), **self.KW)
        assert route.fell_back is False

    def test_pool_unavailable_on_both_refused(self) -> None:
        class _Pool:
            def available(self, provider: str, model: str) -> bool:
                return False

        with pytest.raises(ModelTieringError):
            resolve_tier_model("output_analyze", pool=_Pool(), **self.KW)


# ---------------------------------------------------------------------------
# Funnel classification (model-name based, no task context there).
# ---------------------------------------------------------------------------


class TestModelTierOf:
    def test_matches_fast_flag(self) -> None:
        assert model_tier_of(
            "glm-4.7-flash", model_tier_fast="zai/glm-4.7-flash",
            model_tier_strong="zai/glm-4.7-max",
        ) == TIER_FAST

    def test_matches_strong_flag(self) -> None:
        assert model_tier_of(
            "glm-4.7-max", model_tier_fast="zai/glm-4.7-flash",
            model_tier_strong="zai/glm-4.7-max",
        ) == TIER_STRONG

    def test_unclassified_model(self) -> None:
        assert model_tier_of(
            "gpt-9", model_tier_fast="zai/glm-4.7-flash",
            model_tier_strong="zai/glm-4.7-max",
        ) == UNCLASSIFIED_TIER


# ---------------------------------------------------------------------------
# Per-tier spend accounting.
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, tokens: int) -> None:
        self.tokens_used = tokens
        self.error = None


class TestTierSpendAccounting:
    def setup_method(self) -> None:
        spend_governor._tier_counters.clear()
        spend_governor._counters.clear()

    def test_record_and_snapshot_per_tier(self) -> None:
        spend_governor.record_tier_usage("fast", 100, engagement_id="e1")
        spend_governor.record_tier_usage("fast", 50, engagement_id="e1")
        spend_governor.record_tier_usage("strong", 700, engagement_id="e1")
        spend_governor.record_tier_usage("fast", 999, engagement_id="e2")
        snap = spend_governor.tier_snapshot("e1")
        assert snap == {"fast": 150, "strong": 700}
        # all-engagement view still separates tiers
        assert spend_governor.tier_snapshot()["fast"] == 1149

    def test_nonpositive_and_garbage_tokens_ignored(self) -> None:
        assert spend_governor.record_tier_usage("fast", 0) == 0
        assert spend_governor.record_tier_usage("fast", -5) == 0
        assert spend_governor.record_tier_usage("fast", "junk") == 0  # type: ignore[arg-type]
        assert spend_governor.tier_snapshot() == {}

    def test_tier_counters_do_not_touch_engagement_cap(self) -> None:
        from webpent.config.settings import Settings

        with activate_settings(
            Settings(enable_llm_spend_cap=True, llm_token_cap_per_engagement=100)
        ):
            spend_governor.reset("t1")
            spend_governor.record_tier_usage("strong", 1000, engagement_id="t1")
            # the engagement counter is what the cap reads: unchanged
            assert spend_governor.used("t1") == 0
            r = spend_governor.enforce_spend_cap(
                _FakeResponse(50), engagement_id="t1"
            )
            assert r.tokens_used == 50
            assert r.error is None

    def test_note_tiered_call_classifies_and_records(self) -> None:
        with activate_settings(
            Settings(
                enable_model_tiering=True,
                model_tier_fast="zai/glm-4.7-flash",
                model_tier_strong="zai/glm-4.7-max",
            )
        ):
            assert note_tiered_call("glm-4.7-flash", _FakeResponse(10)) == TIER_FAST
            assert note_tiered_call("glm-4.7-max", _FakeResponse(90)) == TIER_STRONG
            assert note_tiered_call("gpt-9", _FakeResponse(5)) == UNCLASSIFIED_TIER
            snap = spend_governor.tier_snapshot()
            assert snap == {"fast": 10, "strong": 90, "unclassified": 5}

    def test_note_tiered_call_flag_off_unclassified_noop(self) -> None:
        with activate_settings(Settings(enable_model_tiering=False)):
            assert (
                note_tiered_call("glm-4.7-flash", _FakeResponse(10))
                == UNCLASSIFIED_TIER
            )
            assert spend_governor.tier_snapshot() == {}

    def test_tier_breakdown_delegates(self) -> None:
        with activate_settings(
            Settings(
                enable_model_tiering=True,
                model_tier_fast="zai/glm-4.7-flash",
                model_tier_strong="zai/glm-4.7-max",
            )
        ):
            note_tiered_call("glm-4.7-flash", _FakeResponse(7))
            assert dict(tiering.tier_breakdown()) == {"fast": 7}


# ---------------------------------------------------------------------------
# Settings gate.
# ---------------------------------------------------------------------------


class TestSettingsGate:
    def test_defaults_off_and_empty(self) -> None:
        with activate_settings(Settings()):
            assert get_settings().enable_model_tiering is False
            assert get_settings().model_tier_fast == ""
            assert get_settings().model_tier_strong == ""

    def test_flags_activate(self) -> None:
        with activate_settings(
            Settings(
                enable_model_tiering=True,
                model_tier_fast="zai/glm-4.7-flash",
                model_tier_strong="zai/glm-4.7-max",
            )
        ):
            assert get_settings().enable_model_tiering is True
            assert get_settings().model_tier_fast == "zai/glm-4.7-flash"
            assert get_settings().model_tier_strong == "zai/glm-4.7-max"
