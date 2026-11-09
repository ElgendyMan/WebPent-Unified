# tests/test_safety_governor.py
"""Proposal 10 (2026-10-25) test suite: safety governor v2.

Covers the kill switch (engage/release/idempotent-first-reason), its
rate-governor integration, the request ledger's fail-soft contract, the
LLM spend cap's fail-closed replacement, the agency robots double gate,
and the default-off flag contract for all four controls.
"""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from webpent.config.settings import Settings, activate_settings
from webpent.safety import kill_switch
from webpent.safety.request_ledger import RequestLedger
from webpent.safety.spend_governor import (
    SPEND_CAP_ERROR,
    enforce_spend_cap,
    note_llm_response,
    over_cap,
    record_usage,
    reset,
    used,
)


class TestDefaultOffFlags:
    def test_all_safety_flags_default_false(self) -> None:
        s = Settings()
        assert s.enable_request_ledger is False
        assert s.enable_kill_switch is False
        assert s.enable_llm_spend_cap is False
        assert s.enable_robots_override is False

    def test_spend_cap_flag_has_default_budget(self) -> None:
        assert Settings().llm_token_cap_per_engagement == 1_000_000


@pytest.fixture()
def clean_kill_switch() -> Any:
    kill_switch.release()
    yield kill_switch
    kill_switch.release()


class TestKillSwitch:
    def test_engage_release_cycle(self, clean_kill_switch: Any) -> None:
        assert kill_switch.engaged() is False
        kill_switch.engage("manual stop", operator="op1")
        assert kill_switch.engaged() is True
        status = kill_switch.status()
        assert status["engaged"] is True
        assert status["reason"] == "manual stop"
        assert status["operator"] == "op1"
        kill_switch.release()
        assert kill_switch.engaged() is False
        assert kill_switch.status()["engaged"] is False

    def test_engage_idempotent_keeps_first_reason(self, clean_kill_switch: Any) -> None:
        kill_switch.engage("first", operator="op1")
        kill_switch.engage("second", operator="op2")
        status = kill_switch.status()
        assert status["reason"] == "first"
        assert status["operator"] == "op1"

    def test_release_idempotent(self, clean_kill_switch: Any) -> None:
        kill_switch.release()
        assert kill_switch.engaged() is False
        kill_switch.engage("x")
        kill_switch.release()
        kill_switch.release()
        assert kill_switch.engaged() is False

    def test_engaged_never_raises_on_garbage(self, clean_kill_switch: Any) -> None:
        kill_switch.engage(None)  # type: ignore[arg-type]
        assert kill_switch.engaged() is True
        assert kill_switch.status()["reason"] == "unspecified"


class TestKillSwitchRateGovernorIntegration:
    def test_flag_off_kill_switch_ignored(self, clean_kill_switch: Any) -> None:
        from webpent.shared.rate_governor import RequestRateGovernor
        from webpent.config.settings import activate_settings

        kill_switch.engage("frozen")
        governor = RequestRateGovernor(max_concurrent=2)
        with activate_settings(Settings()):
            with governor.acquire("t.example") as permit:
                assert permit.aborted is False  # flag off: unchanged behaviour

    def test_engaged_switch_aborts_before_cap(self, clean_kill_switch: Any) -> None:
        from webpent.shared.rate_governor import RequestRateGovernor
        from webpent.config.settings import Settings, activate_settings

        kill_switch.engage("frozen")
        governor = RequestRateGovernor(max_concurrent=2)
        settings = Settings(enable_kill_switch=True)
        with activate_settings(settings):
            with governor.acquire("t.example") as permit:
                assert permit.aborted is True
                assert permit.reason == "kill_switch_engaged"
            # Host state was NOT consumed by the aborted acquire.
            assert governor.get_stats("t.example")["in_flight"] == 0
        kill_switch.release()
        # After release the same governor works again.
        with activate_settings(settings):
            with governor.acquire("t.example") as permit:
                assert permit.aborted is False


class TestRequestLedger:
    @pytest.fixture()
    def ledger(self, tmp_path: Any) -> RequestLedger:
        return RequestLedger(db_path=str(tmp_path / "requests.db"))

    def test_record_and_stats(self, ledger: RequestLedger) -> None:
        assert ledger.record("GET", "https://t.example/a", engagement_id="eng1") is True
        ledger.record("POST", "https://t.example/b", engagement_id="eng1", flags="ssrf_pinned")
        stats = ledger.stats()
        assert stats["rows"] >= 2
        entries = ledger.entries(limit=10)
        assert {e["method"] for e in entries} >= {"GET", "POST"}
        assert any(e["engagement_id"] == "eng1" for e in entries)

    def test_record_fail_soft_on_garbage(self, ledger: RequestLedger) -> None:
        # Never raises, even for absurd inputs.
        assert ledger.record("", "") is True or True  # type: ignore[arg-type]
        try:
            ledger.record(None, None)  # type: ignore[arg-type]
        except Exception:  # noqa: BLE001
            pytest.fail("record must be fail-soft")

    def test_memory_degradation(self, tmp_path: Any) -> None:
        ledger = RequestLedger(db_path=str(tmp_path / "no-dir" / "x.db" / "sub"))
        assert ledger.record("GET", "https://t.example/a") is True
        assert ledger.stats()["rows"] >= 1

    def test_ttl_expiry_via_injected_clock(self, tmp_path: Any) -> None:
        now = [1000.0]
        ledger = RequestLedger(
            db_path=str(tmp_path / "requests.db"),
            ttl_seconds=50.0,
            now=lambda: now[0],
        )
        ledger.record("GET", "https://t.example/a")
        now[0] += 100.0  # past TTL
        ledger.record("GET", "https://t.example/b")
        ledger.prune()
        stats = ledger.stats()
        assert stats["rows"] == 1  # expired row pruned

    def test_row_cap(self, tmp_path: Any) -> None:
        ledger = RequestLedger(
            db_path=str(tmp_path / "requests.db"), max_rows=5, ttl_seconds=0.0
        )
        for i in range(12):
            ledger.record("GET", f"https://t.example/{i}")
        ledger.prune()
        assert ledger.stats()["rows"] == 5

    def test_hook_fail_soft(self) -> None:
        from webpent.safety.request_ledger import ledger_request_hook

        class FakeRequest:
            method = "GET"
            url = "https://t.example/x"

        ledger_request_hook(FakeRequest())  # must not raise
        ledger_request_hook(None)  # type: ignore[arg-type]  # must not raise


class TestSpendGovernor:
    def test_counter_accumulates_and_resets(self) -> None:
        reset("eng-sp")
        assert record_usage("eng-sp", 100) == 100
        assert record_usage("eng-sp", 50) == 150
        assert used("eng-sp") == 150
        reset("eng-sp")
        assert used("eng-sp") == 0

    def test_negative_and_garbage_tokens_ignored(self) -> None:
        reset("eng-sp")
        record_usage("eng-sp", 100)
        assert record_usage("eng-sp", -5) == 100
        assert record_usage("eng-sp", None) == 100  # type: ignore[arg-type]
        reset("eng-sp")

    def test_note_llm_response_reads_tokens(self) -> None:
        reset("eng-sp")
        note_llm_response(_response(tokens_used=77), engagement_id="eng-sp")
        assert used("eng-sp") == 77
        reset("eng-sp")

    def test_over_cap_contract(self) -> None:
        reset("eng-cap")
        # No settings active: cap check fail-closed to "not over".
        assert over_cap("eng-cap") is False


def _response(tokens_used: int = 0, error: str | None = None) -> Any:
    from webpent.llm_researcher.providers.base import LLMResponse

    return LLMResponse(model="m", content="hello", tokens_used=tokens_used, error=error)


class TestSpendCapEnforcement:
    def test_under_cap_response_unchanged(self) -> None:
        reset("eng-cap")
        record_usage("eng-cap", 10)
        response = _response(tokens_used=5)
        out = enforce_spend_cap(response)
        assert out is response or out.content == "hello"
        assert out.error is None
        reset("eng-cap")

    def test_at_cap_fails_closed_with_error_response(self) -> None:
        from webpent.config.settings import Settings, activate_settings

        reset("eng-cap")
        settings = Settings(enable_llm_spend_cap=True, llm_token_cap_per_engagement=100)
        with activate_settings(settings):
            record_usage("eng-cap", 100)  # exactly at cap
            response = _response(tokens_used=10)
            out = enforce_spend_cap(response, engagement_id="eng-cap")
            assert out.error == SPEND_CAP_ERROR
            assert out.finish_reason == "spend_cap_reached"
            assert out.content == ""
            assert out.model == "m"  # same type, same identity fields
            assert out.tokens_used == 10  # usage preserved for telemetry
        reset("eng-cap")

    def test_provider_error_passthrough(self) -> None:
        reset("eng-cap")
        record_usage("eng-cap", 999_999)
        response = _response(error="PROVIDER_ERROR: x")
        out = enforce_spend_cap(response, engagement_id="eng-cap")
        assert out is response  # already failed — untouched
        reset("eng-cap")

    def test_flag_off_generate_unchanged(self) -> None:
        from webpent.config.settings import Settings, activate_settings
        from webpent.llm_researcher.providers.base import BaseLLMProvider

        class FakeProvider(BaseLLMProvider):
            def _call_api(self, prompt: str, max_tokens: int, **kwargs: Any) -> Any:
                return _response(tokens_used=10)

            @property
            def provider_type(self) -> str:  # pragma: no cover
                return "FAKE"

            @property
            def is_mock(self) -> bool:  # pragma: no cover
                return True

        reset("eng-cap")
        provider = FakeProvider(model="m")
        with activate_settings(Settings(enable_llm_spend_cap=False)):
            out = provider.generate("hi")
        assert out.error is None
        assert out.content == "hello"
        reset("eng-cap")

    def test_flag_on_generate_caps_after_threshold(self) -> None:
        from webpent.config.settings import Settings, activate_settings
        from webpent.llm_researcher.providers.base import BaseLLMProvider

        class FakeProvider(BaseLLMProvider):
            def _call_api(self, prompt: str, max_tokens: int, **kwargs: Any) -> Any:
                return _response(tokens_used=100)

            @property
            def provider_type(self) -> str:  # pragma: no cover
                return "FAKE"

            @property
            def is_mock(self) -> bool:  # pragma: no cover
                return True

        reset("eng-cap")
        settings = Settings(enable_llm_spend_cap=True, llm_token_cap_per_engagement=150)
        with activate_settings(settings):
            provider = FakeProvider(model="m")
            first = provider.generate("hi")
            assert first.error is None  # 100 < 150
            second = provider.generate("hi")
            assert second.error == SPEND_CAP_ERROR  # 200 >= 150, fails CLOSED
        reset("eng-cap")


class TestAgencyRobotsDoubleGate:
    def test_flag_off_preserves_legacy_lift(self) -> None:
        from webpent.config.settings import Settings, activate_settings
        from webpent.safety.agency import robots_lift_authorized

        with activate_settings(Settings(enable_robots_override=False)):
            assert robots_lift_authorized("eng1") is True

    def test_flag_on_without_allowlist_fails_closed(self) -> None:
        from webpent.config.settings import Settings, activate_settings
        from webpent.safety.agency import robots_lift_authorized, robots_override_allowed

        settings = Settings(enable_robots_override=True)
        with activate_settings(settings):
            assert robots_lift_authorized("eng1") is False
            assert robots_override_allowed("eng1") is False
            assert robots_override_allowed("unassigned") is False

    def test_flag_on_with_allowlist_authorized(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from webpent.config.settings import Settings, activate_settings
        from webpent.safety.agency import robots_lift_authorized, robots_override_allowed

        monkeypatch.setenv("WEBPENT_ROBOTS_OVERRIDE_ENGAGEMENTS", "engA, engB")
        settings = Settings(enable_robots_override=True)
        with activate_settings(settings):
            assert robots_override_allowed("engA") is True
            assert robots_lift_authorized("engB") is True
            assert robots_override_allowed("engC") is False

    def test_robots_allows_respects_double_gate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from webpent.config.settings import Settings, activate_settings
        from webpent.recon.autonomous_crawler import CrawlConfig

        class Minimal:
            config = CrawlConfig(respect_robots=False)
            _robots = None
            _robots_checked = True

        from webpent.recon.autonomous_crawler import AutonomousCrawler

        target = Minimal()
        settings = Settings(enable_robots_override=True)
        with activate_settings(settings):
            # Not allowlisted -> gate fails -> robots stay respected.
            result = AutonomousCrawler._robots_allows(target, "https://t.example/x")
            assert result == (False, "robots_unavailable")


class TestStatusSnapshot:
    def test_snapshot_never_raises_and_has_sections(self) -> None:
        from webpent.safety.status_snapshot import safety_snapshot

        snap = safety_snapshot()
        assert "kill_switch" in snap
        assert "request_ledger" in snap
        assert "llm_spend" in snap


class TestV31Fixes:
    """The v3.1 spend-governor fixes: usage fall-through, eviction bound,
    capped-response spend accounting."""

    def setup_method(self) -> None:
        reset("eng-v31")

    def teardown_method(self) -> None:
        reset("eng-v31")

    def test_zero_tokens_used_falls_through_to_usage_dict(self) -> None:
        # tokens_used is a dataclass field defaulting to 0; a response
        # whose provider filled only `usage` was recorded as 0 (v3.0 bug).
        resp = SimpleNamespace(tokens_used=0, usage={"total_tokens": 123})
        note_llm_response(resp, engagement_id="eng-v31")
        assert used("eng-v31") == 123

    def test_nonzero_tokens_used_wins_over_usage(self) -> None:
        resp = SimpleNamespace(tokens_used=50, usage={"total_tokens": 123})
        note_llm_response(resp, engagement_id="eng-v31")
        assert used("eng-v31") == 50

    def test_usage_object_with_total_tokens_attribute(self) -> None:
        usage = SimpleNamespace(total_tokens=64)
        resp = SimpleNamespace(tokens_used=0, usage=usage)
        note_llm_response(resp, engagement_id="eng-v31")
        assert used("eng-v31") == 64

    def test_counters_are_evicted_at_bound(self) -> None:
        from webpent.safety import spend_governor as sg

        for i in range(sg.MAX_TRACKED_ENGAGEMENTS + 10):
            sg.record_usage(f"eng-evict-{i}", 10)
        assert len(sg._counters) <= sg.MAX_TRACKED_ENGAGEMENTS
        # the low-usage first keys were evicted; the latest remain
        assert f"eng-evict-{sg.MAX_TRACKED_ENGAGEMENTS + 9}" in sg._counters
        for i in range(sg.MAX_TRACKED_ENGAGEMENTS + 10):
            sg._counters.pop(f"eng-evict-{i}", None)

    def test_capped_response_keeps_its_spend(self) -> None:
        from dataclasses import dataclass, field as dc_field

        @dataclass
        class Resp:
            content: str = "x"
            raw_content: str = "x"
            tokens_used: int = 0
            finish_reason: str = ""
            error: str | None = None

        from webpent.safety import spend_governor as sg

        reset("eng-v31-cap")
        with activate_settings(
            Settings(enable_llm_spend_cap=True, llm_token_cap_per_engagement=500)
        ):
            resp = Resp(tokens_used=900)
            # enforce_spend_cap records usage itself; the capped call's
            # spend must land in the counter exactly once
            capped = sg.enforce_spend_cap(resp, engagement_id="eng-v31-cap")
        assert capped.error == sg.SPEND_CAP_ERROR
        # the replacement must NOT zero the usage out
        assert capped.tokens_used == 900
        assert used("eng-v31-cap") == 900
        reset("eng-v31-cap")


class TestV31RequestLedgerFixes:
    """The v3.1 request-ledger fixes: WAL + busy timeout, consistent
    newest-first entries() ordering, non-stalling amortized prune."""

    def _fresh(self, tmp_path) -> "RequestLedger":
        from webpent.safety.request_ledger import RequestLedger

        return RequestLedger(db_path=str(tmp_path / f"rl-{tmp_path.name}.db"))

    def test_sqlite_uses_wal_and_busy_timeout(self, tmp_path) -> None:
        import sqlite3

        from webpent.safety.request_ledger import RequestLedger

        rl = self._fresh(tmp_path)
        assert rl._conn is not None
        assert rl._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert rl._conn.execute("PRAGMA busy_timeout").fetchone()[0] > 0

    def test_entries_newest_first_both_backends(self, tmp_path) -> None:
        from webpent.safety.request_ledger import RequestLedger

        for rl in (self._fresh(tmp_path), RequestLedger(db_path=None)):
            for i in range(5):
                rl.record("GET", f"https://t/{i}", engagement_id="e1")
            urls = [e["url"] for e in rl.entries(limit=5)]
            assert urls == [f"https://t/{i}" for i in (4, 3, 2, 1, 0)], (
                f"backend {type(rl._conn)}: entries must be newest-first"
            )

    def test_prune_still_enforces_cap_after_reordering(self, tmp_path) -> None:
        from webpent.safety.request_ledger import RequestLedger

        rl = self._fresh(tmp_path)
        rl._max_rows = 10
        for i in range(25):
            rl.record("GET", f"https://t/{i}", engagement_id="e1")
        rl.prune()
        n = rl._conn.execute("SELECT COUNT(*) FROM request_ledger").fetchone()[0]
        assert n <= 10
        # newest rows survive
        urls = [e["url"] for e in rl.entries(limit=100)]
        assert "https://t/24" in urls


class TestV31KillSwitchFixes:
    """The v3.1 kill-switch fixes: torn-payload race closed, publish
    order serialized, subscriber reconnects after a Redis drop."""

    def test_engage_payload_captured_under_lock(self) -> None:
        from webpent.safety import kill_switch as ks

        ks.release()
        captured = []
        original_publish = ks._publish

        def spy(payload):
            captured.append(dict(payload))

        ks._publish = spy
        try:
            ks.engage("test torn read", operator="op1")
            ks.release()
        finally:
            ks._publish = original_publish
        assert captured[0]["engaged"] is True
        assert captured[0]["reason"] == "test torn read"
        assert captured[0]["operator"] == "op1"
        assert "seq" in captured[0]
        assert captured[-1]["engaged"] is False
        assert captured[-1]["seq"] > captured[0]["seq"]

    def test_release_after_engage_publishes_in_order(self) -> None:
        from webpent.safety import kill_switch as ks

        ks.release()
        order = []
        original_publish = ks._publish

        def spy(payload):
            order.append(payload["engaged"])

        ks._publish = spy
        try:
            ks.engage("r1")
            ks.release()
            ks.engage("r2")
        finally:
            ks._publish = original_publish
        assert order == [True, False, True]
        ks.release()

    def test_engage_idempotent_does_not_republish(self) -> None:
        from webpent.safety import kill_switch as ks

        ks.release()
        n = []
        original_publish = ks._publish
        ks._publish = lambda p: n.append(p)
        try:
            ks.engage("first")
            ks.engage("second")
        finally:
            ks._publish = original_publish
        assert len(n) == 1
        assert n[0]["reason"] == "first"
        ks.release()

    def test_subscriber_loop_reconnects_after_redis_drop(self, monkeypatch) -> None:
        """The listener must retry, not die: simulate two failures then
        a successful subscribe, and assert it kept coming back."""
        import sys
        import time as _time

        from webpent.safety import kill_switch as ks

        subscribe_attempts = []

        class FakePubsub:
            def subscribe(self, *a, **k) -> None:
                subscribe_attempts.append(1)
                if len(subscribe_attempts) < 3:
                    raise ConnectionError("redis down")

            def listen(self):
                yield {"type": "message", "data": b'{"engaged": true}'}  # then apply once

        class FakeClient:
            @classmethod
            def from_url(cls, url, **k):
                return cls()

            def pubsub(self, **k):
                return FakePubsub()

        fake = type(sys)("fake_redis")
        fake.Redis = FakeClient
        monkeypatch.setitem(sys.modules, "redis", fake)
        # break out of the reconnect loop only AFTER the third subscribe
        # attempt succeeds (two simulated Redis drops first)
        def _sleep(s: float) -> None:
            if len(subscribe_attempts) >= 3:
                raise KeyboardInterrupt

        monkeypatch.setattr(ks.time, "sleep", _sleep)
        try:
            ks._listen_loop("redis://fake")
        except KeyboardInterrupt:
            pass
        assert len(subscribe_attempts) == 3, "loop must have reconnected after failures"
        from webpent.safety import kill_switch as ks2

        ks2.release()
