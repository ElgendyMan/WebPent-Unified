# tests/test_waf_adaptive.py
"""PROPOSALS_ULTIMATE_V3 §3 (2026-10-31) test suite: adaptive WAF evasion.

Covers the transform registry (pure, documented, identity-escaping),
block classification (documented statuses and body markers), the
backoff curve with ceiling, the flag gate (off = zero touches), the
kill switch (engaged = no send at all), the mandatory per-attempt
safety path (scope refusal before send, ledger refusal = not sent),
adaptive behavior (original first, transforms on block only,
session memory reorders later sends, successful transform remembered),
the attempt bound (bounded attempts, never a retry storm) and
real-ledger contract compatibility. All senders here are fakes — the
client owns no network.
"""

from __future__ import annotations

import pytest

from webpent.waf_evasion.adaptive import (
    AdaptiveClient,
    AdaptiveContext,
    AdaptiveResponse,
    AdaptiveEvasionError,
    MAX_ATTEMPTS_CAP,
    TRANSFORM_ORDER,
    BackoffPolicy,
    classify_waf_block,
    transform_registry,
    waf_adaptive_refusal,
)

URL = "https://target.example.com/api/search"


def _context() -> AdaptiveContext:
    return AdaptiveContext(url=URL, method="POST", engagement_id="e1")


def _activated(**extra):
    from webpent.config.settings import Settings, activate_settings

    return activate_settings(Settings(enable_waf_adaptive=True, **extra))


class FakeLedger:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.recorded: list[str] = []

    def record(self, method, url, *, engagement_id="", flags=""):
        if not self.ok:
            return False
        self.recorded.append(flags)
        return True


class FakeScope:
    def __init__(self, allowed=("target.example.com",)):
        self.allowed = allowed
        self.checked: list[str] = []

    def check_url(self, url, *, method=""):
        self.checked.append(url)
        host = url.split("/")[2] if "://" in url else url
        return SimpleDecision(allowed=host in self.allowed)


class SimpleDecision:
    def __init__(self, allowed: bool):
        self.allowed = allowed


class ScriptedSender:
    """Fake request_fn: scripted per-call outcomes, records payloads."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.payloads: list[str] = []

    def __call__(self, payload: str) -> AdaptiveResponse:
        self.payloads.append(payload)
        if self.outcomes:
            status, body = self.outcomes.pop(0)
            return AdaptiveResponse(status=status, body=body)
        return AdaptiveResponse(status=200, body="ok")


def _no_sleep(_delay: float) -> None:  # tests control the clock
    return None


# ---------------------------------------------------------------------------
# Transforms: pure, documented, never identity for spaced payloads.
# ---------------------------------------------------------------------------


class TestTransforms:
    def test_registry_matches_documented_order(self):
        assert list(transform_registry) == list(TRANSFORM_ORDER)
        assert len(TRANSFORM_ORDER) == 6

    def test_transforms_are_pure(self):
        for transform in transform_registry.values():
            assert transform("union select") == transform("union select")

    def test_toggle_case_changes_letter_case(self):
        assert transform_registry["toggle_case"]("SeLeCt") == "sElEcT"

    def test_double_url_encode_encodes_twice(self):
        once = "%28"
        twice = transform_registry["double_url_encode"]("(")
        assert twice != once
        assert "%2528" == twice  # % escaped again

    def test_sql_inline_comment_splits_keywords(self):
        assert transform_registry["sql_inline_comment"]("union select") == (
            "union/**/select"
        )

    def test_json_unicode_escape_preserves_ascii_and_escapes_unicode(self):
        f = transform_registry["json_unicode_escape"]
        assert f("a b") == "a b"
        assert "\\u00e9" in f("café")

    def test_space_substitutions(self):
        assert transform_registry["space_to_percent20"]("a b") == "a%20b"
        assert transform_registry["space_to_plus"]("a b") == "a+b"


# ---------------------------------------------------------------------------
# Block classification and backoff.
# ---------------------------------------------------------------------------


class TestClassify:
    def test_documented_statuses_are_blocks(self):
        for status in (403, 406, 429, 501):
            assert classify_waf_block(status, "") is not None

    def test_success_is_not_a_block(self):
        assert classify_waf_block(200, "<html>results</html>") is None
        assert classify_waf_block(500, "internal error") is None

    def test_body_markers_are_blocks(self):
        assert classify_waf_block(200, "Request blocked by Cloudflare") is not None
        assert classify_waf_block(200, "Too many requests, slow down") is not None

    def test_marker_names_are_documented_set(self):
        from webpent.waf_evasion.adaptive import WAF_BLOCK_MARKERS, WAF_BLOCK_STATUSES

        assert WAF_BLOCK_STATUSES == frozenset({403, 406, 429, 501})
        assert len(WAF_BLOCK_MARKERS) >= 5


class TestBackoff:
    def test_exponential_with_ceiling(self):
        policy = BackoffPolicy()
        assert [policy.delay_for_attempt(n) for n in (1, 2, 3, 4, 5, 6)] == [
            0.5,
            1.0,
            2.0,
            4.0,
            8.0,
            8.0,
        ]

    def test_invalid_policy_refused(self):
        with pytest.raises(AdaptiveEvasionError, match="waf_adaptive_invalid_backoff"):
            BackoffPolicy(base=0)
        with pytest.raises(AdaptiveEvasionError, match="waf_adaptive_invalid_backoff"):
            BackoffPolicy(base=4, ceiling=1)


# ---------------------------------------------------------------------------
# Gate, kill switch, mandatory safety path.
# ---------------------------------------------------------------------------


class TestGate:
    def test_flag_off_refuses(self):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_waf_adaptive=False)):
            assert waf_adaptive_refusal() == "waf_adaptive_flag_off"

    def test_flag_off_zero_touches(self):
        from webpent.config.settings import Settings, activate_settings

        sender = ScriptedSender([])
        ledger = FakeLedger()
        with activate_settings(Settings(enable_waf_adaptive=False)):
            with pytest.raises(AdaptiveEvasionError, match="waf_adaptive_flag_off"):
                AdaptiveClient(
                    request_fn=sender,
                    ledger=ledger,
                    scope=FakeScope(),
                    sleep_fn=_no_sleep,
                ).send_with_adaptation("' OR 1=1", _context())
        assert sender.payloads == []
        assert ledger.recorded == []

    def test_kill_switch_engaged_blocks_everything(self):
        from webpent.safety import kill_switch

        sender = ScriptedSender([])
        ledger = FakeLedger()
        kill_switch.engage("test")
        try:
            with _activated():
                result = AdaptiveClient(
                    request_fn=sender,
                    ledger=ledger,
                    scope=FakeScope(),
                    sleep_fn=_no_sleep,
                ).send_with_adaptation("' OR 1=1", _context())
        finally:
            kill_switch.release()
        assert result.inconclusive == "kill_switch_engaged"
        assert sender.payloads == []
        assert ledger.recorded == []

    def test_missing_ledger_or_scope_fail_closed(self):
        with _activated():
            client = AdaptiveClient(
                request_fn=ScriptedSender([]),
                ledger=None,
                scope=FakeScope(),
                sleep_fn=_no_sleep,
            )
            with pytest.raises(AdaptiveEvasionError, match="waf_adaptive_ledger_required"):
                client.send_with_adaptation("x", _context())
            client = AdaptiveClient(
                request_fn=ScriptedSender([]),
                ledger=FakeLedger(),
                scope=None,
                sleep_fn=_no_sleep,
            )
            with pytest.raises(AdaptiveEvasionError, match="waf_adaptive_scope_required"):
                client.send_with_adaptation("x", _context())


class TestSafetyPath:
    def test_out_of_scope_refused_before_send(self):
        with _activated():
            sender = ScriptedSender([])
            ledger = FakeLedger()
            result = AdaptiveClient(
                request_fn=sender,
                ledger=ledger,
                scope=FakeScope(allowed=("other.example.com",)),
                sleep_fn=_no_sleep,
            ).send_with_adaptation("' OR 1=1", _context())
            assert result.inconclusive == "out_of_scope"
            assert sender.payloads == []
            assert ledger.recorded == []

    def test_ledger_refusal_means_not_sent(self):
        with _activated():
            sender = ScriptedSender([(200, "ok")])
            result = AdaptiveClient(
                request_fn=sender,
                ledger=FakeLedger(ok=False),
                scope=FakeScope(),
                sleep_fn=_no_sleep,
            ).send_with_adaptation("' OR 1=1", _context())
            assert result.inconclusive == "ledger_refused"
            assert sender.payloads == []

    def test_every_sent_attempt_is_ledgered(self):
        with _activated():
            ledger = FakeLedger()
            sender = ScriptedSender(
                [(403, "blocked")] * 2 + [(200, "ok")]
            )
            AdaptiveClient(
                request_fn=sender,
                ledger=ledger,
                scope=FakeScope(),
                sleep_fn=_no_sleep,
            ).send_with_adaptation("' OR 1=1", _context())
            assert len(ledger.recorded) == 3
            assert all(flags == "waf_adaptive" for flags in ledger.recorded)


# ---------------------------------------------------------------------------
# Adaptive behavior and session memory.
# ---------------------------------------------------------------------------


class TestAdaptation:
    def test_original_success_needs_no_transform(self):
        with _activated():
            sender = ScriptedSender([(200, "ok")])
            result = AdaptiveClient(
                request_fn=sender,
                ledger=FakeLedger(),
                scope=FakeScope(),
                sleep_fn=_no_sleep,
            ).send_with_adaptation("payload", _context())
            assert result.success
            assert result.transform_used is None
            assert result.attempts == 1
            assert sender.payloads == ["payload"]

    def test_blocked_original_adapts_then_succeeds(self):
        with _activated():
            sender = ScriptedSender([(403, "blocked"), (200, "ok")])
            result = AdaptiveClient(
                request_fn=sender,
                ledger=FakeLedger(),
                scope=FakeScope(),
                sleep_fn=_no_sleep,
            ).send_with_adaptation("union select", _context())
            assert result.success
            assert result.transform_used == TRANSFORM_ORDER[0]  # first in order
            assert result.attempts == 2
            assert len(sender.payloads) == 2
            assert sender.payloads[1] != sender.payloads[0]  # re-encoded only

    def test_session_memory_tries_successful_transform_first(self):
        with _activated():
            target = TRANSFORM_ORDER[3]  # json_unicode_escape
            sender = ScriptedSender(
                # first call: raw blocked, transforms 0..2 blocked,
                # transform 3 succeeds; second call: raw blocked, then
                # the remembered winner succeeds
                [(403, "blocked")] * 4
                + [(200, "ok")]
                + [(403, "blocked"), (200, "ok")]
            )
            client = AdaptiveClient(
                request_fn=sender,
                ledger=FakeLedger(),
                scope=FakeScope(),
                sleep_fn=_no_sleep,
            )
            first = client.send_with_adaptation(
                "union select", _context(), max_attempts=5
            )
            assert first.transform_used == target
            assert client.preferred == [target]
            # second call: memory order puts the winner first, so the
            # payload that arrives second IS the transformed one
            second = client.send_with_adaptation(
                "union select", _context(), max_attempts=5
            )
            assert second.transform_used == target
            assert second.attempts == 2  # raw blocked, then remembered winner
            assert sender.payloads[5] == transform_registry[target]("union select")

    def test_attempt_bound_no_retry_storm(self):
        with _activated():
            sender = ScriptedSender([(403, "blocked")] * 50)
            result = AdaptiveClient(
                request_fn=sender,
                ledger=FakeLedger(),
                scope=FakeScope(),
                sleep_fn=_no_sleep,
            ).send_with_adaptation("x", _context(), max_attempts=3)
            assert result.inconclusive == "waf_blocked"
            assert len(sender.payloads) == 3

    def test_hard_cap_five_independent_of_settings(self):
        # settings-level validation rejects >5; the module cap is the
        # second layer, reachable via the method's explicit override
        from webpent.config.settings import Settings

        with pytest.raises(Exception, match="waf_adaptive_max_attempts"):
            Settings(enable_waf_adaptive=True, waf_adaptive_max_attempts=9)
        with _activated():
            sender = ScriptedSender([(403, "blocked")] * 50)
            result = AdaptiveClient(
                request_fn=sender,
                ledger=FakeLedger(),
                scope=FakeScope(),
                sleep_fn=_no_sleep,
            ).send_with_adaptation("x", _context(), max_attempts=9)
            assert result.inconclusive == "waf_blocked"
            assert len(sender.payloads) == MAX_ATTEMPTS_CAP

    def test_rate_limit_triggers_backoff_sleep(self):
        with _activated():
            sleeps: list[float] = []

            def record_sleep(delay: float) -> None:
                sleeps.append(delay)

            sender = ScriptedSender([(429, "rate limit"), (200, "ok")])
            AdaptiveClient(
                request_fn=sender,
                ledger=FakeLedger(),
                scope=FakeScope(),
                sleep_fn=record_sleep,
            ).send_with_adaptation("x", _context())
            assert sleeps == [BackoffPolicy().delay_for_attempt(1)]

    def test_request_error_is_inconclusive_not_fatal(self):
        with _activated():
            def bad_sender(payload):
                raise RuntimeError("conn refused")

            result = AdaptiveClient(
                request_fn=bad_sender,
                ledger=FakeLedger(),
                scope=FakeScope(),
                sleep_fn=_no_sleep,
            ).send_with_adaptation("x", _context())
            assert result.inconclusive == "request_error: RuntimeError"


# ---------------------------------------------------------------------------
# Real RequestLedger contract compatibility.
# ---------------------------------------------------------------------------


class TestRealLedger:
    def test_records_through_real_ledger(self, tmp_path):
        from webpent.safety.request_ledger import RequestLedger

        with _activated():
            ledger = RequestLedger(db_path=str(tmp_path / "requests.db"))
            sender = ScriptedSender([(200, "ok")])
            result = AdaptiveClient(
                request_fn=sender,
                ledger=ledger,
                scope=FakeScope(),
                sleep_fn=_no_sleep,
            ).send_with_adaptation("payload", _context())
            assert result.success
            rows = ledger.entries(limit=100)
            assert rows and all("waf_adaptive" in (r.get("flags") or "") for r in rows)
