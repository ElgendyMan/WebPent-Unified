"""Hunting Intelligence Sprint — session recovery tests.

Synthetic only: stub exploiter, stub login/provision/M4. No network.
Covers: 3x401 -> recover -> resume; 3 failed recoveries -> halt;
401/302 detection; audit events; zero-FP (healthy responses never trigger).
"""
from __future__ import annotations

import pytest

from webpent.recon.session_recovery import (
    CampaignHalted,
    RecoveryOutcome,
    SessionRecoveryManager,
    SessionRecoveryMonitor,
    is_login_redirect,
    response_looks_dead,
)
from webpent.integration.session_recovery_bridge import RecoveringExploiter, ExploitResultView


# -- stubs -------------------------------------------------------------------
class _StubLogin:
    def __init__(self, succeed_from_attempt=1):
        self.calls = 0
        self.succeed_from = succeed_from_attempt

    def __call__(self, principal_alias=""):
        self.calls += 1
        success = self.calls >= self.succeed_from
        return type("LR", (), {"success": success, "reason": "ok" if success else "bad_credentials"})()


class _StubProvision:
    def __init__(self, succeed=True):
        self.succeed = succeed
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return type("PR", (), {"successful_count": 2 if self.succeed else 0})()


class _StubM4:
    def __call__(self, provisioned):
        return "bound_principal_ref"


def _make_manager(succeed_from=1, provision_succeed=True, max_attempts=3):
    return SessionRecoveryManager(
        campaign_id="camp_1",
        login=_StubLogin(succeed_from_attempt=succeed_from),
        provision=_StubProvision(succeed=provision_succeed),
        m4_bind=_StubM4(),
        max_recovery_attempts=max_attempts,
        clock=lambda: 1000.0,
    )


# -- detection ---------------------------------------------------------------
def test_is_login_redirect_detects_302_to_login():
    assert is_login_redirect(302, {"Location": "/login?next=/"}) is True
    assert is_login_redirect(302, {"Location": "/dashboard"}) is False
    assert is_login_redirect(200, {"Location": "/login"}) is False


def test_response_looks_dead_401_and_403():
    assert response_looks_dead(401) is True
    assert response_looks_dead(403) is True
    assert response_looks_dead(200) is False
    assert response_looks_dead(404) is False  # zero-FP: not a session-death signal


# -- monitor -----------------------------------------------------------------
def test_monitor_declares_dead_after_three_consecutive():
    mon = SessionRecoveryMonitor(dead_threshold=3)
    assert mon.record(401) is False  # 1
    assert mon.record(401) is False  # 2
    assert mon.record(401) is True   # 3 -> dead
    assert mon.dead is True


def test_monitor_resets_on_healthy_response():
    mon = SessionRecoveryMonitor(dead_threshold=3)
    mon.record(401)
    mon.record(401)
    assert mon.record(200) is False  # healthy resets the streak
    assert mon.consecutive_dead == 0


# -- recovery manager --------------------------------------------------------
def test_recover_succeeds_and_emits_recovered_event():
    mgr = _make_manager(succeed_from=2)  # first login fails, second succeeds
    mgr.mark_expired(principal_alias="owner", reason="test")
    outcome = mgr.recover(principal_alias="owner")
    assert isinstance(outcome, RecoveryOutcome)
    assert outcome.recovered is True
    assert outcome.attempts == 2
    types = [e.event_type for e in outcome.audit_events]
    assert "session.expired" in types
    assert "session.recovered" in types


def test_three_failed_recoveries_halt_campaign():
    mgr = _make_manager(succeed_from=99, max_attempts=3)  # never succeeds
    mgr.mark_expired()
    with pytest.raises(CampaignHalted) as exc:
        mgr.recover()
    assert "recovery_exhausted" in str(exc.value)
    assert mgr.halted is True
    types = [e.event_type for e in mgr.audit_events]
    assert "session.exhausted" in types
    assert "campaign.halted" in types
    assert mgr.recovery_attempts == 3  # bounded, no infinite loop


def test_halted_manager_raises_immediately_no_loop():
    mgr = _make_manager(succeed_from=99, max_attempts=2)
    with pytest.raises(CampaignHalted):
        mgr.recover()
    with pytest.raises(CampaignHalted):
        mgr.recover()  # already halted -> immediate, no further attempts
    assert mgr.recovery_attempts == 2


def test_resume_point_recorded():
    mgr = _make_manager(succeed_from=1)
    mgr.set_resume_point("hyp_42")
    assert mgr.resume_hypothesis_id == "hyp_42"


# -- recovering exploiter bridge ---------------------------------------------
class _StubHyp:
    def __init__(self, hid):
        self.hypothesis_id = hid


def _result(status=200, failure=""):
    return type("R", (), {"status_code": status, "headers": {}, "failure": failure, "to_dict": lambda self: {"s": status}})()


def test_exploiter_recovers_and_resumes_same_hypothesis():
    call_log = []

    def inner(hyp, hunter):
        call_log.append(hyp.hypothesis_id)
        if len(call_log) <= 3:
            return _result(401)  # first three inner calls dead (3rd triggers recovery)
        return _result(200)

    mgr = _make_manager(succeed_from=1)
    sleeper = []
    exploiter = RecoveringExploiter(
        inner, recovery_manager=mgr,
        sleep=lambda s: sleeper.append(s),
        clock=lambda: 1.0,
    )
    # Campaign loop: three hypotheses in a row die with 401 -> session dead.
    # The 3rd exploiter call triggers recovery and retries the same hypothesis.
    results = [exploiter(_StubHyp("hyp_7"), {}) for _ in range(3)]
    assert results[0].status_code == 401  # 1st dead, recorded
    assert results[1].status_code == 401  # 2nd dead, recorded
    assert results[2].status_code == 200  # 3rd: recovered + resumed, campaign continues
    # The same hypothesis was retried after recovery (resume from last hypothesis)
    assert call_log.count("hyp_7") == 4  # 3 dead + 1 retry with fresh session
    assert any(e.event_type == "session.recovered" for e in mgr.audit_events)


def test_exploiter_halt_on_connection_refused():
    def inner(hyp, hunter):
        return _result(failure="connection_refused")

    mgr = _make_manager()
    exploiter = RecoveringExploiter(inner, recovery_manager=mgr, sleep=lambda s: None)
    with pytest.raises(CampaignHalted) as exc:
        exploiter(_StubHyp("h1"), {})
    assert "connection_refused" in str(exc.value)  # halt, no retry loop


def test_exploiter_timeout_single_retry_with_backoff():
    call_log = []

    def inner(hyp, hunter):
        call_log.append(1)
        if len(call_log) == 1:
            return _result(failure="timeout")
        return _result(200)

    mgr = _make_manager()
    sleeps = []
    exploiter = RecoveringExploiter(
        inner, recovery_manager=mgr,
        sleep=lambda s: sleeps.append(s),
        backoff_base=1.0,
        max_timeout_retries=1,
    )
    result = exploiter(_StubHyp("h1"), {})
    assert result.status_code == 200
    assert len(call_log) == 2  # exactly one retry
    assert sleeps and sleeps[0] == pytest.approx(1.0)  # backoff applied


def test_exploiter_rate_limit_pause_and_resume():
    call_log = []

    def inner(hyp, hunter):
        call_log.append(1)
        if len(call_log) == 1:
            return _result(429)
        return _result(200)

    mgr = _make_manager()
    sleeps = []
    exploiter = RecoveringExploiter(inner, recovery_manager=mgr, sleep=lambda s: sleeps.append(s), rate_limit_cooldown=5.0)
    result = exploiter(_StubHyp("h1"), {})
    assert result.status_code == 200
    assert 5.0 in sleeps  # paused for cooldown then resumed


def test_exploiter_scope_violation_halt():
    def inner(hyp, hunter):
        return _result(failure="scope_violation")

    mgr = _make_manager()
    exploiter = RecoveringExploiter(inner, recovery_manager=mgr, sleep=lambda s: None)
    with pytest.raises(CampaignHalted) as exc:
        exploiter(_StubHyp("h1"), {})
    assert "scope_violation" in str(exc.value)


def test_zero_fp_healthy_responses_never_trigger_recovery():
    mgr = _make_manager()
    exploiter = RecoveringExploiter(lambda h, d: _result(200), recovery_manager=mgr, sleep=lambda s: None)
    for _ in range(10):
        exploiter(_StubHyp("hx"), {})
    assert mgr.recovery_attempts == 0
    assert not any(e.event_type == "session.expired" for e in mgr.audit_events)
