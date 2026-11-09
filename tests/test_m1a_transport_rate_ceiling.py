"""M1-A (M-3) regression: the transport chokepoint enforces the global
rate ceiling when (and only when) rate_limit_enabled is on.

Contract (M1_READINESS_REVIEW §2.3):
  * rate_limit_enabled=True + low per-minute ceiling → rapid requests
    beyond the ceiling raise RateLimitExceeded (fail-closed);
  * a governor internal error NEVER blocks the request (fail-open) and
    logs CRITICAL;
  * rate_limit_enabled=False (the default) → no governor involvement at
    all (existing test/dev behavior unchanged).
"""
from __future__ import annotations

import logging
from types import SimpleNamespace

import httpx
import pytest

from webpent.shared.http import RateLimitExceeded, SSRFPinningTransport


class _RecordingTransport(httpx.BaseTransport):
    """Minimal stand-in transport that never touches the network."""

    def __init__(self) -> None:
        self.calls = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200, text="ok")


def _request() -> httpx.Request:
    # A PUBLIC IP literal: no DNS resolution, no private-range block,
    # and the recording transport never opens a socket.
    return httpx.Request("GET", "https://93.184.216.34/probe")


def _fake_settings(*, rate_limit_enabled: bool) -> SimpleNamespace:
    return SimpleNamespace(
        rate_limit_enabled=rate_limit_enabled,
        global_rate_governor_max_concurrent=8,
        global_rate_governor_requests_per_minute=2,
    )


@pytest.fixture()
def ceiling_on(monkeypatch):
    """rate_limit_enabled=True with a tiny 2/minute ceiling."""
    import webpent.config.settings as settings_module
    from webpent.shared.global_rate_governor import reset_global_rate_governor

    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: _fake_settings(rate_limit_enabled=True),
    )
    reset_global_rate_governor()
    yield
    reset_global_rate_governor()


def test_ceiling_blocks_beyond_budget(ceiling_on):
    inner = _RecordingTransport()
    transport = SSRFPinningTransport(wrapped=inner)
    granted, denied = 0, 0
    for _ in range(5):
        try:
            response = transport.handle_request(_request())
            assert response.status_code == 200
            granted += 1
        except RateLimitExceeded:
            denied += 1
    assert granted == 2, f"expected the 2/minute ceiling to grant exactly 2, got {granted}"
    assert denied >= 1, "expected at least one blocked request past the ceiling"
    assert inner.calls == 2


def test_governor_internal_error_fails_open(ceiling_on, monkeypatch, caplog):
    import webpent.shared.global_rate_governor as grg
    from webpent.shared.global_rate_governor import (
        GlobalRateGovernor,
        reset_global_rate_governor,
    )

    class _BrokenGovernor(GlobalRateGovernor):
        def try_acquire(self, campaign_id, *, tokens=1):
            raise RuntimeError("governor bug")

    monkeypatch.setattr(grg, "get_global_rate_governor", lambda: _BrokenGovernor())

    inner = _RecordingTransport()
    transport = SSRFPinningTransport(wrapped=inner)
    with caplog.at_level(logging.CRITICAL, logger="webpent.shared.http"):
        response = transport.handle_request(_request())
    assert response.status_code == 200
    assert inner.calls == 1
    assert any(
        "failing OPEN" in rec.getMessage() for rec in caplog.records
    ), "governor failure must be logged CRITICAL"
    reset_global_rate_governor()


def test_disabled_by_default_no_governor_involvement(monkeypatch):
    """rate_limit_enabled=False → the governor is never even consulted."""
    import webpent.config.settings as settings_module

    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: _fake_settings(rate_limit_enabled=False),
    )
    inner = _RecordingTransport()
    transport = SSRFPinningTransport(wrapped=inner)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "webpent.shared.global_rate_governor.get_global_rate_governor",
            lambda: pytest.fail("governor must not be consulted when disabled"),
        )
        response = transport.handle_request(_request())
    assert response.status_code == 200
    assert inner.calls == 1


def test_rate_limit_exceeded_is_request_error():
    """Callers' existing transport-error handling catches it for free."""
    assert issubclass(RateLimitExceeded, httpx.RequestError)
