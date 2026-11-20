"""U-DEEP-2 — Rate Limit Bypass Engine (red tests).

Detection principle: EFFECT OVER STATE — a bypass is only a finding
when the limit actually failed (N requests got through where the
sequential baseline stopped at the limit), never because a header
was merely rotated or a session merely renewed. Zero network:
send(endpoint, body) is injected.
"""
from __future__ import annotations

import pytest

from webpent.deep.rate_limit_bypass import (
    RATE_LIMIT_BYPASSES,
    SEVERITY_BY_SUBFAMILY,
    RateLimitBypassEngine,
)


class _State:
    """Vulnerable limiter: counts by the client-supplied IP header,
    so rotation resets the window. quota=10."""

    def __init__(self, quota=10):
        self.quota = quota
        self._counts: dict[str, int] = {}

    def send(self, endpoint, body, headers=None):
        class R:
            status_code = 200

            def __init__(self, payload):
                self._payload = payload

            def json(self):
                return self._payload

        ip = "1.2.3.4"
        for name, value in (headers or []):
            if name.lower() in ("x-forwarded-for", "x-real-ip",
                                "x-originating-ip", "x-client-ip",
                                "x-remote-addr", "cf-connecting-ip",
                                "true-client-ip"):
                ip = value
                break
        count = self._counts.get(ip, 0)
        if count >= self.quota:
            return R({"ok": False, "limited": True})
        self._counts[ip] = count + 1
        return R({"ok": True})


class _Hardened(_State):
    def send(self, endpoint, body, headers=None):
        # trusts only the socket address; headers never change the key
        return super().send(endpoint, body, headers=None)


@pytest.fixture
def engine():
    return RateLimitBypassEngine(_State().send)


def test_technique_corpus_documented():
    assert set(RATE_LIMIT_BYPASSES) == {
        "header_rotation", "session_rotation", "http2_batching",
        "concurrency"}
    headers = [h.split(":")[0] for h
               in RATE_LIMIT_BYPASSES["header_rotation"]]
    assert headers == [
        "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
        "X-Client-IP", "X-Remote-Addr", "CF-Connecting-IP",
        "True-Client-IP"]
    for subfamily in SEVERITY_BY_SUBFAMILY:
        assert SEVERITY_BY_SUBFAMILY[subfamily]


def test_sequential_baseline_hits_limit(engine):
    result = engine.baseline("POST /api/login", {})
    assert result.stopped_at == engine.quota
    assert result.sent == engine.quota + 5


def test_header_rotation_bypasses(engine):
    result = engine.execute("POST /api/login", {},
                            technique="header_rotation")
    assert result.sent == 100
    assert result.passed == 100
    assert engine.analyze(result) is not None


def test_header_rotation_no_effect_on_hardened():
    engine = RateLimitBypassEngine(_Hardened().send)
    result = engine.execute("POST /api/login", {},
                            technique="header_rotation")
    assert result.passed == engine.quota
    assert engine.analyze(result) is None


def test_subfamily_login_bypass(engine):
    finding = engine.analyze(engine.execute(
        "POST /api/login", {}, technique="header_rotation"))
    assert finding.subfamily == "login_rate_limit_bypass"
    assert finding.severity == "high"


def test_concurrency_and_batching_modes(engine):
    batch = engine.execute("POST /api/login", {},
                           technique="http2_batching")
    parallel = engine.execute("POST /api/login", {},
                              technique="concurrency")
    assert batch.passed == 100
    assert parallel.passed == 100
    assert batch.requests_per_stream > 1
    assert parallel.instant_parallelism > 1


def test_no_false_positive_limited(engine):
    # quota=2: the rotation key changes, but the window still closes
    engine = RateLimitBypassEngine(_State(quota=2).send)
    result = engine.execute("POST /api/login", {},
                            technique="header_rotation")
    assert engine.analyze(result) is None


def test_advisory_and_deterministic(engine):
    first = engine.analyze(engine.execute(
        "POST /api/login", {}, technique="header_rotation"))
    assert "advisory" in first.statement.lower()
    assert first.family == "RATE_LIMIT_BYPASS"
    a = engine.build_plan("POST /api/login", {},
                          technique="header_rotation")
    b = engine.build_plan("POST /api/login", {},
                          technique="header_rotation")
    assert [(p.endpoint, p.headers) for p in a] == \
        [(p.endpoint, p.headers) for p in b]
