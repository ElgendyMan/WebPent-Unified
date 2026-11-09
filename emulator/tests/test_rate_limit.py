"""U-EMU-3 — Rate limiter tests (4 tests)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from conftest import emulator_stack_up, http_status

EMU_DIR = Path(__file__).resolve().parents[1]
LIMITS = (EMU_DIR / "configs" / "rate_limits.conf").read_text()


def test_rate_limit_triggered() -> None:
    assert "limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;" \
        in LIMITS
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    statuses = [http_status("http://localhost:8000/?b=1") for _ in range(25)]
    throttled = statuses.count(429)
    assert throttled > 0, f"no throttling after 25 rapid requests: {statuses}"


def test_429_returned() -> None:
    assert "limit_req_status 429" in LIMITS
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    for _ in range(20):
        if http_status("http://localhost:8000/?c=1") == 429:
            return
    pytest.fail("never observed a 429")


def test_burst_allowed() -> None:
    assert "burst=10" in LIMITS
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    # Earlier tests may have just tripped the limiter for this client IP;
    # the zone decays at 5 r/s, so give it a few seconds to drain first.
    time.sleep(3)
    statuses = [http_status("http://localhost:8000/?d=1") for _ in range(5)]
    assert all(status == 200 for status in statuses), \
        f"small burst should pass: {statuses}"


def test_recovery_after_wait() -> None:
    assert "rate=5r/s" in LIMITS
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    for _ in range(20):
        http_status("http://localhost:8000/?e=1")
    time.sleep(3)  # 5 r/s drains a 10-burst in about 2 seconds
    assert http_status("http://localhost:8000/?e=after-wait") == 200
