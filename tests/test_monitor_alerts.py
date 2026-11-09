"""Tests for webpent.workers.monitor_alerts (Ultimate plan, proposal 9 Phase 3).

Pure/offline: alerts operate on an already-fetched status dict.
"""

from __future__ import annotations

import logging

from webpent.workers.monitor_alerts import check_stalled_and_alert


def _status(workers: list[dict], *, available: bool = True) -> dict:
    return {
        "available": available,
        "workers": workers,
        "checked_at": "2026-10-27T12:00:00+00:00",
        "degraded_reason": None,
        "reason": None,
    }


def test_stalled_worker_produces_a_warning_log_line(caplog) -> None:
    status = _status(
        [
            {"name": "celery@stuck", "status": "stalled", "active_engagements": 0},
            {"name": "celery@fine", "status": "running", "active_engagements": 2},
        ]
    )
    with caplog.at_level(logging.WARNING, logger="webpent.workers.monitor_alerts"):
        alerts = check_stalled_and_alert(status)
    assert alerts == [
        "worker 'celery@stuck' stalled (no active engagements and no "
        "heartbeat for over 900s) — check the engagement it was running"
    ]
    assert "celery@stuck" in caplog.text
    assert "stalled" in caplog.text
    # The healthy worker never appears in the log.
    assert "celery@fine" not in caplog.text


def test_no_stalled_workers_means_no_alerts(caplog) -> None:
    status = _status(
        [
            {"name": "celery@a", "status": "running", "active_engagements": 1},
            {"name": "celery@b", "status": "running", "active_engagements": 0,
             "started_seconds_ago": 60},
        ]
    )
    with caplog.at_level(logging.WARNING, logger="webpent.workers.monitor_alerts"):
        alerts = check_stalled_and_alert(status)
    assert alerts == []
    assert "stalled" not in caplog.text.lower()


def test_degraded_monitoring_status_is_no_crash_no_alerts() -> None:
    status = _status([], available=False)
    status["degraded_reason"] = "celery/broker not reachable"
    assert check_stalled_and_alert(status) == []
    # Missing/None workers key and non-dict payloads degrade the same way.
    assert check_stalled_and_alert({}) == []
    assert check_stalled_and_alert({"available": True, "workers": None}) == []
    assert check_stalled_and_alert("not-a-dict") == []


def test_custom_log_fn_receives_each_alert_line() -> None:
    lines: list[str] = []
    status = _status(
        [
            {"name": "celery@s1", "status": "stalled"},
            {"name": "celery@s2", "status": "stalled"},
        ]
    )
    alerts = check_stalled_and_alert(status, log_fn=lines.append)
    assert alerts == lines
    assert len(lines) == 2
    assert lines[0].startswith("worker 'celery@s1' stalled")


def test_stalled_after_s_threshold_is_forwarded() -> None:
    status = _status(
        [
            {
                "name": "celery@idle",
                "status": "running",
                "active_engagements": 0,
                "started_seconds_ago": 1000,
            }
        ]
    )
    # 1000s uptime with zero engagements: stalled at 900s, fine at 5000s.
    assert check_stalled_and_alert(status, stalled_after_s=900) != []
    assert check_stalled_and_alert(status, stalled_after_s=5000) == []


def test_malformed_worker_entries_are_skipped() -> None:
    status = _status(["not-a-dict", {"status": "stalled"}, {"name": "celery@z", "status": "stalled"}])
    alerts = check_stalled_and_alert(status)
    assert alerts == [
        "worker 'celery@z' stalled (no active engagements and no "
        "heartbeat for over 900s) — check the engagement it was running"
    ]
