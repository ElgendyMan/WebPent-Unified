"""Tests for webpent.api.workers_status (Ultimate plan, proposal 9).

All tests run without a Celery broker: worker data comes from injected
fake inspectors, and the no-broker path is exercised explicitly.
"""

from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from webpent.api.workers_status import (
    detect_stalled_workers,
    get_inspector,
    reset_inspector,
    router,
    set_inspector,
)


@pytest.fixture()
def client():
    """TestClient over a fresh app containing only the workers router.

    UM-DR-25: the operator visibility flag is enabled for these route
    tests (default-off would 404 every request — the gate itself is
    covered by tests/test_worker_status.py)."""
    from webpent.config.settings import Settings, activate_settings

    reset_inspector()
    app = FastAPI()
    app.include_router(router)
    with activate_settings(Settings(enable_worker_status_endpoint=True)):
        with TestClient(app) as test_client:
            yield test_client
    reset_inspector()


def _wrapped_inspector(stats: dict, registered: dict | None = None):
    """Build an inspector returning the wrapped celery-shaped dict."""
    payload = {"stats": stats, "registered": registered or {}}

    def inspector() -> dict:
        return payload

    return inspector


# ---------------------------------------------------------------------------
# detect_stalled_workers (pure helper)
# ---------------------------------------------------------------------------


def test_detect_stalled_flags_status_stalled() -> None:
    workers = [
        {"name": "celery@a", "status": "stalled", "active_engagements": 0},
        {"name": "celery@b", "status": "running", "active_engagements": 3},
    ]
    assert detect_stalled_workers(workers) == ["celery@a"]


def test_detect_stalled_running_with_active_work_is_not_flagged() -> None:
    workers = [
        {
            "name": "celery@a",
            "status": "running",
            "active_engagements": 2,
            "started_seconds_ago": 99999,
        }
    ]
    assert detect_stalled_workers(workers) == []


def test_detect_stalled_idle_beyond_threshold_is_flagged() -> None:
    workers = [
        {
            "name": "celery@idle",
            "status": "running",
            "active_engagements": 0,
            "started_seconds_ago": 901,
        },
        {
            "name": "celery@fresh",
            "status": "running",
            "active_engagements": 0,
            "started_seconds_ago": 10,
        },
    ]
    assert detect_stalled_workers(workers) == ["celery@idle"]
    # A larger threshold moves the same worker out of stall territory.
    assert detect_stalled_workers(workers, stalled_after_s=5000) == []


def test_detect_stalled_explicit_stalled_for_s_field() -> None:
    workers = [
        {"name": "celery@a", "status": "running", "stalled_for_s": 1000},
        {"name": "celery@b", "status": "running", "stalled_for_s": 100},
    ]
    assert detect_stalled_workers(workers, stalled_after_s=900) == ["celery@a"]


def test_detect_stalled_failed_empty_and_malformed_inputs() -> None:
    assert detect_stalled_workers([]) == []
    assert detect_stalled_workers(
        [{"name": "celery@x", "status": "failed", "active_engagements": 0}]
    ) == []
    # Malformed entries are skipped, never raised on; duplicates dedup.
    assert detect_stalled_workers(
        [
            "not-a-dict",
            {"status": "stalled"},  # missing name
            {"name": "celery@a", "status": "stalled"},
            {"name": "celery@a", "status": "stalled"},
        ]
    ) == ["celery@a"]


# ---------------------------------------------------------------------------
# GET /api/v1/workers/status — injected inspector mapping
# ---------------------------------------------------------------------------


def test_status_running_mapping_with_active_tasks(client: TestClient) -> None:
    started = time.time() - 3600
    set_inspector(
        _wrapped_inspector(
            stats={
                "celery@w1": {"active": [{"id": "task-1"}], "started_at": started},
            },
            registered={"celery@w1": ["webpent.run_pentest"]},
        )
    )
    response = client.get("/api/v1/workers/status")
    assert response.status_code == 200
    body = response.json()
    assert body["available"] is True
    assert body["degraded_reason"] is None
    assert len(body["workers"]) == 1
    worker = body["workers"][0]
    assert worker["name"] == "celery@w1"
    assert worker["status"] == "running"
    assert worker["active_engagements"] == 1
    assert worker["started_seconds_ago"] is not None
    assert 3500 <= worker["started_seconds_ago"] <= 3700
    assert body["checked_at"]


def test_status_stalled_mapping_zero_active_no_heartbeat(client: TestClient) -> None:
    set_inspector(
        _wrapped_inspector(stats={"celery@w2": {"pool": {"max-concurrency": 4}}})
    )
    body = client.get("/api/v1/workers/status").json()
    assert body["available"] is True
    worker = body["workers"][0]
    assert worker["status"] == "stalled"
    assert worker["active_engagements"] == 0
    assert worker["started_seconds_ago"] is None


def test_status_failed_mapping_missing_from_stats(client: TestClient) -> None:
    set_inspector(
        _wrapped_inspector(
            stats={"celery@alive": {"clock": 42}},
            registered={"celery@alive": ["t"], "celery@dead": ["t"]},
        )
    )
    body = client.get("/api/v1/workers/status").json()
    by_name = {w["name"]: w for w in body["workers"]}
    assert by_name["celery@alive"]["status"] == "running"  # heartbeat key present
    assert by_name["celery@alive"]["active_engagements"] == 0
    assert by_name["celery@dead"]["status"] == "failed"


def test_status_accepts_bare_stats_shaped_inspector_result(client: TestClient) -> None:
    set_inspector(lambda: {"celery@w9": {"active_engagements": 2}})
    body = client.get("/api/v1/workers/status").json()
    assert body["available"] is True
    assert body["workers"] == [
        {
            "name": "celery@w9",
            "status": "running",
            "active_engagements": 2,
            "started_seconds_ago": None,
        }
    ]


def test_status_heartbeat_counts_as_running_even_with_zero_active(
    client: TestClient,
) -> None:
    set_inspector(_wrapped_inspector(stats={"celery@w3": {"heartbeat": 1729999999.0}}))
    body = client.get("/api/v1/workers/status").json()
    assert body["workers"][0]["status"] == "running"


def test_status_inspector_raising_returns_200_with_honest_reason(
    client: TestClient,
) -> None:
    def boom() -> dict:
        raise RuntimeError("broker socket exploded")

    set_inspector(boom)
    response = client.get("/api/v1/workers/status")
    assert response.status_code == 200  # monitoring never crashes
    body = response.json()
    assert body["available"] is False
    assert body["workers"] == []
    assert "RuntimeError" in body["degraded_reason"]
    assert body["reason"] == body["degraded_reason"]


# ---------------------------------------------------------------------------
# GET /api/v1/workers/status — default (no inspector) path
# ---------------------------------------------------------------------------


def test_status_without_inspector_and_without_broker_is_honest_unavailable(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("WEBPENT_REDIS_URL", raising=False)
    assert get_inspector() is None
    response = client.get("/api/v1/workers/status")
    assert response.status_code == 200
    body = response.json()
    assert body["available"] is False
    assert body["workers"] == []
    assert body["reason"] == "celery/broker not reachable"
    assert body["checked_at"]


def test_health_endpoint_is_ok(client: TestClient) -> None:
    response = client.get("/api/v1/workers/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_set_inspector_round_trip() -> None:
    reset_inspector()
    assert get_inspector() is None
    inspector = _wrapped_inspector(stats={})
    set_inspector(inspector)
    assert get_inspector() is inspector
    reset_inspector()
    assert get_inspector() is None
