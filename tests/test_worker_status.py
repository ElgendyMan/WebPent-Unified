# tests/test_worker_status.py
"""Worker status endpoint family — tests aligned to the IMPLEMENTED design.

UM-DR-25 (red-team window 2026-11-06) reconciliation: this file
originally targeted a 2026-10-25 proposal-6 shape (module-level
``app.workers_status`` + ``_collect_worker_status`` + a dashboard route
patching ``pentest_worker.celery_app.control``). That design was
superseded by the F-05 (0.33.0) implementation in
``webpent/api/workers_status.py``: viewer-auth routes, an injectable
inspector (``set_inspector``), a pure ``detect_stalled_workers`` alert
helper, and honest-unavailable payloads. The tests below preserve the
ORIGINAL protective intent against the implemented design:

  * flag-gating: ``enable_worker_status_endpoint`` (default False)
    hides the route family entirely (404) — wired by UM-DR-25;
  * worker mapping from injected inspector data (online/stalled
    classification, engagement counts, uptime);
  * stall detection with the documented conservative proxy;
  * honest-unavailable when no broker is configured;
  * the inspector injection surface is reset between tests.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

status_mod = importlib.import_module("webpent.api.workers_status")
settings_mod = importlib.import_module("webpent.config.settings")


@pytest.fixture(autouse=True)
def _clean_inspector():
    status_mod.reset_inspector()
    yield
    status_mod.reset_inspector()


def _enabled_settings():
    return settings_mod.Settings(enable_worker_status_endpoint=True)


def _disabled_settings():
    return settings_mod.Settings(enable_worker_status_endpoint=False)


class TestVisibilityGate:
    def test_flag_defaults_off(self) -> None:
        assert settings_mod.Settings().enable_worker_status_endpoint is False

    def test_status_route_404_when_disabled(self) -> None:
        with settings_mod.activate_settings(_disabled_settings()):
            with pytest.raises(status_mod.HTTPException) as excinfo:
                status_mod.workers_status(user=None)
        assert excinfo.value.status_code == 404

    def test_health_route_404_when_disabled(self) -> None:
        with settings_mod.activate_settings(_disabled_settings()):
            with pytest.raises(status_mod.HTTPException) as excinfo:
                status_mod.workers_health(user=None)
        assert excinfo.value.status_code == 404

    def test_status_route_callable_when_enabled(self) -> None:
        # No broker configured and no inspector injected -> honest
        # unavailable payload, NOT a 404 and NOT a crash.
        with settings_mod.activate_settings(_enabled_settings()):
            payload = status_mod.workers_status(user=None)
        assert payload["available"] is False
        assert payload["workers"] == []
        assert payload["degraded_reason"]


class TestWorkerMapping:
    def test_online_worker_mapped_with_engagements(self) -> None:
        status_mod.set_inspector(
            lambda: {
                "stats": {
                    "worker-1": {
                        "concurrency": 4,
                        "pid": 123,
                        "active": [
                            {"id": "task-1", "name": "run", "time_start": 0}
                        ],
                    }
                },
                "registered": {"worker-1": ["run"]},
            }
        )
        with settings_mod.activate_settings(_enabled_settings()):
            payload = status_mod.workers_status(user=None)
        assert payload["available"] is True
        worker = payload["workers"][0]
        assert worker["name"] == "worker-1"
        assert worker["active_engagements"] == 1
        assert worker["status"] in ("running", "stalled", "failed")

    def test_no_workers_is_honest_empty(self) -> None:
        status_mod.set_inspector(lambda: {"stats": {}, "registered": {}})
        with settings_mod.activate_settings(_enabled_settings()):
            payload = status_mod.workers_status(user=None)
        assert payload["available"] is True
        assert payload["workers"] == []


class TestStallDetection:
    def test_stalled_status_flagged_immediately(self) -> None:
        stalled = status_mod.detect_stalled_workers(
            [{"name": "w1", "status": "stalled", "active_engagements": 0}]
        )
        assert stalled == ["w1"]

    def test_running_with_activity_not_flagged(self) -> None:
        stalled = status_mod.detect_stalled_workers(
            [
                {
                    "name": "w1",
                    "status": "running",
                    "active_engagements": 2,
                    "started_seconds_ago": 999_999,
                }
            ]
        )
        assert stalled == []

    def test_long_uptime_idle_proxy_is_advisory_only(self) -> None:
        # running + zero engagements + uptime beyond the threshold is the
        # documented conservative proxy — flagged as advisory, and the
        # caller decides (alert, never enforcement).
        stalled = status_mod.detect_stalled_workers(
            [
                {
                    "name": "idle-w",
                    "status": "running",
                    "active_engagements": 0,
                    "started_seconds_ago": 5_000,
                }
            ],
            stalled_after_s=900,
        )
        assert stalled == ["idle-w"]

    def test_malformed_entries_skipped_never_raised(self) -> None:
        stalled = status_mod.detect_stalled_workers(
            [None, "junk", {"no_name": True}, {"name": ""}, {"name": "ok"}]
        )
        assert stalled == []


class TestInspectorSurface:
    def test_set_and_reset_inspector(self) -> None:
        status_mod.set_inspector(lambda: {"stats": {}})
        assert status_mod.get_inspector() is not None
        status_mod.reset_inspector()
        assert status_mod.get_inspector() is None

    def test_unavailable_payload_shape(self) -> None:
        payload = status_mod._unavailable_payload("no broker", "t0")
        assert payload == {
            "available": False,
            "workers": [],
            "checked_at": "t0",
            "degraded_reason": "no broker",
            "reason": "no broker",
        }
