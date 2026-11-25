"""UM-DR-47 Phase W7 — the live-campaign QC watchdog with safe-stop.

The 47 prompt W7: the watchdog monitors the LIVE campaign (repetition,
requests without new knowledge, evidence/inference mixing, scope
breach) with a REAL safe-stop — snapshot/resume record on fault.
"""
from __future__ import annotations

import json
import os

from webpent.production.brain_watchdog import BrainSafeStop, BrainWatchdog


def _update(url: str, method: str = "GET") -> dict:
    return {"findings": [{"url": url, "request_method": method}]}


class TestThresholds:
    def test_repetition_triggers_stop(self):
        wd = BrainWatchdog(scope_hosts=frozenset(), max_repeats=3)
        for _ in range(4):
            wd.observe_update("node", _update("http://t/api/x"))
        stop, reason = wd.should_stop()
        assert stop
        assert reason.startswith("repetition_without_new_information")

    def test_under_threshold_no_stop(self):
        wd = BrainWatchdog(scope_hosts=frozenset(), max_repeats=4)
        for _ in range(4):
            wd.observe_update("node", _update("http://t/api/x"))
        stop, _ = wd.should_stop()
        assert not stop

    def test_distinct_urls_do_not_count_as_repetition(self):
        wd = BrainWatchdog(scope_hosts=frozenset(), max_repeats=3)
        for i in range(8):
            wd.observe_update("node", _update(f"http://t/api/x/{i}"))
        stop, _ = wd.should_stop()
        assert not stop

    def test_scope_violation_triggers_stop_immediately(self):
        wd = BrainWatchdog(scope_hosts=frozenset({"lab.example"}))
        wd.observe_update("node", _update("http://evil.example/api/x"))
        stop, reason = wd.should_stop()
        assert stop
        assert reason.startswith("scope_violation:evil.example")

    def test_request_budget_triggers_stop(self):
        wd = BrainWatchdog(scope_hosts=frozenset(), request_budget=5)
        for i in range(7):
            wd.observe_update("node", _update(f"http://t/api/x/{i}"))
        stop, reason = wd.should_stop()
        assert stop
        assert reason.startswith("request_budget_exceeded")

    def test_in_scope_hosts_never_stop(self):
        wd = BrainWatchdog(scope_hosts=frozenset({"lab.example"}))
        for i in range(10):
            wd.observe_update("node", _update(f"http://lab.example/api/{i}"))
        stop, _ = wd.should_stop()
        assert not stop


class TestSafeStop:
    def test_snapshot_written_and_exception_raised(self, tmp_path, monkeypatch):
        monkeypatch.setenv("WEBPENT_BRAIN_WATCHDOG_SNAPSHOT_DIR", str(tmp_path))
        wd = BrainWatchdog(
            scope_hosts=frozenset({"lab.example"}), engagement_id="w7-lab")
        wd.observe_update("node", _update("http://evil.example/x"))
        stop, reason = wd.should_stop()
        assert stop
        exc = wd.safe_stop(reason, last_state={"findings": [
            {"title": "t", "url": "http://evil.example/x",
             "vuln_class": "idor"}]})
        assert isinstance(exc, BrainSafeStop)
        assert exc.reason.startswith("scope_violation")
        assert exc.snapshot_path and os.path.isfile(exc.snapshot_path)
        payload = json.loads(open(exc.snapshot_path, encoding="utf-8").read())
        assert payload["schema"] == "umdr47-w7-safe-stop-v1"
        assert payload["engagement_id"] == "w7-lab"
        assert payload["request_count"] == 1
        assert payload["findings_snapshot"][0]["vuln_class"] == "idor"

    def test_snapshot_scrubs_sensitive_material(self, tmp_path, monkeypatch):
        monkeypatch.setenv("WEBPENT_BRAIN_WATCHDOG_SNAPSHOT_DIR", str(tmp_path))
        wd = BrainWatchdog(engagement_id="w7-priv")
        exc = wd.safe_stop("manual", last_state={
            "findings": [{
                "title": "leaked", "url": "http://t/x",
                "vuln_class": "idor", "session": "SESS-1234",
            }],
        })
        raw = open(exc.snapshot_path, encoding="utf-8").read()
        assert "SESS-1234" not in raw

    def test_deterministic_counters(self):
        a = BrainWatchdog(scope_hosts=frozenset({"h"}))
        b = BrainWatchdog(scope_hosts=frozenset({"h"}))
        for wd in (a, b):
            wd.observe_update("n", _update("http://h/1"))
            wd.observe_update("n", _update("http://h/1"))
        assert a.request_count == b.request_count
        assert a.request_signatures == b.request_signatures


class TestStreamIntegration:
    """The watchdog observes the run_unified_hunt update stream."""

    def test_watchdog_gates_on_real_update_shape(self):
        # the real stream yields {node: {findings: [...], ...}}
        wd = BrainWatchdog(scope_hosts=frozenset({"lab"}), max_repeats=2)
        chunk = {"access_control": {
            "findings": [{"url": "http://lab/api/orders/123",
                          "request_method": "GET",
                          "title": "IDOR candidate",
                          "vuln_class": "idor"}],
            "node_step_trace": [],
        }}
        for _ in range(3):
            wd.observe_update("access_control", chunk["access_control"])
        stop, reason = wd.should_stop()
        assert stop
        assert "GET:http://lab/api/orders/123" in reason
