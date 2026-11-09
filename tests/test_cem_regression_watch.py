"""v83 T6 / U-CEM-6: the regression watch."""

from __future__ import annotations

from pathlib import Path

from webpent.autonomous.cem.regression_watch import (
    ACTIVE,
    DEFERRED,
    FIXED,
    REGRESSED,
    RegressionWatch,
    load_regression_config,
)

NOW = 1_700_000_000.0
WEEK = 168 * 3600.0


def _watch(tmp_path: Path, **kwargs) -> RegressionWatch:
    return RegressionWatch(tmp_path / "reg.json", **kwargs)


def test_lifecycle_active_to_fixed(tmp_path: Path) -> None:
    watch = _watch(tmp_path)
    watch.record_finding("f1", endpoint="/login", vuln_class="sqli", now=NOW)
    out = watch.note_result("f1", still_vulnerable=False, now=NOW + 3600)
    assert out["state"] == FIXED
    assert watch.status()[FIXED] == 1


def test_fixed_then_back_is_regression_alert(tmp_path: Path) -> None:
    watch = _watch(tmp_path)
    watch.record_finding("f1", endpoint="/login", now=NOW)
    watch.note_result("f1", still_vulnerable=False, now=NOW + 3600)
    out = watch.note_result("f1", still_vulnerable=True, now=NOW + 7200)
    assert out["state"] == REGRESSED
    assert out["regressed"] is True
    assert watch.regressed()[0]["finding_id"] == "f1"
    # a second consecutive still_vulnerable is not a new regression event
    out2 = watch.note_result("f1", still_vulnerable=True, now=NOW + 10800)
    assert out2["regressed"] is False


def test_endpoint_gone_defers_and_deferred_never_due(tmp_path: Path) -> None:
    watch = _watch(tmp_path)
    watch.record_finding("f1", endpoint="/login", now=NOW)
    out = watch.note_endpoint_gone("f1", now=NOW + 3600)
    assert out["state"] == DEFERRED
    assert watch.due_for_retest(NOW + 10 * WEEK) == []


def test_retest_interval_and_cap(tmp_path: Path) -> None:
    watch = _watch(tmp_path)
    watch.record_finding("f1", now=NOW)
    assert watch.due_for_retest(NOW + WEEK - 60) == []
    assert watch.due_for_retest(NOW + WEEK) == ["f1"]
    # cap: after max_retests the finding is never due again
    for i in range(int(watch.config["max_retests_per_finding"])):
        watch.note_result("f1", still_vulnerable=False, now=NOW + WEEK * (i + 1))
    assert watch.due_for_retest(NOW + WEEK * 99) == []


def test_missed_retests_auto_defer(tmp_path: Path) -> None:
    watch = _watch(tmp_path)
    watch.record_finding("f1", now=NOW)
    watch.note_retest_blocked("f1")
    assert watch._findings["f1"]["state"] == ACTIVE
    watch.note_retest_blocked("f1")
    assert watch._findings["f1"]["state"] == DEFERRED


def test_unknown_and_garbage_ids_are_noops(tmp_path: Path) -> None:
    watch = _watch(tmp_path)
    assert watch.note_result("ghost", still_vulnerable=True, now=NOW) is None
    assert watch.note_endpoint_gone("ghost", now=NOW) is None
    assert watch.note_retest_blocked("ghost") is None
    assert watch.record_finding("", now=NOW) == {}
    assert watch.record_finding("f1", now=NOW)["state"] == ACTIVE
    # duplicate registration is idempotent
    again = watch.record_finding("f1", now=NOW + 60)
    assert again["first_seen"] == NOW


def test_store_bounded_at_max_findings(tmp_path: Path) -> None:
    from webpent.autonomous.cem.regression_watch import MAX_FINDINGS

    watch = _watch(tmp_path)
    for i in range(MAX_FINDINGS + 10):
        watch.record_finding(f"f{i}", now=NOW + i)
    assert len(watch._findings) == MAX_FINDINGS
    assert "f0" not in watch._findings  # oldest evicted


def test_config_defaults_and_corruption(tmp_path: Path) -> None:
    assert load_regression_config(None)["retest_interval_hours"] == 168.0
    missing = load_regression_config(tmp_path / "nope.yaml")
    assert missing == load_regression_config(None)
    bad = tmp_path / "bad.yaml"
    bad.write_text("retest_interval_hours: [broken", encoding="utf-8")
    assert load_regression_config(bad) == load_regression_config(None)
    junk = tmp_path / "junk.yaml"
    junk.write_text("- a\n- b\n", encoding="utf-8")
    assert load_regression_config(junk) == load_regression_config(None)


def test_roundtrip_and_corruption(tmp_path: Path) -> None:
    path = tmp_path / "reg.json"
    watch = RegressionWatch(path)
    watch.record_finding("f1", endpoint="/a", now=NOW)
    watch.note_result("f1", still_vulnerable=False, now=NOW + 1)
    reloaded = RegressionWatch(path)
    assert reloaded.status()[FIXED] == 1

    path.write_text("nope", encoding="utf-8")
    assert RegressionWatch(path).status() == {ACTIVE: 0, FIXED: 0, REGRESSED: 0, DEFERRED: 0}


def test_due_for_retest_capped_per_cycle(tmp_path):
    """RT83-6: one cycle never queues more retests than MAX_DUE_PER_CYCLE."""
    watch = RegressionWatch(tmp_path / "rw.json")
    now = 0.0
    for i in range(64):
        watch.record_finding(f"f{i}", now=now)
    due = watch.due_for_retest(now + 400 * 3600.0)
    assert len(due) == 32
