"""U-DOJO-12 edge cases: ledger boundaries and default directories (L-2/L-5)."""

from __future__ import annotations

import json

from webpent.dojo.progress import MAX_AUDIT_LINES, ProgressTracker


def test_max_audit_lines_is_one_thousand():
    assert MAX_AUDIT_LINES == 1000


def test_trend_with_fewer_than_two_scores_is_flat(tmp_path):
    tracker = ProgressTracker(tmp_path)
    tracker.record({"score": 50.0})
    assert tracker.trend() == "flat"
    assert ProgressTracker(tmp_path).trend() == "flat"


def test_trend_with_two_equal_scores_is_flat(tmp_path):
    tracker = ProgressTracker(tmp_path)
    tracker.record({"score": 50.0})
    tracker.record({"score": 50.0})
    assert tracker.trend() == "flat"


def test_trend_ignores_entries_without_a_score(tmp_path):
    tracker = ProgressTracker(tmp_path)
    tracker.record({"command": "labs"})
    tracker.record({"command": "spar", "winner": "red"})
    assert tracker.trend() == "flat"


def test_odd_score_counts_favor_the_older_half(tmp_path):
    """With 3 entries: half=1, first=[s0], second=[s1,s2]."""
    tracker = ProgressTracker(tmp_path)
    for score in (0.0, 100.0, 100.0):
        tracker.record({"score": score})
    assert tracker.trend() == "improving"


def test_history_is_empty_without_a_file(tmp_path):
    assert ProgressTracker(tmp_path).history() == []


def test_summary_reports_dir_and_trend(tmp_path):
    tracker = ProgressTracker(tmp_path)
    summary = tracker.summary()
    assert summary["entries"] == 0
    assert summary["trend"] == "flat"
    assert summary["dojo_dir"] == str(tmp_path)


def test_default_dir_honors_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBPENT_DOJO_DIR", str(tmp_path / "env-dir"))
    tracker = ProgressTracker()
    assert tracker.dojo_dir == tmp_path / "env-dir"
    assert tracker.dojo_dir.exists()


def test_default_dir_falls_back_to_download_dojo(tmp_path, monkeypatch):
    from pathlib import Path

    monkeypatch.delenv("WEBPENT_DOJO_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    tracker = ProgressTracker()
    assert tracker.dojo_dir == Path("download") / "dojo"
    assert (tmp_path / "download" / "dojo").exists()


def test_record_nested_values_survive_the_roundtrip(tmp_path):
    tracker = ProgressTracker(tmp_path)
    entry = {"command": "practice", "meta": {"tags": ["a", "b"], "n": 2},
             "score": 91.5}
    tracker.record(entry)
    assert tracker.history()[0] == entry


def test_record_output_is_sorted_stable_json(tmp_path):
    tracker = ProgressTracker(tmp_path)
    tracker.record({"b": 1, "a": 2})
    line = (tmp_path / "history.jsonl").read_text(encoding="utf-8").strip()
    assert line == '{"a": 2, "b": 1}'


def test_audit_cap_at_exactly_the_boundary(tmp_path):
    tracker = ProgressTracker(tmp_path)
    for i in range(MAX_AUDIT_LINES):
        tracker.audit("practice", f"r-{i}")
    lines = (tmp_path / "audit_log.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == MAX_AUDIT_LINES
    tracker.audit("practice", "one-more")
    lines = (tmp_path / "audit_log.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == MAX_AUDIT_LINES
    assert json.loads(lines[-1])["detail"] == "one-more"
    assert json.loads(lines[0])["detail"] == "r-1"


def test_history_and_audit_are_independent_files(tmp_path):
    tracker = ProgressTracker(tmp_path)
    tracker.record({"score": 1.0})
    tracker.audit("practice", "x")
    assert (tmp_path / "history.jsonl").exists()
    assert (tmp_path / "audit_log.jsonl").exists()


def test_tracker_creates_the_dojo_dir_on_demand(tmp_path):
    deep = tmp_path / "a" / "b" / "c"
    tracker = ProgressTracker(deep)
    tracker.record({"score": 1.0})
    assert (deep / "history.jsonl").exists()
