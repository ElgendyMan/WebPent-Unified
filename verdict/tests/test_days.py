"""U-VERDICT-2 — day checklist tests (8 tests)."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import write_target_yaml
from verdict_tool.classifier import FindingClassifier
from verdict_tool.protocol import TOTAL_DAYS, get_day, protocol_days
from verdict_tool.tracking import Workspace, new_state, utc_now


def test_registry_covers_all_47_days() -> None:
    registry = protocol_days()
    assert len(registry) == TOTAL_DAYS == 47
    assert set(registry) == set(range(47))


def test_every_day_is_fully_specified() -> None:
    for number, spec in protocol_days().items():
        assert spec.title, f"day {number} has no title"
        assert spec.phase, f"day {number} has no phase"
        assert spec.objectives, f"day {number} has no objectives"
        assert spec.output_required, f"day {number} has no required outputs"


def test_day0_passes_when_prepared(ws: Workspace) -> None:
    day0 = get_day(0)
    assert day0.is_complete(ws) is False
    (ws.root / "pre_registration.md").write_text("# pre-registration\n",
                                                encoding="utf-8")
    state = ws.load()
    state.pre_registered = True
    ws.save(state)
    assert day0.is_complete(ws) is True


def test_day1_requires_three_valid_targets(ws: Workspace) -> None:
    day1 = get_day(1)
    assert not day1.is_complete(ws)
    for letter in "abc":
        yaml_path = write_target_yaml(
            ws.root, name=f"target_{letter}", handle=f"handle_{letter}")
        yaml_path.rename(ws.root / "targets" / f"{yaml_path.name}")
    state = ws.load()
    for letter in "abc":
        state.targets.append({
            "name": f"target_{letter}", "platform": "hackerone",
            "config_path": str(ws.root / "targets" / f"target_{letter}.yaml"),
            "added_at": utc_now(), "legal_review": True,
        })
    ws.save(state)
    missing = day1.missing(ws)
    assert missing == ["legal_clearance.md exists"]
    (ws.root / "legal_clearance.md").write_text("cleared\n", encoding="utf-8")
    assert day1.is_complete(ws)


def test_run_day_pair_checks(tmp_path: Path) -> None:
    ws = Workspace(tmp_path / "ws")
    ws.ensure_dirs()
    ws.save(new_state())
    day3 = get_day(3)
    day4 = get_day(4)
    assert not day3.is_complete(ws)
    state = ws.load()
    state.runs.append({"target": "target_a", "started_at": utc_now(),
                       "stopped_at": None})
    ws.save(state)
    run_dir = ws.root / "runs" / "target_a"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "launch.txt").write_text("launch\n", encoding="utf-8")
    assert day3.is_complete(ws)
    assert not day4.is_complete(ws)
    (run_dir / "stop.txt").write_text("stop\n", encoding="utf-8")
    (run_dir / "backup").mkdir(exist_ok=True)
    (run_dir / "checkins.txt").write_text("ok\n", encoding="utf-8")
    state = ws.load()
    state.runs[-1]["stopped_at"] = utc_now()
    ws.save(state)
    assert day4.is_complete(ws)


def test_analysis_day_requires_classification(ws: Workspace) -> None:
    day5 = get_day(5)
    state = ws.load()
    classifier = FindingClassifier(state, ws)
    classifier.register("f-1", "target_a", "sqli", "high", 0.9)
    assert not day5.is_complete(ws)
    classifier.classify("f-1", "false_positive",
                        re_test_evidence=["shots/f.png"],
                        reason="waf blocks the probe")
    (ws.root / "findings" / "analysis_target_a.md").write_text(
        "analysis\n", encoding="utf-8")
    assert day5.is_complete(ws)


def test_selection_day_requires_exact_five(ws: Workspace) -> None:
    day14 = get_day(14)
    state = ws.load()
    classifier = FindingClassifier(state, ws)
    ids = []
    for i in range(6):
        fid = f"f-{i}"
        classifier.register(fid, "target_a", "sqli", "high", 0.9)
        classifier.classify(fid, "confirmed",
                            re_test_evidence=["shots/f.png"],
                            impact_confirmed="impact")
        ids.append(fid)
    (ws.root / "findings" / "cross_analysis.md").write_text(
        "cross\n", encoding="utf-8")
    state = ws.load()
    state.selection = ids[:4]
    ws.save(state)
    assert not day14.is_complete(ws)
    state = ws.load()
    state.selection = ids[:5]
    ws.save(state)
    assert day14.is_complete(ws)


def test_watch_days_and_final_day(ws: Workspace) -> None:
    day16 = get_day(16)
    day45 = get_day(45)
    day46 = get_day(46)
    assert day16.phase == day45.phase == "watch"
    assert day46.phase == "verdict"
    assert not day16.is_complete(ws)
    state = ws.load()
    state.watch_opened_at = utc_now()
    state.submissions.append({"finding_id": "f-1", "platform_id": "p-1",
                              "platform": "hackerone",
                              "submitted_at": utc_now(),
                              "screenshot_path": "shots/f.png",
                              "report_path": "submissions/f-1.md"})
    ws.save(state)
    (ws.root / "watch").mkdir(exist_ok=True)
    (ws.root / "watch" / "tracker.md").write_text("tracker\n",
                                                  encoding="utf-8")
    assert day16.is_complete(ws)
    assert day45.is_complete(ws)
    assert not day46.is_complete(ws)
    for rel in ("verdict/metrics_report.md", "verdict/final_verdict.md"):
        path = ws.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("content\n", encoding="utf-8")
    state = ws.load()
    state.final_verdict = {"outcome": "GO", "reasoning": "validated"}
    ws.save(state)
    assert day46.is_complete(ws)


def test_unknown_day_raises() -> None:
    with pytest.raises(ValueError):
        get_day(99)
