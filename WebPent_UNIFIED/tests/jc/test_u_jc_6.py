"""U-JC-6: the Dissent Register — minority opinions preserved and scored."""

from __future__ import annotations

from datetime import datetime, timezone

from webpent.jc.contracts import DissentingView, Verdict
from webpent.jc.dissent import DissentRegister

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
TS = 1_800_000_000.0


def verdict_with_dissent(session_id, pairs):
    """pairs: list of (advocate_id, claim)."""
    return Verdict(
        action="winner-action",
        reasoning="r",
        confidence=0.7,
        confidence_tier="medium",
        dissent=[
            DissentingView(advocate_id=aid, claim=claim, reasoning="kept",
                           confidence=0.6)
            for aid, claim in pairs
        ],
        escalate=False,
        escalation_reason=None,
        advocates_summary={},
        session_id=session_id,
        timestamp=NOW,
    )


def test_record_writes_one_line_per_dissent(tmp_path):
    register = DissentRegister(tmp_path / "dissent.jsonl")
    written = register.record(verdict_with_dissent("s1", [("a2", "wait"),
                                                          ("a3", "park")]))
    assert written == 2
    assert len((tmp_path / "dissent.jsonl").read_text().splitlines()) == 2


def test_record_without_dissent_writes_nothing(tmp_path):
    register = DissentRegister(tmp_path / "dissent.jsonl")
    assert register.record(verdict_with_dissent("s1", [])) == 0
    assert not (tmp_path / "dissent.jsonl").exists()


def test_link_outcome_updates_state(tmp_path):
    register = DissentRegister(tmp_path / "dissent.jsonl")
    register.record(verdict_with_dissent("s1", [("a2", "wait")]), now=TS)
    linked = register.link_outcome("s1", "correct", now=TS + 1)
    assert linked == 1
    resolved = list(register._resolve().values())
    assert resolved[0]["outcome"] == "correct"


def test_link_unknown_session_links_nothing(tmp_path):
    register = DissentRegister(tmp_path / "dissent.jsonl")
    register.record(verdict_with_dissent("s1", [("a2", "wait")]), now=TS)
    assert register.link_outcome("missing", "correct", now=TS) == 0


def test_accuracy_none_without_data(tmp_path):
    register = DissentRegister(tmp_path / "dissent.jsonl")
    register.record(verdict_with_dissent("s1", [("a2", "wait")]), now=TS)
    assert register.get_dissent_accuracy("a2") is None
    assert register.get_dissent_accuracy("a9") is None


def test_accuracy_computed(tmp_path):
    register = DissentRegister(tmp_path / "dissent.jsonl")
    register.record(verdict_with_dissent("s1", [("a2", "wait")]), now=TS)
    register.record(verdict_with_dissent("s2", [("a2", "wait")]), now=TS)
    register.link_outcome("s1", "correct", now=TS)
    register.link_outcome("s2", "incorrect", now=TS)
    assert register.get_dissent_accuracy("a2") == 0.5


def test_log_is_append_only(tmp_path):
    path = tmp_path / "dissent.jsonl"
    register = DissentRegister(path)
    register.record(verdict_with_dissent("s1", [("a2", "wait")]), now=TS)
    before = path.read_text()
    register.link_outcome("s1", "correct", now=TS + 5)
    after = path.read_text()
    assert after.startswith(before)  # history never rewritten
    assert len(after.splitlines()) == len(before.splitlines()) + 1


def test_latest_link_wins(tmp_path):
    register = DissentRegister(tmp_path / "dissent.jsonl")
    register.record(verdict_with_dissent("s1", [("a2", "wait")]), now=TS)
    register.link_outcome("s1", "correct", now=TS + 1)
    register.link_outcome("s1", "incorrect", now=TS + 2)
    assert register.get_dissent_accuracy("a2") == 0.0


def test_persistent_minority_requires_three(tmp_path):
    register = DissentRegister(tmp_path / "dissent.jsonl")
    for i in range(2):
        register.record(verdict_with_dissent(f"s{i}", [("a2", "wait")]), now=TS)
        register.link_outcome(f"s{i}", "correct", now=TS)
    assert register.get_persistent_minority() == []


def test_persistent_minority_detected(tmp_path):
    register = DissentRegister(tmp_path / "dissent.jsonl")
    for i in range(3):
        register.record(verdict_with_dissent(f"s{i}", [("a2", "wait")]), now=TS)
        register.link_outcome(f"s{i}", "correct", now=TS)
    assert register.get_persistent_minority() == ["a2"]


def test_export_for_lessons(tmp_path):
    register = DissentRegister(tmp_path / "dissent.jsonl")
    register.record(verdict_with_dissent("s1", [("a2", "wait")]), now=TS)
    register.link_outcome("s1", "correct", now=TS)
    lessons = register.export_for_lessons()
    assert lessons and lessons[0]["lesson_kind"] == "dissent_proved_right"
    assert lessons[0]["advocate_id"] == "a2"


def test_corrupt_lines_ignored(tmp_path):
    path = tmp_path / "dissent.jsonl"
    path.write_text("not json\n{s1, a2\n")
    register = DissentRegister(path)
    register.record(verdict_with_dissent("s1", [("a2", "wait")]), now=TS)
    assert register.get_dissent_accuracy("a2") is None
