"""U-JC-9: the Council Memory — bounded recall with patterns and lessons."""

from __future__ import annotations

from datetime import datetime, timezone

from webpent.jc.contracts import CouncilSession, Verdict, context_hash
from webpent.jc.memory import DEFAULT_RETENTION_DAYS, PATTERN_MIN_SAMPLES, CouncilMemory

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
TS = 1_800_000_000.0


def make_verdict(action="attack", confidence=0.7):
    return Verdict(action=action, reasoning="r", confidence=confidence,
                   confidence_tier="medium", dissent=[], escalate=False,
                   escalation_reason=None, advocates_summary={},
                   session_id="s1", timestamp=NOW)


def make_session(session_id="s1", question="q", context=None):
    return CouncilSession(session_id=session_id, question=question,
                          context=context or {"target_id": "lab-01"},
                          started_at=NOW)


def test_documented_constants():
    assert DEFAULT_RETENTION_DAYS == 180
    assert PATTERN_MIN_SAMPLES == 5


def test_record_writes_entry(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    memory.record(make_session(), make_verdict(), ts=TS)
    rows = memory.all_entries()
    assert len(rows) == 1
    assert rows[0]["session_id"] == "s1"
    assert rows[0]["context_hash"] == context_hash({"target_id": "lab-01"})
    assert rows[0]["verdict"]["advisory"] is True


def test_record_hash_is_key_order_independent(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    memory.record(make_session(context={"a": 1, "b": 2}), make_verdict(), ts=TS)
    memory.record(make_session(session_id="s2", context={"b": 2, "a": 1}),
                  make_verdict(), ts=TS)
    hashes = {r["context_hash"] for r in memory.all_entries()}
    assert len(hashes) == 1  # canonical JSON: key order never matters


def test_link_outcome(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    memory.record(make_session(), make_verdict(), ts=TS)
    memory.record(make_session(session_id="s2"), make_verdict(), ts=TS)
    assert memory.link_outcome("s1", "correct", ts=TS) == 1
    rows = memory.all_entries()
    linked = [r for r in rows if r["outcome"] == "correct"]
    assert len(linked) == 1 and linked[0]["session_id"] == "s1"


def test_link_unknown_session_returns_zero(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    memory.record(make_session(), make_verdict(), ts=TS)
    assert memory.link_outcome("missing", "correct", ts=TS) == 0


def test_retention_drops_old_entries(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    memory.record(make_session(), make_verdict(), ts=TS)
    far_future = TS + (DEFAULT_RETENTION_DAYS + 10) * 86400.0
    memory.record(make_session(session_id="s2"), make_verdict(), ts=far_future)
    ids = [r["session_id"] for r in memory.all_entries()]
    assert ids == ["s2"]  # the old entry aged out on compaction


def test_retention_keeps_recent_entries(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    for i in range(3):
        memory.record(make_session(session_id=f"s{i}"), make_verdict(), ts=TS + i)
    assert len(memory.all_entries()) == 3


def test_find_similar_exact_match_first(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    memory.record(make_session(context={"target_id": "lab-01"}), make_verdict(),
                  ts=TS)
    memory.record(make_session(session_id="s2", context={"os": "linux"}),
                  make_verdict(), ts=TS)
    memory.record(make_session(session_id="s3",
                               context={"target_id": "lab-02", "env": "prod"}),
                  make_verdict(), ts=TS)
    similar = memory.find_similar({"target_id": "lab-01", "env": "prod"}, k=5)
    assert similar[0]["session_id"] == "s3"  # best key overlap (2 of 2)
    ids = [s["session_id"] for s in similar]
    assert "s2" not in ids  # zero key overlap with the query -> excluded
    assert "s1" in ids


def test_find_similar_respects_k(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    for i in range(6):
        memory.record(make_session(session_id=f"s{i}",
                                   context={"target_id": "lab-01", "n": i}),
                      make_verdict(), ts=TS + i)
    similar = memory.find_similar({"target_id": "lab-01"}, k=2)
    assert len(similar) == 2


def test_find_similar_exact_hash_scores_one(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    memory.record(make_session(context={"target_id": "lab-01"}), make_verdict(),
                  ts=TS)
    similar = memory.find_similar({"target_id": "lab-01"})
    assert similar and similar[0]["session_id"] == "s1"


def test_find_pattern_requires_five(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    prefix = context_hash({"target_id": "lab-01"})[:12]
    for i in range(PATTERN_MIN_SAMPLES - 1):
        memory.record(make_session(session_id=f"s{i}"), make_verdict(), ts=TS)
    assert memory.find_pattern(prefix) is None


def test_find_pattern_detected(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    prefix = context_hash({"target_id": "lab-01"})[:12]
    for i in range(PATTERN_MIN_SAMPLES):
        memory.record(make_session(session_id=f"s{i}"),
                      make_verdict(action="attack"), ts=TS)
    pattern = memory.find_pattern(prefix)
    assert pattern is not None
    assert pattern.action == "attack"
    assert pattern.count == PATTERN_MIN_SAMPLES
    assert pattern.as_dict()["advisory"] is True


def test_find_pattern_mixed_actions_is_none(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    prefix = context_hash({"target_id": "lab-01"})[:12]
    for i in range(PATTERN_MIN_SAMPLES):
        memory.record(make_session(session_id=f"s{i}"),
                      make_verdict(action="attack" if i % 2 else "park"),
                      ts=TS)
    assert memory.find_pattern(prefix) is None


def test_feed_lessons_incorrect_only(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    memory.record(make_session(), make_verdict(), ts=TS)
    memory.record(make_session(session_id="s2"), make_verdict(), ts=TS)
    memory.link_outcome("s1", "incorrect", ts=TS)
    memory.link_outcome("s2", "correct", ts=TS)
    lessons = memory.feed_lessons()
    assert len(lessons) == 1
    assert lessons[0]["lesson_kind"] == "council_decision_failed"
    assert lessons[0]["session_id"] == "s1"
    assert lessons[0]["advisory"] is True


def test_corrupt_lines_ignored(tmp_path):
    (tmp_path / "mem.jsonl").write_text("garbage\n")
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    memory.record(make_session(), make_verdict(), ts=TS)
    assert len(memory.all_entries()) == 1  # corrupt line dropped, not duplicated


def test_repeated_records_survive(tmp_path):
    memory = CouncilMemory(tmp_path / "mem.jsonl", now_ts=TS)
    for i in range(10):
        memory.record(make_session(session_id=f"s{i}"), make_verdict(), ts=TS + i)
    assert len(memory.all_entries()) == 10
