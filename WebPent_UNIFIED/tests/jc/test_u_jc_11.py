"""U-JC-11: the Override Protocol — operator sovereignty, recorded and scored."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webpent.jc.contracts import Verdict
from webpent.jc.override import (
    ALLOWED_MODES,
    DEFAULT_MIN_REASON_CHARS,
    OverrideProtocol,
)

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
TS = 1_800_000_000.0


def make_verdict(action="attack", confidence=0.7, escalate=False,
                 session_id="s1"):
    return Verdict(action=action, reasoning="r", confidence=confidence,
                   confidence_tier="medium", dissent=[], escalate=escalate,
                   escalation_reason=None, advocates_summary={},
                   session_id=session_id, timestamp=NOW)


def test_documented_constants():
    assert ALLOWED_MODES == ("full", "partial", "advisory")
    assert DEFAULT_MIN_REASON_CHARS == 10


def test_full_override_requires_final_action(tmp_path):
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=TS)
    with pytest.raises(ValueError):
        protocol.apply(make_verdict(), "full", "i disagree with the council")


def test_short_reason_rejected(tmp_path):
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=TS)
    with pytest.raises(ValueError):
        protocol.apply(make_verdict(), "advisory", "nope")


def test_unknown_mode_rejected(tmp_path):
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=TS)
    with pytest.raises(ValueError):
        protocol.apply(make_verdict(), "veto", "this mode does not exist")


def test_full_override_recorded(tmp_path):
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=TS)
    entry = protocol.apply(make_verdict(), "full", "i disagree with the council",
                           final_action="wait", ts=TS)
    assert entry["mode"] == "full"
    assert entry["final_action"] == "wait"
    assert entry["council_action"] == "attack"
    assert entry["advisory"] is True
    assert entry["outcome"] is None


def test_partial_override_defaults_to_council_action(tmp_path):
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=TS)
    entry = protocol.apply(make_verdict(), "partial", "narrow the scope only",
                           ts=TS)
    assert entry["final_action"] == "attack"


def test_advisory_override_recorded(tmp_path):
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=TS)
    entry = protocol.apply(make_verdict(), "advisory", "noted, no action taken",
                           ts=TS)
    assert entry["mode"] == "advisory"
    assert (tmp_path / "ov.jsonl").exists()


def test_link_outcome_updates_all_session_overrides(tmp_path):
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=TS)
    protocol.apply(make_verdict(), "advisory", "first note for the record",
                   ts=TS)
    protocol.apply(make_verdict(), "partial", "second note for the record",
                   ts=TS)
    assert protocol.link_outcome("s1", "correct", ts=TS + 1) == 2
    entries = protocol.entries()
    assert all(e["outcome"] == "correct" for e in entries)


def test_link_unknown_session_links_nothing(tmp_path):
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=TS)
    protocol.apply(make_verdict(), "advisory", "noted, no action taken", ts=TS)
    assert protocol.link_outcome("missing", "correct", ts=TS) == 0


def test_accuracy_none_without_outcomes(tmp_path):
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=TS)
    protocol.apply(make_verdict(), "advisory", "noted, no action taken", ts=TS)
    assert protocol.operator_accuracy() is None


def test_accuracy_computed(tmp_path):
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=TS)
    protocol.apply(make_verdict(session_id="s1"), "advisory",
                   "first call, proved right", ts=TS)
    protocol.apply(make_verdict(session_id="s2"), "advisory",
                   "second call, proved wrong", ts=TS)
    protocol.apply(make_verdict(session_id="s3"), "advisory",
                   "third call, proved right", ts=TS)
    protocol.link_outcome("s1", "correct", ts=TS)
    protocol.link_outcome("s2", "incorrect", ts=TS)
    protocol.link_outcome("s3", "correct", ts=TS)
    assert protocol.operator_accuracy() == pytest.approx(2 / 3)


def test_accuracy_per_operator(tmp_path):
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=TS)
    protocol.apply(make_verdict(session_id="s1"), "advisory",
                   "operator one was right", operator_id="op1", ts=TS)
    protocol.apply(make_verdict(session_id="s2"), "advisory",
                   "operator two was wrong", operator_id="op2", ts=TS)
    protocol.link_outcome("s1", "correct", ts=TS)
    protocol.link_outcome("s2", "incorrect", ts=TS)
    assert protocol.operator_accuracy("op1") == 1.0
    assert protocol.operator_accuracy("op2") == 0.0


def test_log_is_append_only(tmp_path):
    path = tmp_path / "ov.jsonl"
    protocol = OverrideProtocol(path, now_ts=TS)
    protocol.apply(make_verdict(), "advisory", "noted, no action taken", ts=TS)
    before = path.read_text()
    protocol.link_outcome("s1", "correct", ts=TS + 5)
    after = path.read_text()
    assert after.startswith(before)  # history never rewritten
    assert len(after.splitlines()) == len(before.splitlines()) + 1


def test_confidence_clamped_in_entry(tmp_path):
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=TS)
    entry = protocol.apply(make_verdict(confidence=1.5), "advisory",
                           "noted, no action taken", ts=TS)
    assert entry["council_confidence"] == 1.0


def test_corrupt_lines_ignored(tmp_path):
    (tmp_path / "ov.jsonl").write_text("garbage\n")
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=TS)
    protocol.apply(make_verdict(), "advisory", "noted, no action taken", ts=TS)
    assert len(protocol.entries()) == 1
