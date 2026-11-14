# tests/test_feedback_loop.py
"""PROPOSALS_ULTIMATE_V3 §1 (2026-10-31) test suite: market feedback loop.

Covers the operator gate (flag off AND empty path each refuse before
any path is touched), fail-closed recording (unknown outcome, negative
bounty, empty finding ref, write failure), the append-only JSONL
format, fail-closed reading (bad encoding, bad JSON, schema
violations), the per-class aggregation math on a fixed fixture, the
worst_classes ordering (flip count, then acceptance rate), and that a
closed gate performs zero I/O.
"""

from __future__ import annotations

import json
import os

import pytest

from webpent.learning.feedback_loop import (
    ACCEPTED,
    FeedbackLoopError,
    OutcomeRecord,
    all_class_stats,
    class_stats,
    feedback_loop_refusal,
    load_outcomes,
    record_outcome,
    worst_classes,
)

OUTCOMES_PATH = "outcomes.jsonl"


def _activated(path_only: bool = False):
    from webpent.config.settings import Settings, activate_settings

    kwargs = {"enable_feedback_loop": not path_only, "feedback_outcomes_path": OUTCOMES_PATH}
    if path_only:
        kwargs["enable_feedback_loop"] = False
    return activate_settings(Settings(**kwargs))


def _rec(**overrides):
    base = dict(
        finding_ref="F-001",
        campaign_id="camp-1",
        vuln_class="idor",
        outcome=ACCEPTED,
        platform_report_id="R-99",
        bounty_usd=250.0,
        severity_offered="high",
        operator_note="paid",
        recorded_at=1000.0,
    )
    base.update(overrides)
    return OutcomeRecord(**base)


# ---------------------------------------------------------------------------
# Operator gate (flag AND path, doubly gated).
# ---------------------------------------------------------------------------


class TestGate:
    def test_flag_off_refuses(self):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(
            Settings(enable_feedback_loop=False, feedback_outcomes_path=OUTCOMES_PATH)
        ):
            assert feedback_loop_refusal() == "feedback_loop_flag_off"

    def test_empty_path_refuses_even_with_flag_on(self):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_feedback_loop=True, feedback_outcomes_path="")):
            assert feedback_loop_refusal() == "feedback_loop_path_missing"

    def test_flag_on_and_path_open(self):
        with _activated():
            assert feedback_loop_refusal() is None


# ---------------------------------------------------------------------------
# Recording: append-only JSONL, fail-closed validation.
# ---------------------------------------------------------------------------


class TestRecordOutcome:
    def test_appends_one_json_line(self, tmp_path):
        target = tmp_path / "nested" / OUTCOMES_PATH
        with _activated():
            record_outcome(target, _rec())
        lines = target.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        doc = json.loads(lines[0])
        assert doc["finding_ref"] == "F-001"
        assert doc["outcome"] == "accepted"
        assert doc["bounty_usd"] == 250.0

    def test_append_only_preserves_history(self, tmp_path):
        target = tmp_path / OUTCOMES_PATH
        with _activated():
            record_outcome(target, _rec())
            record_outcome(target, _rec(outcome="duplicate", bounty_usd=None))
        lines = target.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["outcome"] == "accepted"
        assert json.loads(lines[1])["outcome"] == "duplicate"

    def test_zero_bounty_allowed_negative_refused(self, tmp_path):
        target = tmp_path / OUTCOMES_PATH
        with _activated():
            record_outcome(target, _rec(bounty_usd=0))
            with pytest.raises(FeedbackLoopError, match="feedback_loop_negative_bounty"):
                record_outcome(target, _rec(bounty_usd=-1))
        assert len(target.read_text(encoding="utf-8").splitlines()) == 1

    def test_unknown_outcome_refused(self, tmp_path):
        target = tmp_path / OUTCOMES_PATH
        with _activated():
            with pytest.raises(FeedbackLoopError, match="feedback_loop_unknown_outcome"):
                record_outcome(target, _rec(outcome="triaged"))
        assert not target.exists()

    def test_empty_finding_ref_refused(self, tmp_path):
        with _activated():
            with pytest.raises(FeedbackLoopError, match="finding_ref"):
                record_outcome(tmp_path / OUTCOMES_PATH, _rec(finding_ref="  "))

    def test_write_failure_wrapped_fail_closed(self, tmp_path):
        target = tmp_path / "d"
        target.mkdir()
        target_file = target / OUTCOMES_PATH
        target_file.write_text("")
        target.chmod(0o444)  # read-only directory -> append fails
        try:
            with _activated():
                if os.access(target_file, os.W_OK):
                    pytest.skip("fs does not honor read-only bits for this uid")
                with pytest.raises(FeedbackLoopError, match="feedback_loop_write_failed"):
                    record_outcome(target_file, _rec())
        finally:
            target.chmod(0o755)

    def test_gate_refusal_raises_before_any_io(self, tmp_path):
        target = tmp_path / OUTCOMES_PATH
        with _activated(path_only=True):
            with pytest.raises(FeedbackLoopError, match="feedback_loop_flag_off"):
                record_outcome(target, _rec())
        assert not target.exists()
        assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# Reading: fail-closed on corruption.
# ---------------------------------------------------------------------------


class TestLoadOutcomes:
    def test_missing_file_returns_empty(self, tmp_path):
        assert load_outcomes(tmp_path / "nope.jsonl") == []

    def test_roundtrip(self, tmp_path):
        target = tmp_path / OUTCOMES_PATH
        with _activated():
            record_outcome(target, _rec())
        loaded = load_outcomes(target)
        assert len(loaded) == 1
        assert loaded[0].to_dict() == _rec().to_dict()

    def test_bad_encoding_refused(self, tmp_path):
        target = tmp_path / OUTCOMES_PATH
        target.write_bytes(b'{"finding_ref": "F\xff\xfe"}')
        with pytest.raises(FeedbackLoopError, match="feedback_loop_invalid_encoding"):
            load_outcomes(target)

    def test_bad_json_refused(self, tmp_path):
        target = tmp_path / OUTCOMES_PATH
        target.write_text(
            '{"finding_ref": "F-1", "outcome": "accepted"}\n{not json}\n',
            encoding="utf-8",
        )
        with pytest.raises(FeedbackLoopError, match="feedback_loop_invalid_json at line 2"):
            load_outcomes(target)

    def test_schema_violations_refused(self, tmp_path):
        for bad in (
            '["not an object"]',
            '{"outcome": "accepted"}',  # missing finding_ref
            '{"finding_ref": "F", "outcome": "x", "extra": 1}',  # unknown field
        ):
            target = tmp_path / OUTCOMES_PATH
            target.write_text(bad, encoding="utf-8")
            with pytest.raises(FeedbackLoopError, match="feedback_loop_schema"):
                load_outcomes(target)


# ---------------------------------------------------------------------------
# Aggregation: class_stats / worst_classes on a fixed fixture.
# ---------------------------------------------------------------------------


FIXTURE = [
    _rec(vuln_class="idor", outcome=ACCEPTED, bounty_usd=250.0, recorded_at=1),
    _rec(vuln_class="idor", outcome=ACCEPTED, bounty_usd=100.0, recorded_at=2),
    _rec(vuln_class="idor", outcome="duplicate", bounty_usd=None, recorded_at=3),
    _rec(vuln_class="xss", outcome="nfa", bounty_usd=None, recorded_at=4),
    _rec(vuln_class="xss", outcome="spam", bounty_usd=None, recorded_at=5),
    _rec(vuln_class="ssrf", outcome=ACCEPTED, bounty_usd=500.0, recorded_at=6),
]


class TestClassStats:
    def test_per_class_accuracy(self, tmp_path):
        target = tmp_path / OUTCOMES_PATH
        with _activated():
            for rec in FIXTURE:
                record_outcome(target, rec)
        idor = class_stats(target, "idor")
        assert idor["reports"] == 3
        assert idor["accepted"] == 2
        assert idor["duplicate"] == 1
        assert idor["acceptance_rate"] == pytest.approx(2 / 3)
        assert idor["total_bounty_usd"] == 350.0

    def test_unknown_class_empty(self, tmp_path):
        target = tmp_path / OUTCOMES_PATH
        with _activated():
            record_outcome(target, _rec())
        assert class_stats(target, "lfi") == {}

    def test_all_class_stats_pure_function(self):
        stats = all_class_stats(FIXTURE)
        assert set(stats) == {"idor", "xss", "ssrf"}
        assert stats["xss"]["reports"] == 2
        assert stats["xss"]["acceptance_rate"] == 0.0
        assert stats["ssrf"]["total_bounty_usd"] == 500.0


class TestWorstClasses:
    def test_ranked_by_flip_count_then_acceptance_rate(self, tmp_path):
        target = tmp_path / OUTCOMES_PATH
        with _activated():
            for rec in FIXTURE:
                record_outcome(target, rec)
        worst = worst_classes(target, k=2)
        # xss: 2 flips / 0 acceptance; idor: 1 flip / 2/3 acceptance.
        assert [w["vuln_class"] for w in worst] == ["xss", "idor"]
        assert worst[0]["reports"] == 2
        assert worst[0]["nfa"] == 1 and worst[0]["spam"] == 1

    def test_k_bounds_and_advisory_shape(self, tmp_path):
        target = tmp_path / OUTCOMES_PATH
        with _activated():
            for rec in FIXTURE:
                record_outcome(target, rec)
        worst = worst_classes(target, k=10)
        assert len(worst) == 3
        assert "auto_block" not in worst[0]  # awareness only, by contract

    def test_empty_file_no_classes(self, tmp_path):
        assert worst_classes(tmp_path / "empty.jsonl") == []


# ---------------------------------------------------------------------------
# Flag off: zero I/O anywhere.
# ---------------------------------------------------------------------------


class TestFlagOffNoIO:
    def test_reads_and_stats_still_pure_when_gate_closed(self, tmp_path):
        # Aggregation helpers take an explicit path and are pure; the
        # gate guards the WRITE path only, so with the flag off nothing
        # in the loop writes. Verify record_outcome never touches disk.
        target = tmp_path / OUTCOMES_PATH
        with _activated(path_only=True):
            with pytest.raises(FeedbackLoopError):
                record_outcome(target, _rec())
        assert not target.exists()
        # pure functions still work over a hand-built file (operator's
        # own data, written before the flag was turned off)
        target.write_text(
            json.dumps(_rec().to_dict()) + "\n", encoding="utf-8"
        )
        assert class_stats(target, "idor")["reports"] == 1
