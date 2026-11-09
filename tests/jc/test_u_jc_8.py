"""U-JC-8: the Bias Detector — five systemic patterns over recorded sessions."""

from __future__ import annotations

import json

import pytest

from webpent.jc.bias_detector import BIAS_TYPES, BiasDetector

TS = 1_800_000_000.0


def session_row(session_id, scores, claims=None, orders=None, ts=TS):
    """scores: {aid: score}; claims/orders optional per-advocate maps."""
    summary = {}
    for aid, score in scores.items():
        summary[aid] = {
            "score": score,
            "claim": (claims or {}).get(aid, f"{aid}-claim"),
            "argue_order": (orders or {}).get(aid, 0),
        }
    return json.dumps({
        "session_id": session_id,
        "ts": ts,
        "verdict": {"advocates_summary": summary},
    })


def write_sessions(path, rows):
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def types_of(findings):
    return {f.bias_type for f in findings}


def test_documented_bias_types_tuple():
    assert BIAS_TYPES == (
        "systemic_confirmation", "recency_dominance", "anchor_stickiness",
        "silent_veto", "majority_tyranny",
    )


def test_below_min_sessions_returns_nothing(tmp_path):
    path = tmp_path / "sessions.jsonl"
    write_sessions(path, [session_row(f"s{i}", {"a1": 2.0, "a2": 1.0})
                          for i in range(4)])
    detector = BiasDetector(path, min_sessions=5)
    assert detector.detect(now_ts=TS + 100) == []


def test_missing_file_returns_nothing(tmp_path):
    detector = BiasDetector(tmp_path / "nope.jsonl", min_sessions=1)
    assert detector.detect(now_ts=TS + 100) == []


def test_silent_veto_detected(tmp_path):
    path = tmp_path / "sessions.jsonl"
    write_sessions(path, [session_row(f"s{i}", {"loser": 1.0, "winner": 2.0},
                                        orders={"loser": 1, "winner": 0})
                          for i in range(5)])
    findings = BiasDetector(path, min_sessions=5).detect(now_ts=TS + 100)
    assert "silent_veto" in types_of(findings)
    finding = next(f for f in findings if f.bias_type == "silent_veto")
    assert "loser" in finding.evidence[0]


def test_silent_veto_not_fired_when_won_once(tmp_path):
    path = tmp_path / "sessions.jsonl"
    rows = [session_row(f"s{i}", {"loser": 1.0, "winner": 2.0},
                        orders={"loser": 1, "winner": 0}) for i in range(5)]
    rows.append(session_row("s5", {"loser": 2.0, "winner": 1.0},
                            orders={"loser": 0, "winner": 1}))
    write_sessions(path, rows)
    findings = BiasDetector(path, min_sessions=5).detect(now_ts=TS + 100)
    assert "silent_veto" not in types_of(findings)


def test_systemic_confirmation_detected(tmp_path):
    path = tmp_path / "sessions.jsonl"
    write_sessions(path, [
        session_row(f"s{i}", {"echo": 1.0, "winner": 2.0},
                    claims={"echo": "attack", "winner": "attack"},
                    orders={"echo": 1, "winner": 0})
        for i in range(5)
    ])
    findings = BiasDetector(path, min_sessions=5).detect(now_ts=TS + 100)
    assert "systemic_confirmation" in types_of(findings)
    finding = next(f for f in findings if f.bias_type == "systemic_confirmation")
    assert finding.recommendation  # every finding carries a recommendation


def test_systemic_confirmation_below_rate_not_fired(tmp_path):
    path = tmp_path / "sessions.jsonl"
    rows = [session_row(f"s{i}", {"echo": 1.0, "winner": 2.0},
                        claims={"echo": "attack", "winner": "attack"},
                        orders={"echo": 1, "winner": 0}) for i in range(4)]
    rows.append(session_row("s4", {"echo": 1.0, "winner": 2.0},
                            claims={"echo": "park", "winner": "attack"},
                            orders={"echo": 1, "winner": 0}))
    write_sessions(path, rows)  # echo rate 4/5 = 0.8 < 0.90
    findings = BiasDetector(path, min_sessions=5).detect(now_ts=TS + 100)
    assert "systemic_confirmation" not in types_of(findings)


def test_anchor_stickiness_detected(tmp_path):
    path = tmp_path / "sessions.jsonl"
    rows = [session_row(f"s{i}", {"a1": 3.0, "a2": 2.0, "a3": 1.0},
                        orders={"a1": 0, "a2": 1, "a3": 2}) for i in range(4)]
    rows.append(session_row("s4", {"a1": 3.0, "a2": 2.0, "a3": 1.0},
                            orders={"a1": 1, "a2": 0, "a3": 2}))
    write_sessions(path, rows)  # first-argued won 4/5 = 0.8 >= 0.70
    findings = BiasDetector(path, min_sessions=5).detect(now_ts=TS + 100)
    types = types_of(findings)
    assert "anchor_stickiness" in types
    assert "recency_dominance" not in types


def test_recency_dominance_detected(tmp_path):
    path = tmp_path / "sessions.jsonl"
    rows = [session_row(f"s{i}", {"a1": 1.0, "a2": 2.0, "a3": 3.0},
                        orders={"a1": 0, "a2": 1, "a3": 2}) for i in range(4)]
    rows.append(session_row("s4", {"a1": 1.0, "a2": 3.0, "a3": 2.0},
                            orders={"a1": 0, "a2": 2, "a3": 1}))
    write_sessions(path, rows)  # last-argued won 4/5 = 0.8 >= 0.70
    findings = BiasDetector(path, min_sessions=5).detect(now_ts=TS + 100)
    types = types_of(findings)
    assert "recency_dominance" in types
    assert "anchor_stickiness" not in types


def test_no_dominance_when_wins_scattered(tmp_path):
    path = tmp_path / "sessions.jsonl"
    rows = []
    for i in range(5):
        winner = f"a{i % 3}"
        scores = {"a0": 1.0, "a1": 1.0, "a2": 1.0}
        scores[winner] = 3.0
        rows.append(session_row(f"s{i}", scores,
                                orders={"a0": 0, "a1": 1, "a2": 2}))
    write_sessions(path, rows)
    findings = BiasDetector(path, min_sessions=5).detect(now_ts=TS + 100)
    types = types_of(findings)
    assert "anchor_stickiness" not in types
    assert "recency_dominance" not in types


def test_majority_tyranny_detected(tmp_path):
    from datetime import datetime, timezone

    from webpent.jc.contracts import DissentingView, Verdict
    from webpent.jc.dissent import DissentRegister

    now = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
    dpath = tmp_path / "dissent.jsonl"
    register = DissentRegister(dpath)
    for i in range(3):
        register.record(Verdict(
            action="winner", reasoning="r", confidence=0.7,
            confidence_tier="medium",
            dissent=[DissentingView(advocate_id="a2", claim="wait",
                                    reasoning="kept", confidence=0.6)],
            escalate=False, escalation_reason=None, advocates_summary={},
            session_id=f"s{i}", timestamp=now), now=TS)
        register.link_outcome(f"s{i}", "correct", now=TS)
    for i in (3, 4):
        register.record(Verdict(
            action="winner", reasoning="r", confidence=0.7,
            confidence_tier="medium",
            dissent=[DissentingView(advocate_id="a2", claim="wait",
                                    reasoning="kept", confidence=0.6)],
            escalate=False, escalation_reason=None, advocates_summary={},
            session_id=f"s{i}", timestamp=now), now=TS)
        register.link_outcome(f"s{i}", "incorrect", now=TS)
    spath = tmp_path / "sessions.jsonl"
    write_sessions(spath, [session_row(f"s{i}", {"a1": 2.0, "a2": 1.0})
                           for i in range(5)])
    detector = BiasDetector(spath, dissent_path=dpath, min_sessions=5)
    findings = detector.detect(now_ts=TS + 100)
    assert "majority_tyranny" in types_of(findings)


def test_majority_tyranny_needs_resolved_minimum(tmp_path):
    from datetime import datetime, timezone

    from webpent.jc.contracts import DissentingView, Verdict
    from webpent.jc.dissent import DissentRegister

    now = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
    dpath = tmp_path / "dissent.jsonl"
    register = DissentRegister(dpath)
    for i in range(4):  # below MIN_RESOLVED_DISSENT = 5
        register.record(Verdict(
            action="winner", reasoning="r", confidence=0.7,
            confidence_tier="medium",
            dissent=[DissentingView(advocate_id="a2", claim="wait",
                                    reasoning="kept", confidence=0.6)],
            escalate=False, escalation_reason=None, advocates_summary={},
            session_id=f"s{i}", timestamp=now), now=TS)
        register.link_outcome(f"s{i}", "correct", now=TS)
    spath = tmp_path / "sessions.jsonl"
    write_sessions(spath, [session_row(f"s{i}", {"a1": 2.0, "a2": 1.0})
                           for i in range(5)])
    detector = BiasDetector(spath, dissent_path=dpath, min_sessions=5)
    assert "majority_tyranny" not in types_of(detector.detect(now_ts=TS + 100))


def test_finding_envelope_advisory(tmp_path):
    path = tmp_path / "sessions.jsonl"
    write_sessions(path, [session_row(f"s{i}", {"loser": 1.0, "winner": 2.0})
                          for i in range(5)])
    findings = BiasDetector(path, min_sessions=5).detect(now_ts=TS + 100)
    for f in findings:
        d = f.as_dict()
        assert d["advisory"] is True
        assert d["recommendation"]
        assert 0.0 <= d["severity"] <= 1.0
        assert 0.0 <= d["confidence"] <= 1.0


def test_corrupt_lines_ignored(tmp_path):
    path = tmp_path / "sessions.jsonl"
    good = [session_row(f"s{i}", {"a1": 2.0, "a2": 1.0}) for i in range(5)]
    write_sessions(path, ["garbage", "{oops"] + good)
    findings = BiasDetector(path, min_sessions=5).detect(now_ts=TS + 100)
    assert "silent_veto" in types_of(findings)  # a1 wins 5, a2 never wins


def test_old_sessions_outside_window_ignored(tmp_path):
    path = tmp_path / "sessions.jsonl"
    write_sessions(path, [session_row(f"s{i}", {"loser": 1.0, "winner": 2.0},
                                        ts=TS - 60 * 86400)
                          for i in range(5)])
    detector = BiasDetector(path, min_sessions=5)
    assert detector.detect(window_days=30, now_ts=TS) == []


def test_history_and_timeline(tmp_path):
    path = tmp_path / "sessions.jsonl"
    write_sessions(path, [session_row(f"s{i}", {"loser": 1.0, "winner": 2.0})
                          for i in range(5)])
    history = tmp_path / "bias_history.jsonl"
    detector = BiasDetector(path, history_path=history, min_sessions=5)
    findings = detector.detect(now_ts=TS + 100)
    assert findings  # something fired
    assert history.exists()
    for f in findings:
        timeline = detector.get_bias_timeline(f.bias_type)
        assert timeline and timeline[0] == (TS + 100, pytest.approx(f.severity))
    assert detector.get_bias_timeline("nonexistent") == []


def test_detect_deterministic(tmp_path):
    path = tmp_path / "sessions.jsonl"
    write_sessions(path, [session_row(f"s{i}", {"loser": 1.0, "winner": 2.0},
                                        orders={"loser": 1, "winner": 0})
                          for i in range(5)])
    detector = BiasDetector(path, min_sessions=5)
    a = [f.as_dict() for f in detector.detect(now_ts=TS + 100)]
    b = [f.as_dict() for f in detector.detect(now_ts=TS + 100)]
    assert a == b
