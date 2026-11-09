"""U-JC-10: the Reasoning Explainer — three levels, markdown and JSON."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webpent.jc.contracts import (
    Argument,
    Challenge,
    CouncilSession,
    DissentingView,
    Evidence,
    Verdict,
)
from webpent.jc.explainer import LEVELS, Explainer

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)


def make_verdict():
    return Verdict(
        action="attack", reasoning="a1 scored highest", confidence=0.72,
        confidence_tier="medium",
        dissent=[DissentingView(advocate_id="a2", claim="park",
                                reasoning="JC-L-5: minority view kept",
                                confidence=0.55)],
        escalate=False, escalation_reason=None,
        advocates_summary={
            "a1": {"claim": "attack", "score": 3.0, "challenge_severity": 0.1,
                   "confidence": 0.72, "argue_order": 0, "evidence_count": 3,
                   "raw_evidence_weight": 3.0},
            "a2": {"claim": "park", "score": 1.2, "challenge_severity": 0.2,
                   "confidence": 0.55, "argue_order": 1, "evidence_count": 1,
                   "raw_evidence_weight": 1.2},
        },
        session_id="s1", timestamp=NOW,
    )


def make_session():
    session = CouncilSession(session_id="s1", question="is lab-01 ready?",
                             context={"target_id": "lab-01"}, started_at=NOW)
    session.arguments.append(Argument(
        advocate_id="a1", claim="attack",
        evidence=[Evidence(kind="signal", content="open port", source="lab-01",
                           observed_at=NOW, confidence=0.8, specificity=0.8)],
        reasoning="stated", confidence=0.7, alternatives=["hold"],
        timestamp=NOW))
    session.challenges.append(Challenge(
        target_advocate_id="a1", counter_claim="one kind only",
        counter_evidence=[], bias_flags=["confirmation"],
        alternative_hypothesis="artifact", challenge_severity=0.15,
        timestamp=NOW))
    return session


def test_documented_levels():
    assert LEVELS == ("one-liner", "summary", "full")


def test_unknown_level_raises():
    with pytest.raises(ValueError):
        Explainer().explain(make_verdict(), level="tiny")


def test_one_liner_level():
    data = Explainer().explain(make_verdict(), level="one-liner")
    assert data["advisory"] is True
    assert data["level"] == "one-liner"
    assert data["action"] == "attack"
    assert "attack" in data["one_liner"]
    assert "escalate" not in data["one_liner"] or not data["escalate"]
    assert data["winner"] == "a1"


def test_one_liner_mentions_escalation():
    verdict = make_verdict()
    verdict.escalate = True
    verdict.escalation_reason = "below medium"
    data = Explainer().explain(verdict, level="one-liner")
    assert "escalate" in data["one_liner"]


def test_summary_level_counts():
    data = Explainer().explain(make_verdict(), level="summary")
    assert data["n_arguments"] == 2
    assert data["n_dissent"] == 1
    assert data["dissent_ids"] == ["a2"]
    assert [a["advocate_id"] for a in data["advocates"]] == ["a1", "a2"]


def test_full_level_includes_everything():
    session = make_session()
    data = Explainer().explain(make_verdict(), session, level="full")
    assert data["question"] == "is lab-01 ready?"
    assert len(data["arguments"]) == 1
    assert len(data["challenges"]) == 1
    assert data["dissent"][0]["advocate_id"] == "a2"
    entry = next(a for a in data["advocates"] if a["advocate_id"] == "a1")
    assert entry["evidence_count"] == 3
    assert entry["argue_order"] == 0


def test_full_level_without_session():
    data = Explainer().explain(make_verdict(), None, level="full")
    assert data["question"] is None
    assert data["arguments"] == []
    assert data["challenges"] == []


def test_levels_are_monotonic_in_information():
    ex = Explainer()
    verdict, session = make_verdict(), make_session()
    one = ex.explain(verdict, session, level="one-liner")
    summary = ex.explain(verdict, session, level="summary")
    full = ex.explain(verdict, session, level="full")
    for key, value in one.items():
        if key != "level":
            assert summary[key] == value
    for key, value in summary.items():
        if key not in ("level", "advocates"):
            assert full[key] == value
    # full's advocate entries are strict supersets of summary's
    for f_entry, s_entry in zip(full["advocates"], summary["advocates"], strict=False):
        for key, value in s_entry.items():
            assert f_entry[key] == value


def test_markdown_renders_all_sections():
    text = Explainer().to_markdown(make_verdict(), make_session())
    assert "# Council verdict (s1)" in text
    assert "## Advocates" in text
    assert "## Dissent (preserved, JC-L-5)" in text
    assert "## Skeptic challenges" in text
    assert "## Reasoning" in text
    assert "Advisory only (JC-L-1)" in text
    assert "attack" in text and "a2" in text


def test_markdown_deterministic():
    ex = Explainer()
    a = ex.to_markdown(make_verdict(), make_session())
    b = ex.to_markdown(make_verdict(), make_session())
    assert a == b


def test_json_matches_explain_data():
    ex = Explainer()
    verdict, session = make_verdict(), make_session()
    assert ex.to_json(verdict, session) == ex.explain(verdict, session,
                                                      level="full")
