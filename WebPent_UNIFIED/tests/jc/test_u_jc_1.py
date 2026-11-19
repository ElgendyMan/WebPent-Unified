"""U-JC-1: the CouncilChamber — deterministic session lifecycle (JC-L-2..L-5)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from webpent.jc.chamber import CouncilChamber, load_council_config
from webpent.jc.contracts import Argument, Challenge, CouncilSession, Evidence
from webpent.jc.judge import Judge
from webpent.jc.skeptic import Skeptic

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
CONTEXT = {"target_id": "lab-01", "findings_value": 30}


def make_arg(advocate_id: str = "tactician", claim: str = "do-x",
             confidence: float = 0.7, n_evidence: int = 2,
             observed: datetime | None = None) -> Argument:
    stamp = observed or NOW
    return Argument(
        advocate_id=advocate_id,
        claim=claim,
        evidence=[
            Evidence(kind="signal", content=f"fact-{advocate_id}-{i}",
                     source="scanner-1", observed_at=stamp,
                     confidence=0.8, specificity=0.8)
            for i in range(n_evidence)
        ],
        reasoning="clear signal from the scan",
        confidence=confidence,
        alternatives=["alternative-path"],
        timestamp=stamp,
    )


def chamber(judge: Judge | None = None) -> CouncilChamber:
    return CouncilChamber(skeptic=Skeptic(), judge=judge or Judge(),
                          now=NOW)


def test_convene_creates_session():
    ch = chamber()
    session = ch.convene("should we escalate?", CONTEXT)
    assert isinstance(session, CouncilSession)
    assert session.question == "should we escalate?"
    assert session.session_id


def test_convene_is_deterministic():
    ch = chamber()
    a = ch.convene("same question", dict(CONTEXT))
    b = chamber().convene("same question", dict(CONTEXT))
    assert a.session_id == b.session_id


def test_session_id_survives_key_order():
    ch = chamber()
    a = ch.convene("q", {"a": 1, "b": 2})
    b = chamber().convene("q", {"b": 2, "a": 1})
    assert a.session_id == b.session_id


def test_convene_rejects_empty_question():
    with pytest.raises(ValueError):
        chamber().convene("   ", CONTEXT)


def test_convene_rejects_empty_context():
    with pytest.raises(ValueError):
        chamber().convene("question", {})


def test_submit_argument_files_into_session():
    ch = chamber()
    session = ch.convene("q", CONTEXT)
    ch.submit_argument(session.session_id, make_arg())
    assert len(session.arguments) == 1
    assert session.arguments[0].advocate_id == "tactician"


def test_submit_to_unknown_session_raises():
    ch = chamber()
    stranger = CouncilSession(session_id="nope", question="q", context=CONTEXT,
                              started_at=NOW)
    with pytest.raises(ValueError):
        ch.submit_argument(stranger.session_id, make_arg())


def test_debate_round_limit_raises(tmp_path):
    config = tmp_path / "council.yaml"
    config.write_text(
        "council:\n  max_debate_rounds: 1\n  min_advocates: 1\n"
        "  time_limit_seconds: 30\n"
    )
    ch = CouncilChamber(skeptic=Skeptic(), judge=Judge(),
                        config_path=config, now=NOW)
    session = ch.convene("q", CONTEXT)
    ch.submit_argument(session.session_id, make_arg("a1", "c1"))
    with pytest.raises(ValueError):
        ch.submit_argument(session.session_id, make_arg("a2", "c2"))


def test_close_with_judge_returns_verdict():
    ch = chamber()
    session = ch.convene("q", CONTEXT)
    for aid in ("a1", "a2", "a3"):
        ch.submit_argument(session.session_id, make_arg(aid, f"claim-{aid}"))
    verdict = ch.close(session.session_id, now=NOW + timedelta(seconds=5))
    assert verdict is not None
    assert verdict.action == "claim-a1"  # deterministic: first max wins
    assert verdict.session_id == session.session_id


def test_close_without_judge_escalates():
    ch = CouncilChamber(skeptic=Skeptic(), judge=None, now=NOW)
    session = ch.convene("q", CONTEXT)
    ch.submit_argument(session.session_id, make_arg("a1"))
    ch.submit_argument(session.session_id, make_arg("a2"))
    verdict = ch.close(session.session_id, now=NOW + timedelta(seconds=5))
    assert verdict is not None and verdict.escalate
    assert "judge" in (verdict.escalation_reason or "")


def test_min_advocates_escalates():
    ch = chamber()
    session = ch.convene("q", CONTEXT)
    ch.submit_argument(session.session_id, make_arg("a1", "c1"))
    verdict = ch.close(session.session_id, now=NOW + timedelta(seconds=5))
    assert verdict is not None and verdict.escalate
    assert "minimum" in (verdict.escalation_reason or "")


def test_skeptic_challenges_every_argument_on_close():
    ch = chamber()
    session = ch.convene("q", CONTEXT)
    for aid in ("a1", "a2", "a3"):
        ch.submit_argument(session.session_id, make_arg(aid, f"claim-{aid}"))
    ch.close(session.session_id, now=NOW + timedelta(seconds=5))
    assert len(session.challenges) == 3
    assert all(isinstance(c, Challenge) for c in session.challenges)


def test_time_limit_exceeded_escalates(tmp_path):
    config = tmp_path / "council.yaml"
    config.write_text(
        "council:\n  max_debate_rounds: 3\n  min_advocates: 1\n"
        "  time_limit_seconds: 10\n"
    )
    ch = CouncilChamber(skeptic=Skeptic(), judge=Judge(),
                        config_path=config, now=NOW)
    session = ch.convene("q", CONTEXT)
    ch.submit_argument(session.session_id, make_arg("a1", "c1"))
    verdict = ch.close(session.session_id, now=NOW + timedelta(seconds=11))
    assert verdict is not None and verdict.escalate
    assert "time limit" in (verdict.escalation_reason or "")


def test_second_close_returns_same_verdict():
    ch = chamber()
    session = ch.convene("q", CONTEXT)
    for aid in ("a1", "a2", "a3"):
        ch.submit_argument(session.session_id, make_arg(aid, f"claim-{aid}"))
    first = ch.close(session.session_id, now=NOW + timedelta(seconds=5))
    second = ch.close(session.session_id, now=NOW + timedelta(seconds=5))
    assert first is second
    assert session.closed is True


def test_config_loader_fails_soft(tmp_path):
    corrupt = tmp_path / "council.yaml"
    corrupt.write_text("council: [broken\n  yaml: :")
    defaults = load_council_config(corrupt)
    assert defaults == load_council_config(None)


def test_config_overrides_apply(tmp_path):
    config = tmp_path / "council.yaml"
    config.write_text(
        "council:\n  max_debate_rounds: 2\n  min_advocates: 1\n"
        "  time_limit_seconds: 30\n"
    )
    data = load_council_config(config)
    assert data["min_advocates"] == 1
    assert data["max_debate_rounds"] == 2
