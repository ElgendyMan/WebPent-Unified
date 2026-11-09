"""U-JC-5: the Judge — scoring, synthesis, confidence, tiers, escalation."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webpent.jc.contracts import Argument, Challenge, CouncilSession, Evidence
from webpent.jc.judge import Judge
from webpent.jc.verdict import VerdictRules, load_verdict_rules
from webpent.jc.weigher import EvidenceWeigher

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)


def ev(content, source="lab-01", confidence=0.8, specificity=0.8,
       kind="signal", observed=None):
    return Evidence(kind=kind, content=content, source=source,
                    observed_at=observed or NOW, confidence=confidence,
                    specificity=specificity)


def arg(advocate_id, claim, n_evidence=3, confidence=0.7):
    return Argument(advocate_id=advocate_id, claim=claim,
                    evidence=[ev(f"{advocate_id}-{i}") for i in range(n_evidence)],
                    reasoning="stated", confidence=confidence,
                    alternatives=["hold"], timestamp=NOW)


def challenge(target, severity):
    return Challenge(target_advocate_id=target, counter_claim="counter",
                     counter_evidence=[], bias_flags=["general_doubt"],
                     alternative_hypothesis="alt", challenge_severity=severity,
                     timestamp=NOW)


def session(args, challenges=(), context=None):
    s = CouncilSession(session_id="s1", question="q",
                       context=context or {"target_id": "lab-01"},
                       started_at=NOW)
    s.arguments.extend(args)
    s.challenges.extend(challenges)
    return s


def test_clear_winner_mode():
    verdict = Judge().rule(session([arg("a1", "attack", 4), arg("a2", "wait", 1)]),
                           now=NOW)
    assert verdict.action == "attack"
    assert "mode=clear_winner" in verdict.reasoning
    assert not verdict.escalate


def test_coalesce_mode():
    close = arg("a1", "attack", 2, )
    close.evidence = [
        Evidence(kind="lesson", content="l1", source="lab-01", observed_at=NOW,
                 confidence=0.8, specificity=0.8),
        Evidence(kind="lesson", content="l2", source="lab-01", observed_at=NOW,
                 confidence=0.8, specificity=0.8),
    ]
    verdict = Judge().rule(session([close, arg("a2", "wait", 1)]), now=NOW)
    assert "mode=coalesce" in verdict.reasoning
    assert verdict.action == "attack"


def test_tie_escalates():
    verdict = Judge().rule(session([arg("a1", "attack", 2), arg("a2", "attack", 2)]),
                           now=NOW)
    assert verdict.escalate
    assert "tie" in (verdict.escalation_reason or "")


def test_low_confidence_escalates():
    verdict = Judge().rule(session([arg("a1", "attack", 1), arg("a2", "wait", 1),
                                    arg("a3", "park", 1), arg("a4", "hold", 1)]),
                           now=NOW)
    assert verdict.escalate
    assert "below medium" in (verdict.escalation_reason or "")


def test_confidence_formula():
    s = session([arg("a1", "attack", 3), arg("a2", "wait", 1)])
    verdict = Judge().rule(s, now=NOW)
    scores = {d["score"] for d in verdict.advocates_summary.values()}
    top, total = max(scores), sum(scores)
    assert verdict.confidence == pytest.approx(top / total, abs=1e-6)


def test_score_formula_applies_challenge_severity():
    s = session([arg("a1", "attack", 2), arg("a2", "wait", 2)],
                challenges=[challenge("a1", 0.5)])
    summary = Judge().score_advocates(s, EvidenceWeigher(now=NOW))
    weigher = EvidenceWeigher(now=NOW)
    raw = sum(w.weight for w in weigher.weigh_all(s.arguments[0].evidence))
    assert summary["a1"]["score"] == pytest.approx(raw * 0.5, abs=1e-9)
    assert summary["a1"]["challenge_severity"] == 0.5


def test_max_severity_wins_per_advocate():
    s = session([arg("a1", "attack", 2)],
                challenges=[challenge("a1", 0.3), challenge("a1", 0.7)])
    summary = Judge().score_advocates(s, EvidenceWeigher(now=NOW))
    assert summary["a1"]["challenge_severity"] == 0.7


def test_dissent_excludes_winner_and_echoes():
    s = session([arg("a1", "attack", 3), arg("a2", "attack", 1),
                 arg("a3", "park", 1)])
    verdict = Judge().rule(s, now=NOW)
    dissent_ids = [d.advocate_id for d in verdict.dissent]
    assert "a1" not in dissent_ids
    assert "a2" not in dissent_ids  # same claim as the winner: agreement, not dissent
    assert "a3" in dissent_ids
    assert all("JC-L-5" in d.reasoning for d in verdict.dissent)


def test_empty_session_escalates():
    verdict = Judge().rule(session([]), now=NOW)
    assert verdict.action == "none"
    assert verdict.escalate
    assert "no arguments" in (verdict.escalation_reason or "")


def test_every_advocate_appears_in_reasoning():
    s = session([arg("a1", "attack", 3), arg("a2", "wait", 1), arg("a3", "park", 1)])
    verdict = Judge().rule(s, now=NOW)
    for aid in ("a1", "a2", "a3"):
        assert aid in verdict.reasoning


@pytest.mark.parametrize(
    "confidence,expected",
    [(0.85, "high"), (0.86, "high"), (0.84, "medium"), (0.60, "medium"),
     (0.59, "low"), (0.0, "low")],
)
def test_tier_boundaries(confidence, expected):
    rules = VerdictRules()
    assert rules.tier(confidence) == expected


@pytest.mark.parametrize(
    "confidence,escalates",
    [(0.85, False), (0.60, False), (0.59, True)],
)
def test_escalation_rule(confidence, escalates):
    rules = VerdictRules()
    assert rules.should_escalate(confidence) is escalates


def test_rules_load_from_yaml(tmp_path):
    config = tmp_path / "verdict_rules.yaml"
    config.write_text(
        "verdict:\n"
        "  confidence_thresholds:\n    high: 0.9\n    medium: 0.7\n"
        "  clear_winner_ratio: 2.0\n"
    )
    rules = load_verdict_rules(config)
    assert rules.high == 0.9 and rules.medium == 0.7
    assert rules.clear_winner_ratio == 2.0
    assert rules.source == "config"


def test_rules_fail_soft_on_corrupt(tmp_path):
    corrupt = tmp_path / "broken.yaml"
    corrupt.write_text("verdict: [unclosed")
    rules = load_verdict_rules(corrupt)
    assert rules.high == VerdictRules().high


def test_verdict_is_deterministic():
    s = session([arg("a1", "attack", 3), arg("a2", "wait", 1)])
    a = Judge().rule(s, now=NOW)
    b = Judge().rule(s, now=NOW)
    assert a.action == b.action
    assert a.confidence == b.confidence
    assert a.reasoning == b.reasoning
    assert a.as_dict() == b.as_dict()


def test_confidence_never_exceeds_one():
    s = session([arg("a1", "attack", 9), arg("a2", "wait", 1)])
    verdict = Judge().rule(s, now=NOW)
    assert 0.0 <= verdict.confidence <= 1.0
    assert verdict.confidence_tier in ("high", "medium", "low")
