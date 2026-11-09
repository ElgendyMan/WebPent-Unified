"""U-JC-3: the Skeptic — 7 documented flags, capped severity, alternatives."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from webpent.jc.contracts import BIAS_FLAGS, MAX_CHALLENGE_SEVERITY, Argument, Evidence
from webpent.jc.skeptic import BASE_SEVERITY, EMPTY_SEVERITY, FLAG_SEVERITY, Skeptic

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
OLD = NOW - timedelta(days=45)
CONTEXT = {"target_id": "lab-01", "now": NOW}


def make_arg(**overrides) -> Argument:
    defaults: dict = {
        "advocate_id": "historian",
        "claim": "do-x",
        "evidence": [
            Evidence(kind="lesson", content="lesson A", source="lab-01",
                     observed_at=NOW, confidence=0.8, specificity=0.8),
            Evidence(kind="signal", content="signal B", source="lab-01",
                     observed_at=NOW, confidence=0.7, specificity=0.7),
        ],
        "reasoning": "because",
        "confidence": 0.5,
        "alternatives": ["wait"],
        "timestamp": NOW,
    }
    defaults.update(overrides)
    return Argument(**defaults)


def flags_of(arg: Argument) -> list[str]:
    return Skeptic().challenge(arg, CONTEXT).bias_flags


# ------------------------------------------------------ the documented set
def test_bias_flag_set_is_documented_and_complete():
    assert BIAS_FLAGS == (
        "confirmation", "recency", "anchoring", "availability",
        "overconfidence", "sampling", "cherry_picking",
    )


def test_confirmation_flag_single_kind():
    arg = make_arg(evidence=[make_arg().evidence[0], make_arg().evidence[0]])
    assert "confirmation" in flags_of(arg)


def test_recency_flag_stale_evidence():
    arg = make_arg(evidence=[
        Evidence(kind="lesson", content="stale-1", source="lab-01",
                 observed_at=OLD, confidence=0.8, specificity=0.8),
        Evidence(kind="signal", content="stale-2", source="lab-01",
                 observed_at=OLD, confidence=0.8, specificity=0.8),
    ])
    assert "recency" in flags_of(arg)


def test_anchoring_flag_extreme_confidence():
    assert "anchoring" in flags_of(make_arg(confidence=1.0))
    assert "anchoring" in flags_of(make_arg(confidence=0.0))


def test_overconfidence_flag_thin_evidence():
    arg = make_arg(confidence=0.9, evidence=[make_arg().evidence[0]])
    assert "overconfidence" in flags_of(arg)


def test_sampling_flag_foreign_source():
    arg = make_arg(evidence=[
        Evidence(kind="lesson", content="x", source="other-lab",
                 observed_at=NOW, confidence=0.8, specificity=0.8),
        Evidence(kind="signal", content="y", source="lab-01",
                 observed_at=NOW, confidence=0.8, specificity=0.8),
    ])
    assert "sampling" in flags_of(arg)


def test_cherry_picking_flag_ignores_pool():
    pool_context = {"target_id": "lab-01", "now": NOW,
                    "evidence_pool": ["a", "b", "c"]}
    challenge = Skeptic().challenge(make_arg(), pool_context)
    assert "cherry_picking" in challenge.bias_flags


def test_availability_flag_no_evidence():
    challenge = Skeptic().challenge(make_arg(evidence=[]), CONTEXT)
    assert challenge.bias_flags == ["availability"]
    assert challenge.challenge_severity == EMPTY_SEVERITY
    assert challenge.counter_evidence  # the absence is the counter-evidence


# ------------------------------------------------------------ envelope
def test_general_doubt_baseline_for_clean_argument():
    challenge = Skeptic().challenge(
        make_arg(evidence=[
            Evidence(kind="lesson", content="x", source="lab-01",
                     observed_at=NOW, confidence=0.5, specificity=0.5),
            Evidence(kind="signal", content="y", source="lab-01",
                     observed_at=NOW, confidence=0.5, specificity=0.5),
        ], confidence=0.5),
        CONTEXT,
    )
    assert challenge.bias_flags == ["general_doubt"]
    assert challenge.challenge_severity == BASE_SEVERITY


def test_severity_scales_with_flag_count():
    stale_lesson = Evidence(kind="lesson", content="x", source="lab-01",
                            observed_at=OLD, confidence=0.5, specificity=0.5)
    stale_repeat = Evidence(kind="lesson", content="y", source="lab-01",
                            observed_at=OLD, confidence=0.5, specificity=0.5)
    light = Skeptic().challenge(make_arg(confidence=0.9,
                                         evidence=[stale_lesson, stale_repeat]),
                                CONTEXT)  # confirmation + recency = 2 flags
    assert light.challenge_severity == pytest.approx(2 * FLAG_SEVERITY)


def test_severity_is_capped_at_max():
    pool = {"target_id": "lab-01", "now": NOW, "evidence_pool": ["a", "b", "c"]}
    arg = make_arg(
        evidence=[Evidence(kind="lesson", content="s1", source="other-lab",
                           observed_at=OLD, confidence=0.5, specificity=0.8),
                  Evidence(kind="lesson", content="s2", source="other-lab",
                           observed_at=OLD, confidence=0.5, specificity=0.8)],
        confidence=1.0,
    )  # confirmation + recency + anchoring + sampling + cherry_picking
    challenge = Skeptic().challenge(arg, pool)  # 5 flags; 6th impossible now
    assert len(challenge.bias_flags) == 5
    # after RT-05 confirmation needs >= 2 items, so the flag count tops out
    # at 5 and severity stays below the cap; the cap is still the bound.
    assert challenge.challenge_severity == pytest.approx(5 * FLAG_SEVERITY)
    assert challenge.challenge_severity <= MAX_CHALLENGE_SEVERITY


def test_alternative_hypothesis_always_present():
    for arg in (make_arg(), make_arg(evidence=[]), make_arg(confidence=1.0)):
        challenge = Skeptic().challenge(arg, CONTEXT)
        assert challenge.alternative_hypothesis.strip()


def test_counter_claim_always_present():
    challenge = Skeptic().challenge(make_arg(), CONTEXT)
    assert challenge.counter_claim.strip()


def test_counter_evidence_mirrors_sources():
    challenge = Skeptic().challenge(make_arg(), CONTEXT)
    assert len(challenge.counter_evidence) == len(make_arg().evidence)
    assert all(e.kind == "prior" for e in challenge.counter_evidence)


def test_challenge_is_deterministic():
    arg = make_arg()
    a = Skeptic().challenge(arg, CONTEXT)
    b = Skeptic().challenge(arg, CONTEXT)
    assert a.bias_flags == b.bias_flags
    assert a.challenge_severity == b.challenge_severity
    assert a.counter_claim == b.counter_claim


def test_challenge_all_preserves_order():
    args = [make_arg(advocate_id=f"a{i}") for i in range(3)]
    challenges = Skeptic().challenge_all(args, CONTEXT)
    assert [c.target_advocate_id for c in challenges] == ["a0", "a1", "a2"]
