"""Tests for engagement-scoped hunt memory (Phase 4).

* hints never leak across engagement:target scopes,
* tampered or forged entries are refused,
* hints are capped at 0.75,
* an offline replay of two hunts on the same scope proves the learned
  memory reorders the deterministic ranking toward the pattern that
  confirmed, while never overriding it,
* governance stops are never learned from.
"""

from __future__ import annotations

from webpent.autonomous.hunt_memory import ScopedHuntMemory, scope_key
from webpent.autonomous.hunt_orchestrator import _apply_learning_hints
from webpent.smart.memory_engine import MemoryEntry


def _entry(pattern: str, outcome: str, confidence: float = 0.75) -> MemoryEntry:
    return MemoryEntry(
        pattern_id=pattern,
        pattern_type="hunt_pattern",
        features={"vulnerability_class": pattern},
        outcome=outcome,
        confidence=confidence,
        source="autonomous_hunt",
    )


def test_hints_do_not_leak_across_scopes() -> None:
    memory = ScopedHuntMemory()
    memory.store(
        engagement_id="e1",
        target_id="http://a.example/",
        entry=_entry("idor", "vulnerable"),
    )
    hints_a = memory.hint(engagement_id="e1", target_id="http://a.example/")
    hints_b = memory.hint(engagement_id="e1", target_id="http://b.example/")
    hints_other = memory.hint(engagement_id="e2", target_id="http://a.example/")
    assert hints_a.get("idor", 0.0) > 0
    assert hints_b == {}
    assert hints_other == {}


def test_tampered_entry_is_refused() -> None:
    memory = ScopedHuntMemory()
    entry = _entry("idor", "vulnerable")
    entry.outcome = "clean"  # forged after signing
    try:
        memory.store(engagement_id="e1", target_id="t1", entry=entry)
        raise AssertionError("tampered entry was accepted")
    except ValueError:
        pass
    assert memory.entries_for("e1", "t1") == []


def test_hints_are_capped_at_0_75() -> None:
    memory = ScopedHuntMemory()
    memory.store(
        engagement_id="e1",
        target_id="t1",
        entry=_entry("idor", "vulnerable", confidence=1.0),
    )
    hints = memory.hint(engagement_id="e1", target_id="t1")
    assert hints["idor"] <= 0.75


def test_governance_stops_are_never_learned() -> None:
    memory = ScopedHuntMemory()

    class _State:
        engagement_id = "e1"
        target_url = "http://a.example/"
        outcomes = [
            {"status": "policy_denied", "vulnerability_class": "idor"},
            {"status": "confirmed", "vulnerability_class": "sqli"},
        ]

    memory.update(_State())
    entries = memory.entries_for("e1", "http://a.example/")
    patterns = {e.pattern_id for e in entries}
    assert patterns == {"sqli"}


def test_offline_replay_reorders_toward_confirmed_pattern() -> None:
    memory = ScopedHuntMemory()

    # Hunt 1: two hypotheses, sqli confirms, idor is clean.
    class _Hunt1:
        engagement_id = "e1"
        target_url = "http://a.example/"
        outcomes = [
            {"status": "confirmed", "vulnerability_class": "sqli"},
            {"status": "executed", "vulnerability_class": "idor"},
        ]

    memory.update(_Hunt1())

    # Hunt 2 (offline replay of the same scope): the deterministic
    # ranking alone has idor slightly ahead; the learned hint must
    # reorder sqli to the top, bounded by the cap.
    hypotheses = [
        {"pattern_id": "idor", "priority": 1.0},
        {"pattern_id": "sqli", "priority": 0.8},
    ]
    hints = memory.update(_Hunt1())
    assert hints.get("sqli", 0.0) > 0
    ranked = _apply_learning_hints(hypotheses, hints)
    assert ranked[0]["pattern_id"] == "sqli"
    # The cap still bounds the boost: a large deterministic gap survives.
    hypotheses2 = [
        {"pattern_id": "idor", "priority": 3.0},
        {"pattern_id": "sqli", "priority": 0.8},
    ]
    ranked2 = _apply_learning_hints(hypotheses2, hints)
    assert ranked2[0]["pattern_id"] == "idor"


def test_clean_outcome_is_not_hinted_upward() -> None:
    memory = ScopedHuntMemory()

    class _State:
        engagement_id = "e1"
        target_url = "http://a.example/"
        outcomes = [{"status": "executed", "vulnerability_class": "idor"}]

    hints = memory.update(_State())
    assert "idor" not in hints


def test_scope_key_is_engagement_colon_target() -> None:
    assert scope_key("e1", "t1") == "e1:t1"
