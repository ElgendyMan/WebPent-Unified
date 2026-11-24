"""UM-DR-46 Phase H — research memory tests (deterministic lessons).

The lab: Phase C's lesson records flow into a wall-clock-free memory,
match OPEN hypotheses by family (vuln_class — lessons carry no target
URL, an honest documented limitation), and DEMOTE matching open
hypotheses by pure copies (info_gain ×0.8 + a memory stamp). Memory
can LOWER a priority; it never raises authority or rewrites history.
"""

from __future__ import annotations

from typing import Any

from webpent.researcher.memory import (
    compact_lessons,
    match_lessons,
    memory_demotion_lookup,
)

LESSON_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PARENT_ID = "11111111-1111-4111-8111-111111111111"
RELATED_ID = "22222222-2222-4222-8222-222222222222"
UNRELATED_ID = "33333333-3333-4333-8333-333333333333"
BASE = "https://shop.example"


def _lesson() -> dict[str, Any]:
    return {
        "lesson_id": LESSON_ID,
        "refuted_hypothesis_id": PARENT_ID,
        "vuln_class": "idor",
        "statement": "orders:123 readable by bob without ownership",
        "evidence_refs": ["ev-1"],
        "related_hypothesis_ids": [RELATED_ID],
        "learned": "the idor family on this target was resolved FALSE once",
    }


def _hypothesis(hyp_id: str, **overrides: Any) -> Any:
    from webpent.production.hypothesis_adapter import canonical_hypothesis

    fields: dict[str, Any] = {
        "id": hyp_id,
        "statement": "orders:456 readable by bob",
        "vuln_class": "idor",
        "origin": "researcher_brain",
        "origin_detail": "lab",
        "target_url": BASE,
        "expected_behavior": "denied",
        "negative_control": "owner succeeds",
        "info_gain": 0.5,
    }
    fields.update(overrides)
    return canonical_hypothesis(**fields)


def _pool() -> list[Any]:
    return [
        _hypothesis(RELATED_ID),                                # matching open
        _hypothesis(UNRELATED_ID, vuln_class="ssti",
                    statement="ssti candidate"),                # non-matching
        _hypothesis("44444444-4444-4444-8444-444444444444",
                    status="resolved_false"),                   # closed
    ]


class TestCompaction:
    def test_deterministic_grouping(self) -> None:
        memory = compact_lessons([_lesson()])
        assert memory["total_lessons"] == 1
        assert memory["clock_policy"] == "deterministic (no wall clock)"
        assert memory["by_class"]["idor"]["refutation_count"] == 1
        assert memory["by_class"]["idor"]["latest_lesson_id"] == LESSON_ID
        assert memory == compact_lessons([_lesson()])

    def test_empty_lessons_empty_memory(self) -> None:
        memory = compact_lessons([])
        assert memory["total_lessons"] == 0
        assert memory["by_class"] == {}


class TestMatching:
    def test_matching_family_hint(self) -> None:
        pool = _pool()
        memory = compact_lessons([_lesson()])
        hints = match_lessons(pool, memory, [_lesson()])
        ids = {h["hypothesis_id"] for h in hints}
        assert RELATED_ID in ids
        hint = next(h for h in hints if h["hypothesis_id"] == RELATED_ID)
        assert hint["prior_refutations"] == 1
        assert LESSON_ID in hint["lesson_ids"]
        assert UNRELATED_ID not in ids
        assert "44444444-4444-4444-8444-444444444444" not in ids

    def test_deterministic(self) -> None:
        pool = _pool()
        memory = compact_lessons([_lesson()])
        one = match_lessons(pool, memory, [_lesson()])
        two = match_lessons(pool, memory, [_lesson()])
        assert one == two


class TestDemotions:
    def test_lookup_is_negative_and_clamped(self) -> None:
        pool = _pool()
        memory = compact_lessons([_lesson()])
        lookup = memory_demotion_lookup(pool, memory, [_lesson()])
        assert str(RELATED_ID) in lookup
        assert lookup[str(RELATED_ID)] == -0.1
        assert str(UNRELATED_ID) not in lookup
        # the closed hypothesis is never demoted
        assert "44444444-4444-4444-8444-444444444444" not in lookup

    def test_lookup_scales_with_refutations_and_clamps(self) -> None:
        pool = _pool()
        memory = compact_lessons([_lesson()] * 7)
        lookup = memory_demotion_lookup(pool, memory, [_lesson()] * 7)
        assert lookup[str(RELATED_ID)] == -0.5, "clamped at -0.5"

    def test_pool_values_stay_lifecycle_protected(self) -> None:
        # the UM-DR-44 B2 policy: a DECLARED info_gain wins over any
        # re-emission — memory must NOT be able to mutate the pool
        from webpent.state.reducers import merge_hypotheses

        pool = _pool()
        merged = merge_hypotheses(pool, list(pool))
        related = next(h for h in merged if str(h.id) == RELATED_ID)
        assert related.info_gain == 0.5, "declared values win"
