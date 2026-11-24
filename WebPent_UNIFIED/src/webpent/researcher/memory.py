"""UM-DR-46 Phase H — research memory (deterministic lessons).

The mission's Phase H: the negative-evidence lessons (Phase C's
``research_lessons``) become a DETERMINISTIC, wall-clock-free memory:

* ``compact_lessons``  — group the lessons by vuln_class with counts
  and the latest deterministic lesson record per class;
* ``match_lessons``    — for each OPEN hypothesis, the memory hint for
  its (vuln_class, target_url) family: how many prior refutations the
  family carries and which lesson ids — a PRIORITIZATION hint only;
* ``apply_memory_demotions`` — pure copies of matching open
  hypotheses with decayed info_gain (×0.8) and a memory stamp in the
  evidence contract (the pool reducer upserts them).

No wall clock anywhere (measurement determinism law): the memory is a
pure function of the lesson records. Advisory only — memory can lower
a priority, never raise authority, never rewrite history.
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from webpent.models.hypothesis import Hypothesis

__all__ = [
    "compact_lessons",
    "match_lessons",
    "memory_demotion_lookup",
]

_MAX_LESSONS = 64
_MAX_HINTS = 32
_MEMORY_DECAY_STEP = 0.1
_OPEN_STATUSES = {"unexplored", "investigating", "learned"}


def _open(hyp: Hypothesis) -> bool:
    return str(getattr(hyp, "status", "")).lower().split(".")[-1] in (
        _OPEN_STATUSES)


def compact_lessons(lessons: list[dict[str, Any]]) -> dict[str, Any]:
    """Deterministic memory compaction (no wall clock)."""
    by_class: dict[str, dict[str, Any]] = {}
    for lesson in lessons[:_MAX_LESSONS]:
        vuln_class = str(lesson.get("vuln_class") or "unknown")
        entry = by_class.setdefault(vuln_class, {
            "refutation_count": 0,
            "lesson_ids": [],
            "latest_lesson_id": "",
            "latest_learned": "",
        })
        entry["refutation_count"] += 1
        lesson_id = str(lesson.get("lesson_id") or "")
        entry["lesson_ids"].append(lesson_id)
        entry["lesson_ids"] = entry["lesson_ids"][:8]
        entry["latest_lesson_id"] = lesson_id
        entry["latest_learned"] = str(lesson.get("learned") or "")[:300]
    return {
        "advisory_only": True,
        "total_lessons": min(len(lessons), _MAX_LESSONS),
        "by_class": dict(sorted(by_class.items())),
        "clock_policy": "deterministic (no wall clock)",
    }


def _family_key(vuln_class: str) -> str:
    """Lessons (Phase C records) carry no target URL, so the memory
    family is keyed by vuln_class alone — an honest, documented
    limitation: the hint is family-level, not target-level."""
    blob = json.dumps({"c": str(vuln_class or "").lower()},
                      sort_keys=True, separators=(",", ":"))
    return sha256(blob.encode("utf-8")).hexdigest()[:40]


def match_lessons(
    pool: list[Hypothesis],
    memory: dict[str, Any],
    lessons: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Memory hints for open hypotheses matching refuted families."""
    family_lessons: dict[str, list[dict[str, Any]]] = {}
    for lesson in lessons[:_MAX_LESSONS]:
        key = _family_key(str(lesson.get("vuln_class") or ""))
        family_lessons.setdefault(key, []).append(lesson)
    hints: list[dict[str, Any]] = []
    for hyp in pool[:_MAX_HINTS * 2]:
        if not _open(hyp):
            continue
        key = _family_key(str(hyp.vuln_class))
        matched = family_lessons.get(key) or []
        if not matched:
            continue
        hints.append({
            "hypothesis_id": str(hyp.id),
            "vuln_class": str(hyp.vuln_class),
            "target_url": str(hyp.target_url),
            "prior_refutations": len(matched),
            "lesson_ids": [str(m.get("lesson_id") or "") for m in matched[:4]],
            "advisory_only": True,
        })
        if len(hints) >= _MAX_HINTS:
            break
    return hints


def memory_demotion_lookup(
    pool: list[Hypothesis],
    memory: dict[str, Any],
    lessons: list[dict[str, Any]],
) -> dict[str, float]:
    """Ranking-time demotion bonuses for matching open hypotheses.

    The pool's declared values are lifecycle-protected (the reducer's
    UM-DR-44 B2 policy: an existing DECLARED info_gain wins over any
    re-emission), so memory does NOT mutate the pool. Instead it
    returns the ``{hypothesis_id: negative bonus}`` map that any
    consumer of ``rank_open_hypotheses(novelty_lookup=...)`` can apply
    at RANKING time: ``-0.1 * prior_refutations``, clamped at -0.5.
    """
    hints = {
        h["hypothesis_id"]: h for h in match_lessons(pool, memory, lessons)
    }
    lookup: dict[str, float] = {}
    for hyp in pool:
        hint = hints.get(str(hyp.id))
        if hint is None or not _open(hyp):
            continue
        bonus = max(
            -0.5, -_MEMORY_DECAY_STEP * int(hint["prior_refutations"]))
        lookup[str(hyp.id)] = round(bonus, 4)
    return lookup
