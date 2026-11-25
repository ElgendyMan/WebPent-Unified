"""UM-DR-46 Phase H — the research-memory production node.

Compacts the accumulated negative-evidence lessons (Phase C's
research_lessons) into a deterministic wall-clock-free memory, matches
OPEN hypotheses by family, and emits the demoted pure copies into the
ordinary pool (the upsert-by-id reducer applies them). Memory can
LOWER a priority — it never raises authority, never rewrites history,
never executes anything.
"""
from __future__ import annotations

import logging
from typing import Any

from webpent.researcher.memory import (
    compact_lessons,
    match_lessons,
    memory_demotion_lookup,
)

logger = logging.getLogger(__name__)

__all__ = ["research_memory_node"]


def _pool_of(state: Any) -> list[Any]:
    pool = state.get("hypotheses") if isinstance(state, dict) else None
    return list(pool) if isinstance(pool, (list, tuple)) else []


def research_memory_node(state: Any) -> dict[str, Any]:
    """Compact lessons, match the pool, emit demotion copies."""
    try:
        lessons = list(
            (state.get("research_lessons") if isinstance(state, dict) else None)
            or [])
        pool = _pool_of(state)
        memory = compact_lessons(lessons)
        hints = match_lessons(pool, memory, lessons)
        demotion_lookup = memory_demotion_lookup(pool, memory, lessons)
        matched = len(hints)
    except Exception as exc:  # noqa: BLE001 — advisory node, never fatal
        logger.warning("research memory failed (advisory node): %s", exc)
        return {
            "research_memory": {
                "built": False,
                "error": str(exc)[:200],
                "advisory_only": True,
            },
        }
    return {
        "research_memory": {
            "built": True,
            "advisory_only": True,
            "lesson_count": memory["total_lessons"],
            "matched_open_hypotheses": matched,
            "hints": hints,
            "demotion_lookup": demotion_lookup,
            "demotion_contract": (
                "ranking-time bonuses for rank_open_hypotheses("
                "novelty_lookup=...) — the pool's declared values are "
                "lifecycle-protected and are never mutated by memory"
            ),
            "by_class": memory["by_class"],
            "clock_policy": memory["clock_policy"],
            "influence_contract": (
                "memory can LOWER a research priority — never raise "
                "authority, never rewrite history, never execute"
            ),
        },
    }
