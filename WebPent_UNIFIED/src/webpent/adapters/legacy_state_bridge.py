# src/webpent/adapters/legacy_state_bridge.py
"""Loss-free state bridging between the two legacy engine families.

Ultimate plan 2026-10-27, proposal 1 (Engine Unification), phase 2:

The project has real campaigns with real checkpoints in both state
shapes. The unified engine must not break either: a campaign resumed
under ``webpent hunt`` has to load a legacy ``PentestState`` checkpoint
unchanged, and a caller migrating from the bounded hunter (the retired
``hunt-auto`` CLI alias, removed in v0.32.0 — the runtime itself lives
on as the ``webpent.autonomous`` library API) should be able to
carry their HunterGraphState-shaped inputs (budgets, persona) into the
unified run.

This module is deliberately boring: pure functions, no I/O, no network,
no LLM. Every mapping is documented and every dropped-key decision is
explicit. Nothing here ever mutates its inputs.

Mapping contracts:

* ``pentest_state_to_unified`` — identity-plus: a PentestState IS a
  UnifiedState (superset TypedDict, total=False); the function only
  adds the hunt-mode preset fields on top, never rewriting existing
  keys (preset values are skipped for any key already present, so a
  resumed campaign keeps its own budgets).
* ``hunter_state_to_unified`` — maps the hunter-family budget/persona
  fields onto the unified shape and carries over the shared channel
  names (findings, hypotheses, messages) verbatim. Hunter-only fields
  with no unified equivalent are recorded in ``_hunter_legacy_fields``
  for provenance instead of being silently dropped.
* ``unified_to_pentest_state`` — strips the unified-only keys so the
  result can be handed to code typed against the narrower PentestState
  (the graph schema accepts the superset anyway, but explicit is
  better than implicit for checkpoint round-trips).
"""

from __future__ import annotations

from typing import Any, Mapping

from webpent.state.unified_state import resolve_hunt_mode

#: HunterGraphState fields with no unified equivalent — kept verbatim
#: under ``_hunter_legacy_fields`` so nothing is lost in the crossing.
_HUNTER_ONLY_FIELDS: tuple[str, ...] = (
    "hunter_decisions",
    "hunter_memory",
    "hunt_artifact_root",
)

#: Unified-only keys that must not leak into a narrowed PentestState.
_UNIFIED_ONLY_FIELDS: tuple[str, ...] = (
    "max_hypotheses",
    "max_decisions",
    "max_llm_calls",
    "max_cost_usd",
    "persona",
    "llm_calls_used",
    "cost_spent_usd",
    "decisions",
    "surface_metrics",
    "dynamic_step_budget",
    "consulted_lessons",
    "lesson_priority_adjustments",
    "extracted_lessons",
    "detector_results",
)


def pentest_state_to_unified(
    state: Mapping[str, Any],
    *,
    mode: str | None = "standard",
) -> dict[str, Any]:
    """Lift a PentestState (or a legacy checkpoint dict) into UnifiedState.

    Existing keys are NEVER overwritten: the mode preset only fills
    budget fields the state does not already carry, so a resumed
    campaign keeps its own numbers. Returns a NEW dict.
    """
    unified: dict[str, Any] = dict(state)
    preset = resolve_hunt_mode(mode)
    for key, value in preset.items():
        if key == "mode":
            continue
        if key not in unified or unified[key] is None:
            unified[key] = value
    return unified


def hunter_state_to_unified(
    state: Mapping[str, Any],
) -> dict[str, Any]:
    """Map a HunterGraphState-shaped dict into the unified shape.

    Shared channels (findings, hypotheses, messages, crawled_data …)
    pass through verbatim — same names on both sides by design. The
    hunter budget/persona fields map 1:1 onto their unified
    declarations. Hunter-only fields are preserved under
    ``_hunter_legacy_fields`` (a list of (name, value) pairs) for
    provenance and round-tripping.
    """
    unified: dict[str, Any] = {}
    legacy: list[tuple[str, Any]] = []
    for key, value in state.items():
        if key in _HUNTER_ONLY_FIELDS:
            legacy.append((key, value))
            continue
        unified[key] = value
    if legacy:
        unified["_hunter_legacy_fields"] = legacy
    # Hunter runs are budget-shaped by construction; mirror the budget
    # fields onto their unified names when the caller used the hunter
    # spellings (the bounded hunter's state keys) so downstream budget
    # checks see one canonical shape.
    budget_aliases: tuple[tuple[str, str], ...] = (
        ("max_llm_calls", "max_llm_calls"),
        ("max_cost_usd", "max_cost_usd"),
    )
    for hunter_key, unified_key in budget_aliases:
        if hunter_key in state and unified_key not in unified:
            unified[unified_key] = state[hunter_key]
    return unified


def unified_to_pentest_state(
    state: Mapping[str, Any],
) -> dict[str, Any]:
    """Narrow a UnifiedState back to the PentestState key set.

    Used when handing a unified run's state to code typed against the
    narrower dict (e.g. legacy workers). The unified-only keys are
    dropped — they are advisory/derived and every one of them is
    reconstructible (surface sizing, lesson consultation) or pure
    budget bookkeeping.
    """
    return {
        key: value
        for key, value in state.items()
        if key not in _UNIFIED_ONLY_FIELDS and key != "_hunter_legacy_fields"
    }
