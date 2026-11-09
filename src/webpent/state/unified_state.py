# src/webpent/state/unified_state.py
"""UnifiedState — the superset campaign state for the unified hunt engine.

Ultimate plan 2026-10-27, proposal 1 (Engine Unification):

The pre-plan tree ran two engine families with two state shapes:

* ``PentestState`` (``state/state.py``) — the 80+ node LangGraph pipeline
  used by the unified ``hunt`` command (planner → auth → recon → crawler
  → … → reflection), with Annotated reducer channels (``merge_findings``,
  ``merge_dicts``, ``merge_lists`` …).
* ``HunterGraphState`` (``agents/hunter_graph.py``) — the bounded Agent
  Evolution hunter (library API since the v0.32.0 removal of the retired
  ``hunt-auto`` CLI alias), with its own
  budget fields (``max_hypotheses``, ``max_decisions``, ``max_llm_calls``,
  ``max_cost_usd``) and persona field.

The unified ``webpent hunt --mode quick|standard|deep`` command runs the
production graph (the deep, mature engine) while accepting the hunter's
budget-shaped options, so callers of both legacy commands get one entry
point. ``UnifiedState`` is the typed superset that makes that possible
without breaking either side:

* It re-uses ``PentestState`` as its base (same reducers, same channel
  names), so every existing node, checkpoint, and test keeps working —
  a unified-run state IS a PentestState with extra optional keys.
* The hunter-family fields are declared here (not in hunter_graph) so
  the bridge (``adapters/legacy_state_bridge.py``) can map an old
  HunterGraphState into this shape losslessly.
* The Ultimate-plan additions (lesson consultation outputs, surface
  metrics, the dynamic step budget, detector results) live here too,
  next to their reducers, with the same merge semantics as the parent.

This module owns ONLY the typed dict and the mode presets. The actual
graph node implementations live in ``graph/lesson_nodes.py``,
``graph/surface_sizing.py`` and ``graph/detector_nodes.py``; the CLI
entry point is ``cli/unified_hunt.py``.
"""

from __future__ import annotations

from typing import Any

from webpent.state.state import PentestState

# ---------------------------------------------------------------------------
# Mode presets (proposal 1, phase 4: "أمر واحد بأوضاع مدروسة").
#
# Budgets are deliberately conservative and DOCUMENTED — they are the
# starting point of a run, not its ceiling: when the dynamic step budget
# (proposal 2) is enabled the step figure is re-derived from the measured
# surface after crawling, always clamped to dynamic_step_budget_cap and
# the cost ceiling.
# ---------------------------------------------------------------------------

HUNT_MODES: frozenset[str] = frozenset({"quick", "standard", "deep"})

HUNT_MODE_PRESETS: dict[str, dict[str, Any]] = {
    "quick": {
        # Small surface, minutes-scale run: the flat legacy ceiling is
        # already more than a quick pass needs; the deterministic path
        # with no LLM is the expected configuration here.
        "time_budget_s": 15 * 60,
        "request_budget": 500,
        "llm_budget_usd": 1.0,
        "max_hypotheses": 6,
        "max_llm_calls": 15,
        "surface_probe_depth": "light",
        "_doc": "فحص سريع، تقرير في دقائق — سقف تكلفة ليمت وخطوات قليلة",
    },
    "standard": {
        # The recommended default: balanced depth vs cost. Same request
        # budget family as the legacy scan default (1000) with a
        # meaningful-but-bounded LLM allowance.
        "time_budget_s": 60 * 60,
        "request_budget": 1000,
        "llm_budget_usd": 5.0,
        "max_hypotheses": 12,
        "max_llm_calls": 40,
        "surface_probe_depth": "balanced",
        "_doc": "فحص عميق متوازن — الافتراضي الموصى به",
    },
    "deep": {
        # Large surfaces: the whole point of the dynamic budget. The
        # step figure is irrelevant once surface sizing runs (proposal 2
        # derives it); the cost ceiling is the real governor.
        "time_budget_s": 6 * 60 * 60,
        "request_budget": 10000,
        "llm_budget_usd": 25.0,
        "max_hypotheses": 40,
        "max_llm_calls": 200,
        "surface_probe_depth": "exhaustive",
        "_doc": "فحص شامل طويل لتطبيق كبير — الميزانية الديناميكية تاخد حقها",
    },
}


def resolve_hunt_mode(mode: str | None) -> dict[str, Any]:
    """Return the preset for ``mode`` (default: standard).

    Unknown modes raise ``ValueError`` listing the accepted set — the
    CLI surfaces the same message to the operator.
    """
    resolved = (mode or "standard").strip().lower()
    if resolved not in HUNT_MODES:
        raise ValueError(
            f"unknown hunt mode {mode!r} — accepted modes: "
            f"{', '.join(sorted(HUNT_MODES))}"
        )
    preset = dict(HUNT_MODE_PRESETS[resolved])
    preset.pop("_doc", None)
    preset["mode"] = resolved
    return preset


class UnifiedState(PentestState, total=False):
    """Typed superset of PentestState + HunterGraphState + plan fields.

    ``total=False`` (inherited) means every key is optional — a legacy
    PentestState checkpoint is a valid UnifiedState by construction,
    which is what keeps resumability intact across the transition.

    Hunter-family fields (mapped by ``adapters/legacy_state_bridge``):
    """

    # --- HunterGraphState superset (hunter family) --------------------
    max_hypotheses: int
    max_decisions: int
    max_llm_calls: int
    max_cost_usd: float
    persona: str
    llm_calls_used: int
    cost_spent_usd: float
    decisions: list[dict[str, Any]]

    # --- Ultimate plan, proposal 2 (dynamic budget) ----------------------
    # NOTE (M1b, CANONICAL_PHASE_REGISTRY): ``surface_metrics`` and
    # ``dynamic_step_budget`` are DECLARED ONCE on PentestState — the
    # re-declarations below previously SHADOWED the parent's
    # ``Annotated[..., merge_dicts]`` channel with a plain dict, silently
    # dropping the merge reducer in unified runs (concurrent writes
    # overwrote instead of merging; caught by
    # tests/test_m1b_domain_contracts.py::test_unified_state_is_a_
    # structural_superset_of_pentest_state). The duplicates are gone;
    # the channel semantics live on the parent declaration.
    #: Measured surface metrics written by the surface-sizing node:
    #: {"endpoints": int, "forms": int, "parameters": int,
    #:  "graphql_operations": int, "surface_size": int}
    # surface_metrics — see PentestState (Annotated[..., merge_dicts]).
    #: The per-run step budget derived from the surface metrics. When
    #: absent (legacy checkpoints / dynamic budget disabled) the flat
    #: settings.max_graph_steps ceiling applies unchanged.
    dynamic_step_budget: int

    # --- Ultimate plan, proposal 3 (closed-loop learning) ----------------
    # NOTE (M1b): ``consulted_lessons``, ``lesson_priority_adjustments``
    # and ``extracted_lessons`` are likewise declared ONCE on PentestState
    # with their merge reducers; the plain re-declarations that shadowed
    # them were removed with the same regression as ``surface_metrics``.
    #: Advisory lesson summaries consulted after planning. Bounded list
    #: of redacted, decision-level dicts — NEVER raw payload content and
    #: NEVER treated as executable instructions (README trust boundary).
    # consulted_lessons — see PentestState (Annotated[..., merge_lists]).
    #: Priority adjustments returned by consult_lessons, keyed for the
    #: hypothesis/payload nodes to read as advisory context.
    # lesson_priority_adjustments — see PentestState (merge_dicts).
    #: Lessons extracted from THIS campaign at reflection time.
    # extracted_lessons — see PentestState (Annotated[..., merge_lists]).

    # --- Ultimate plan, proposal 7 (new detectors) -----------------------
    #: Deterministic ValidationResults from the new detector nodes
    #: (GraphQL / cache poisoning / prototype pollution / OAuth), as
    #: JSON-safe dicts with the validator's outcome + evidence quality.
    # detector_results — see PentestState (Annotated[..., merge_lists]).
