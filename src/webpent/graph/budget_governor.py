# src/webpent/graph/budget_governor.py
"""Step-budget governor for the engagement graph (R-B convergence).

Problem this module solves (proven live in the E2E pass, evidence
``e2e_chain_on.json``: ``status=terminated_recursion_limit`` on the
15-endpoint ground-truth surface):

Every backward/cycle edge in the graph is *individually* bounded
(optimizer retries <= 3, replan rounds <= 3, rabbit-hole loop-back <= 3,
chainer pairs deduped, controller runs bounded), but those bounds are
counted in *rounds*, not in *graph supersteps*.  The independent bounds
multiply on a large surface and the product exhausts
``settings.max_graph_steps`` before the graph reaches the reporting
tail; LangGraph aborts with ``GraphRecursionError`` and the worker
records ``terminated_recursion_limit``, parking every still-pending
candidate to Needs Human Review.  The engagement never reaches
cross-reasoning / executive summary / reflection.

Fix: a deterministic, centralized, two-tier **budget governor**.

1. ``node_step_trace`` observability — ``build_graph`` wraps every node
   so each execution appends one ``{"seq","node","under_pressure",..}``
   entry to the append-only ``node_step_trace`` state channel.  After a
   run you can PROVE where the budget went (previously unobservable).

2. Two reserves, derived from the worst-case forward paths in
   ``graph/builder.py``:

   * ``RESEARCH_RESERVE_STEPS = 24`` — research cutoff.  While
     ``remaining <= 24`` the *pre-evidence research loop*
     (autonomous_controller / recovery / knowledge_gap /
     research_session / active_research / causal_research /
     smart-campaigns replan) is cut: the remaining budget is spent
     validating what was already discovered instead of discovering
     more.  Worst forward path from these cuts is the strategist line
     (16 supersteps), leaving >= 8 supersteps of slack.

   * ``COMPLETION_RESERVE_STEPS = 19`` — completion cutoff.  While
     ``remaining <= 19`` EVERY optional re-entry is cut (optimizer
     retries, strategist replans, chainer loop-backs, rabbit-hole
     loop-backs, and the optional deep-probe/smart-campaign pre-tail
     entries).  All remaining edges then form a straight line to END:
     strategist -> payload_generator -> execution_sandbox -> validator
     -> devils_advocate (once) -> exploit_chainer -> post_exploitation
     -> rabbit_hole -> cvss_engine -> business_impact ->
     cross_reasoning -> executive_summary -> reporter -> reflection =
     16 supersteps <= 19, so the run cannot terminate via recursion
     limit after the cutoff — it converges with status ``completed``.

3. Router contract (all routers stay pure; the governor only decides
   routing): with the completion guard active each cycle-cutting router
   routes FORWARD.  With only the research guard active the research
   loop is cut and everything else behaves as before.

Authority preservation (hard contract): the governor NEVER confirms,
refutes, promotes, suppresses, or re-classifies a finding.  It only
skips *optional re-entries*.  Candidates that lose their retry slot
keep their honest Pending status and the existing fail-safe labels them
Needs Human Review.  Fresh evidence still flows forward through the
normal chain (validator -> devils_advocate -> ... -> reporter).

Fail-safe direction: if ``node_step_trace`` is missing (legacy
checkpoints), both guards deactivate and behavior is byte-identical to
the pre-governor graph.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Mapping
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "COMPLETION_RESERVE_STEPS",
    "GOVERNOR_VERSION",
    "RESEARCH_RESERVE_STEPS",
    "budget_pressure",
    "compute_step_budget",
    "completion_reserve_for",
    "max_graph_steps",
    "research_reserve_for",
    "steps_consumed",
    "steps_remaining",
    "trace_entry",
]

#: Bump when the reserve math or the router contract changes so run
#: evidence is self-describing. rb-3: Ultimate plan 2026-10-27,
#: proposal 2 — dynamic per-run budgets with proportional reserves
#: (floored at the rb-2 documented minima).
GOVERNOR_VERSION = "rb-3"

#: Completion cutoff (tier 2): while ``remaining <= 19`` every optional
#: re-entry is cut.  Worst forward path after a tier-2 cut is the
#: strategist line = 16 supersteps (margin 3).  Derived from the edge
#: map in ``graph/builder.py``; see module docstring for the chain.
COMPLETION_RESERVE_STEPS = 19

#: Research cutoff (tier 1): while ``remaining <= 24`` the pre-evidence
#: research loop is cut first, so the remaining budget is spent on the
#: evidence pipeline (validating already-discovered candidates) instead
#: of discovering more.  This is the "consume the budget converging"
#: law for large surfaces: explore while rich, validate while poor.
RESEARCH_RESERVE_STEPS = 24


def max_graph_steps() -> int:
    """Read the configured step budget (single source of truth)."""
    try:
        from webpent.config.settings import get_settings

        return max(1, int(getattr(get_settings(), "max_graph_steps", 50) or 50))
    except Exception:  # pragma: no cover - settings must exist in prod
        return 50


# ---------------------------------------------------------------------------
# Ultimate plan 2026-10-27, proposal 2 — dynamic step budget.
#
# The flat ``max_graph_steps`` ceiling stays as the fallback (and as the
# budget when ``enable_dynamic_step_budget`` is off). When the sizing
# node measures the surface, ``compute_step_budget`` derives a per-run
# budget from the measurement, always clamped by the hard cap and the
# cost ceiling — never a blind raise of the number.
# ---------------------------------------------------------------------------

#: Baseline steps every run gets regardless of surface size (small
#: targets must keep the full legacy experience).
_BASE_STEPS = 50

#: Additional steps per measured surface unit (endpoint/form/parameter).
#: 50 + 200 endpoints x 1.0 = 250 — a mid-size app gets 5x the legacy
#: ceiling, which is the historical GraphRecursionError fixpoint scaled.
_STEPS_PER_SURFACE_UNIT = 1.0


def compute_step_budget(
    surface_size: int,
    *,
    time_budget_s: int | None = None,
    cost_ceiling_usd: float | None = None,
    hard_cap: int | None = None,
) -> int:
    """Derive the per-run step budget from the measured surface size.

    Ultimate plan, proposal 2 (unit-tested contract):

    * ``budget = BASE + surface_size x STEPS_PER_SURFACE_UNIT``
    * clamped to ``min(budget, dynamic_step_budget_cap)`` — the hard
      cap from settings (default 400), overridable per call for tests,
    * further clamped by the cost ceiling when given: no run may
      budget more steps than 40 steps per remaining USD (the empirical
      worst-case superstep cost documented in the hunt budgets),
    * floored at ``max_graph_steps()`` — a dynamic budget is never
      SMALLER than the legacy flat ceiling (sizing must only ever
      ADD exploration room for big targets, never quietly shrink
      small ones).

    Pure function; no I/O; no state reads.
    """
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        cap = int(hard_cap or settings.dynamic_step_budget_cap)
        flat = max(1, int(getattr(settings, "max_graph_steps", 50) or 50))
    except Exception:  # pragma: no cover - settings must exist in prod
        cap = int(hard_cap or 400)
        flat = 50
    computed = _BASE_STEPS + max(0, int(surface_size)) * _STEPS_PER_SURFACE_UNIT
    budget = min(computed, cap)
    if cost_ceiling_usd is not None and cost_ceiling_usd > 0:
        # 40 supersteps per remaining USD — the conservative empirical
        # worst case so a $1 quick pass can never budget a $10 walk.
        cost_bound = int(cost_ceiling_usd * 40)
        budget = min(budget, max(flat, cost_bound))
    return max(flat, int(budget))


def completion_reserve_for(budget: int) -> int:
    """Tier-2 reserve as a function of the ACTIVE budget (>= 19).

    12% of the budget per the plan, floored at the rb-2 documented
    minimum (19 supersteps — the proven worst forward path from a
    completion cutoff). For the flat 50-step budget this returns 19,
    byte-identical to the pre-plan constant.
    """
    return max(COMPLETION_RESERVE_STEPS, math.ceil(int(budget) * 0.12))


def research_reserve_for(budget: int) -> int:
    """Tier-1 reserve as a function of the ACTIVE budget (>= 24).

    15% per the plan, floored at the documented 24-superstep minimum.
    For the flat 50-step budget this returns 24 — byte-identical to
    the pre-plan constant.
    """
    return max(RESEARCH_RESERVE_STEPS, math.ceil(int(budget) * 0.15))


def _active_budget(state: Mapping[str, Any]) -> int:
    """The run's effective step budget: dynamic when sized, else flat."""
    dynamic = state.get("dynamic_step_budget") if isinstance(state, Mapping) else None
    try:
        dynamic = int(dynamic) if dynamic else 0
    except (TypeError, ValueError):
        dynamic = 0
    if dynamic > 0:
        # The sizing node already clamped by cap/cost; still clamp the
        # ceiling here as defense in depth.
        return min(dynamic, max(max_graph_steps(), 4000))
    return max_graph_steps()


def steps_consumed(state: Mapping[str, Any]) -> int:
    """Number of node executions already recorded for this run."""
    trace = state.get("node_step_trace")
    if not isinstance(trace, (list, tuple)):
        return 0
    return len(trace)


def steps_remaining(state: Mapping[str, Any]) -> int:
    """Effective budget minus consumed steps (floor 0).

    Ultimate plan, proposal 2: the effective budget is the run's
    dynamic_step_budget when the sizing node computed one, else the
    flat max_graph_steps ceiling (legacy behavior).
    """
    return max(0, _active_budget(state) - steps_consumed(state))


def budget_pressure(state: Mapping[str, Any]) -> dict[str, Any]:
    """Pure, deterministic two-tier pressure guard.

    Returns a JSON-safe dict::

        {"active": bool,           # tier-2 completion cutoff
         "research_active": bool,  # tier-1 research cutoff
         "consumed": int, "max_steps": int, "remaining": int,
         "reserve": int, "research_reserve": int, "version": str,
         "reason": "completion_cutoff" | "research_cutoff" | "inactive"
                   | "inactive_no_trace"}

    Contract honored by the cycle-cutting routers in
    ``graph/builder.py``:

    * ``active=True``          -> cut ALL optional re-entries, route
      forward (straight line to END, <= 16 supersteps).
    * ``research_active=True`` -> cut the pre-evidence research loop
      only (controller / recovery / research-session chain and the
      smart-campaigns replan edge).
    * both False               -> behave exactly as before this module.

    The function NEVER mutates state and NEVER reads or writes findings;
    it cannot promote, refute, or suppress anything.
    """
    max_steps = _active_budget(state)
    completion_reserve = completion_reserve_for(max_steps)
    research_reserve = research_reserve_for(max_steps)
    trace = state.get("node_step_trace")
    if not isinstance(trace, (list, tuple)):
        # UM-DR-33 §5.3 (Workstream C, external hard budgets): the trace
        # channel is declared append-only (state.py) and no legit write
        # path ever persists a non-list (builder.py materialises
        # ``update["node_step_trace"] = [entry]`` whenever the previous
        # value is not a list). A key that is PRESENT but not a list is
        # therefore agent-side corruption, and corruption must never
        # RESET consumed budget: fail closed with the budget fully
        # consumed (both cutoffs engaged, nothing left to spend). Only a
        # genuinely ABSENT key keeps the documented legacy-checkpoint
        # behaviour (pre-governor fail-safe deactivation).
        if "node_step_trace" in state:
            return {
                "active": True,
                "research_active": False,
                "consumed": max_steps,
                "max_steps": max_steps,
                "remaining": 0,
                "reserve": completion_reserve,
                "research_reserve": research_reserve,
                "version": GOVERNOR_VERSION,
                "reason": "fail_closed_corrupted_trace",
            }
        # Legacy checkpoint without the trace channel: deactivate (the
        # pre-governor behavior is the fail-safe default).
        return {
            "active": False,
            "research_active": False,
            "consumed": 0,
            "max_steps": max_steps,
            "remaining": max_steps,
            "reserve": completion_reserve,
            "research_reserve": research_reserve,
            "version": GOVERNOR_VERSION,
            "reason": "inactive_no_trace",
        }
    consumed = len(trace)
    remaining = max(0, max_steps - consumed)
    completion_active = remaining <= completion_reserve
    research_active = remaining <= research_reserve
    if completion_active:
        reason = "completion_cutoff"
    elif research_active:
        reason = "research_cutoff"
    else:
        reason = "inactive"
    return {
        "active": completion_active,
        "research_active": research_active,
        "consumed": consumed,
        "max_steps": max_steps,
        "remaining": remaining,
        "reserve": completion_reserve,
        "research_reserve": research_reserve,
        "version": GOVERNOR_VERSION,
        "reason": reason,
    }


def trace_entry(
    state: Mapping[str, Any],
    node_name: str,
) -> dict[str, Any]:
    """Build one append-only step-trace entry (used by the builder wrapper).

    The entry records the node name, its 0-based sequence position, and
    whether the completion/research guards were active when the node was
    entered (i.e. the routing decision that led here was made under
    that guard).
    """
    pressure = budget_pressure(state)
    return {
        "seq": int(pressure["consumed"]),
        "node": str(node_name),
        "remaining_after_entering": max(0, int(pressure["remaining"]) - 1),
        "under_pressure": bool(pressure["active"]),
        "under_research_pressure": bool(pressure["research_active"]),
        "governor": GOVERNOR_VERSION,
    }
