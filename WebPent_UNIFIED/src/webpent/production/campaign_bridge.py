"""Wave 3 — the CAMPAIGN bridge: the strategist meets the orchestrator.

After an AUTONOMOUS VALIDATION CAMPAIGN completes, its result is a
body of evidence nobody has turned into a plan. This bridge does
exactly that, and nothing more: it adapts the result into an oracle
view, builds a thesis, plans phases, and registers the brief as
PENDING for the operator.

The operator-sovereignty line (the tool's laws): the bridge holds
NO approval code path — a machine cannot sanction its own campaign.
Where the operator HAS ruled on a brief for the target, the bridge
surfaces the approved plan as advisory guidance for the next
dispatch. That surface fails open: it gates nothing, and a missing
store or a thin result is a typed blocker recorded in the block,
never an exception into a completed campaign.

Zero getattr (direct-I/O inventory discipline), zero network,
advisory only.
"""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from webpent.campaign.errors import (
    CampaignError,
)
from webpent.campaign.schemas import (
    CampaignBudget,
    Decision,
)
from webpent.campaign.storage.campaign_store import CampaignStore
from webpent.campaign.strategist.handoff import OperatorHandoff
from webpent.campaign.strategist.phase_planner import (
    PhasePlanner,
)
from webpent.campaign.strategist.thesis_builder import (
    ThesisBuilder,
)

CAMPAIGN_BRIDGE_VERSION = "campaign_bridge_v1"

# Operator-scale defaults for an operator-ruling-sized campaign.
# These are caps the operator can revise on the brief before any
# phase runs; the machine never raises them.
DEFAULT_MAX_REQUESTS = 400
DEFAULT_MAX_TIME_MINUTES = 60
DEFAULT_MAX_LLM_CALLS = 40

_ENV_STORE = "WEBPENT_CAMPAIGN_STORE"
_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_STORE_DIR = _REPO_ROOT / "campaign-workspace"

# The wiring's guard surface: everything the advisory calls can
# realistically raise (store I/O, JSON round-trip, schema drift).
# Deliberately enumerated — the P-1 hygiene rule forbids a broad
# `except Exception` in the spine, and the bridge never needs one.
BRIDGE_GUARD: tuple[type[BaseException], ...] = (
    OSError,
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    AttributeError,
)

_NO_STORE_BLOCKER = (
    "campaign store not configured "
    "(set WEBPENT_CAMPAIGN_STORE to the operator's brief directory)")


def _store_configured(store: Any) -> bool:
    """The bridge is off unless an operator points it at a brief
    directory: an explicit store, or the environment variable. The
    default-write behaviour of shipping files into the tree during
    ordinary dispatches is exactly what the tool's laws forbid."""
    return store is not None or bool(os.environ.get(_ENV_STORE))


class CampaignBridge:
    """Typed adapter surface; module-level functions below delegate
    here so tests and callers can pin one configured instance."""

    version = CAMPAIGN_BRIDGE_VERSION


def _resolve_store(store: Any) -> CampaignStore:
    """Accept a CampaignStore, a directory path, or None (env var,
    then the workspace default)."""
    if isinstance(store, CampaignStore):
        return store
    if isinstance(store, (str, Path)):
        return CampaignStore(Path(store))
    return CampaignStore(Path(os.environ.get(_ENV_STORE,
                                             _DEFAULT_STORE_DIR)))


class OracleView:
    """The strategist's oracle protocol, seen through one AVI
    result. Every field degrades to empty: the thesis builder owns
    the evidence floor, not this adapter."""

    def __init__(self, avi_result: dict) -> None:
        source = avi_result if isinstance(avi_result, dict) else {}
        tech = source.get("tech_stack") or {}
        self.tech_stack: dict = dict(tech) if isinstance(tech, dict) \
            else {}
        self.subdomains: tuple[str, ...] = tuple(
            source.get("subdomains") or ())
        self.historical_endpoints: tuple[str, ...] = tuple(
            source.get("historical_endpoints") or ())
        self.leaked_signals: tuple[dict, ...] = tuple(
            source.get("leaked_signals") or ())
        self.crown_jewel_hints: tuple[dict, ...] = tuple(
            source.get("crown_jewel_hints") or ())


class _UnscoredEconomist(SimpleNamespace):
    """The honest absence of an economist signal: the evidence piece
    reports exactly that (tier unscored, payout 0.0) rather than a
    fabricated number. The LIKELY_FLOOR still rules."""

    tier = "unscored"
    payout_potential = 0.0


def _plan_block(brief) -> dict:
    return {
        "campaign_id": brief.campaign_id,
        "decision": brief.decision.value.upper(),
        "families": [family.value for family, _score
                     in (brief.thesis.likely_vuln_families
                         if brief.thesis else [])],
        "phases": [
            {"order": phase.order,
             "goal": phase.goal,
             "max_requests": phase.budget.max_requests}
            for phase in brief.phases
        ],
    }


def campaign_advisory_brief(avi_result: dict, target_url: str,
                            store: Any = None, patterns=None,
                            economist: Any = None) -> dict:
    """Turn one completed AVI result into a PENDING operator brief.

    Returns a structured block either way: registered (with the
    campaign_id) or a typed blocker. Never raises into the caller.
    """
    block: dict = {"bridge": CAMPAIGN_BRIDGE_VERSION,
                   "target_id": target_url}
    if not _store_configured(store):
        return dict(block, registered=False, blocker=_NO_STORE_BLOCKER)
    try:
        thesis = ThesisBuilder().build(
            target_url,
            OracleView(avi_result),
            list(patterns or []),
            economist or _UnscoredEconomist(),
        )
        budget = CampaignBudget(
            max_requests=DEFAULT_MAX_REQUESTS,
            max_time_minutes=DEFAULT_MAX_TIME_MINUTES,
            max_llm_calls=DEFAULT_MAX_LLM_CALLS,
        )
        phases = PhasePlanner().plan(thesis, budget)
        brief = OperatorHandoff(store=_resolve_store(store)).present(
            thesis, phases, budget)
    except CampaignError as exc:
        return dict(block, registered=False, blocker=str(exc))
    plan = _plan_block(brief)
    return dict(block, registered=True,
                campaign_id=brief.campaign_id,
                decision=plan["decision"],
                families=plan["families"],
                phases=len(plan["phases"]))


def approved_plan_for(target_url: str, store: Any = None) -> dict:
    """If the operator has ruled a brief for this target, surface
    the plan as advisory guidance. Fail-open: no ruling is a
    recorded reason, not an error."""
    if not _store_configured(store):
        return {"bridge": CAMPAIGN_BRIDGE_VERSION, "attached": False,
                "reason": "campaign_store_not_configured"}
    resolved = _resolve_store(store)
    candidates = [
        brief for brief in resolved.list_briefs()
        if brief.thesis is not None
        and brief.thesis.target_id == target_url
        and brief.decision is Decision.APPROVED
    ]
    if not candidates:
        return {"bridge": CAMPAIGN_BRIDGE_VERSION, "attached": False,
                "reason": "no_approved_brief"}
    latest = max(candidates, key=lambda brief: brief.created_at)
    return {"bridge": CAMPAIGN_BRIDGE_VERSION, "attached": True,
            "plan": _plan_block(latest)}
