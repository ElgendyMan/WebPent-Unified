"""Multi-agent swarm mode (v82, Layer 3 / Task 9).

A deterministic, bounded coordinator that runs the hunt as a sequence of
specialized role passes under one central brain (the existing orchestrator):

* Scout: merges recon-amplifier leads into advisory discovery candidates,
* Striker: prioritizes execution candidates on still-unexplored, in-scope
  endpoints,
* Philosopher: surfaces business-logic chains by pairing a proven class
  with an untested neighbor endpoint,
* Skeptic: flags which candidates deserve self-adversarial checks,
* Scribe: assembles the round summary.

Each role is a pure function over a state-like mapping; the coordinator
runs them in a fixed order per round with hard round bounds. There are no
threads, no processes, and no new execution authority: a role that raises
is skipped (recorded in ``errors``), never fatal. This is "swarm" as a
disciplined relay, not as free-floating concurrency — the determinism is
the point.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

MAX_ROUNDS = 4
MAX_ITEMS_PER_ROLE = 8

ROLE_ORDER: tuple[str, ...] = ("scout", "striker", "philosopher", "skeptic", "scribe")

RoleFn = Callable[[dict[str, Any]], dict[str, Any]]


def role_scout(state: dict[str, Any]) -> dict[str, Any]:
    """Collect advisory leads from recon amplifiers into one inbox."""
    amplifiers = state.get("amplifier_reports") or {}
    leads: list[dict[str, Any]] = []
    for source in ("takeover", "cloud_storage", "wayback", "js_analyzer", "ct_mining"):
        report = amplifiers.get(source)
        if not isinstance(report, dict):
            continue
        for key in ("candidates", "open_candidates"):
            for item in report.get(key, []) or []:
                if isinstance(item, dict):
                    fields = {
                        k: item.get(k)
                        for k in ("host", "path", "subdomain", "url", "service", "verdict")
                        if item.get(k) is not None
                    }
                    leads.append({"source": source, **fields})
    return {"role": "scout", "inbox": leads[:MAX_ITEMS_PER_ROLE]}


def role_striker(state: dict[str, Any]) -> dict[str, Any]:
    """Rank unexplored in-scope endpoints as execution candidates."""
    explored = set(state.get("explored_endpoints") or [])
    endpoints = [
        str(item) for item in (state.get("known_endpoints") or [])[:MAX_ITEMS_PER_ROLE * 4]
        if str(item) not in explored
    ]
    return {"role": "striker", "candidates": endpoints[:MAX_ITEMS_PER_ROLE]}


def role_philosopher(state: dict[str, Any]) -> dict[str, Any]:
    """Pair a proven class with an untested endpoint: a chain lead."""
    proven = state.get("proven_classes") or []
    untested = role_striker(state).get("candidates", [])
    chains = [
        {"chain": f"{redact(str(c))[:60]} x {redact(str(ep))[:120]}", "advisory": True}
        for c in proven[:2]
        for ep in untested[:2]
    ]
    return {"role": "philosopher", "chains": chains[:MAX_ITEMS_PER_ROLE]}


def role_skeptic(state: dict[str, Any]) -> dict[str, Any]:
    """Name the candidates that deserve self-adversarial validation."""
    candidates = (state.get("verify_candidates") or [])[:MAX_ITEMS_PER_ROLE]
    return {"role": "skeptic", "to_validate": [str(c)[:200] for c in candidates]}


def role_scribe(state: dict[str, Any]) -> dict[str, Any]:
    """Assemble the round summary from the other roles' outputs."""
    outputs = state.get("role_outputs") or {}
    summary = {
        "leads": len((outputs.get("scout") or {}).get("inbox", [])),
        "execution_candidates": len((outputs.get("striker") or {}).get("candidates", [])),
        "chains": len((outputs.get("philosopher") or {}).get("chains", [])),
        "to_validate": len((outputs.get("skeptic") or {}).get("to_validate", [])),
    }
    return {"role": "scribe", "summary": summary}


_ROLE_FUNCTIONS: dict[str, RoleFn] = {
    "scout": role_scout,
    "striker": role_striker,
    "philosopher": role_philosopher,
    "skeptic": role_skeptic,
    "scribe": role_scribe,
}


def _role_fn(role: str) -> RoleFn:
    """Resolve a role function at call time (module globals), so a
    replaced function propagates and stays overridable."""
    fn = globals().get(f"role_{role}")
    assert callable(fn)
    return fn


def run_swarm_round(state: dict[str, Any]) -> dict[str, Any]:
    """One deterministic relay round: every role in fixed order.

    A failing role is recorded and skipped; the round never raises.
    """
    outputs: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for role in ROLE_ORDER:
        fn = _role_fn(role)
        # Each role sees the outputs of the roles before it (scribe last).
        state["role_outputs"] = outputs
        try:
            outputs[role] = fn(state)
        except Exception as exc:  # a role failure must never break the round
            errors[role] = f"{type(exc).__name__}: {redact(str(exc))[:120]}"
            _LOG.warning("swarm role %s failed: %s", role, errors[role])
    return {"round": {"outputs": outputs, "errors": errors}, "advisory": True}


def run_swarm(initial_state: dict[str, Any], *, rounds: int = MAX_ROUNDS) -> dict[str, Any]:
    """Run bounded swarm rounds; each round's scribe summary is kept."""
    rounds = max(1, min(MAX_ROUNDS, int(rounds)))
    state = dict(initial_state or {})
    history: list[dict[str, Any]] = []
    for round_index in range(rounds):
        result = run_swarm_round(state)
        history.append({"round_index": round_index, **result["round"]})
        # Deterministic relay: the scribe summary feeds the next round's
        # inputs (e.g. explored endpoints can grow between rounds via the
        # caller-provided state update hooks; here it stays read-only).
    return {"rounds": history, "advisory": True}
