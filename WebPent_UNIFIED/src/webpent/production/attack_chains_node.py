"""UM-DR-46 Phase D — the attack-chain production node.

Wires the cross-feature attack reasoning (researcher/attack_chains.py)
into the graph AFTER the appmodel node and BEFORE the researcher-brain
node: composes the SKG's evidence-backed facts into multi-step chain
candidates and emits ONE canonical hypothesis per chain into the
ORDINARY pool (same strategist ranking, same promotion gates).

Hard limits: no network I/O, no lifecycle authority, never a finding
or confirmation, never bypasses CausalGuard / ProofBundle / Replay.
"""
from __future__ import annotations

import logging
from typing import Any

from webpent.appmodel.skg import build_security_knowledge_graph
from webpent.researcher.attack_chains import (
    chain_hypotheses,
    compose_attack_chains,
    summarize_chains,
)

logger = logging.getLogger(__name__)

__all__ = ["attack_chain_node"]


def _get(state: Any, key: str) -> Any:
    if isinstance(state, dict):
        return state.get(key)
    return getattr(state, key, None)


def attack_chain_node(state: Any) -> dict[str, Any]:
    """Compose the SKG into cross-feature attack-chain candidates."""
    try:
        model = build_security_knowledge_graph(state)
    except Exception as exc:  # noqa: BLE001 — advisory node, never fatal
        logger.warning("attack chain construction failed (advisory): %s", exc)
        return {
            "attack_chains": [],
            "attack_chain_summary": {
                "built": False,
                "error": str(exc)[:200],
                "advisory_only": True,
            },
            "hypotheses": [],
        }

    chains = compose_attack_chains(model)
    hypotheses = chain_hypotheses(model, str(_get(state, "target_url") or ""))
    summary = summarize_chains(model)
    summary.update({
        "built": True,
        "influence_contract": (
            "advisory for research prioritization only — never authorizes, "
            "never confirms, never bypasses CausalGuard/ProofBundle/Replay"
        ),
    })
    return {
        "attack_chains": chains,
        "attack_chain_summary": summary,
        "hypotheses": hypotheses,
    }
