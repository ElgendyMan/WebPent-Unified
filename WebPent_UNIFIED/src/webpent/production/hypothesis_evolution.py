"""UM-DR-46 Phase C — the hypothesis-evolution production node.

Wires the adaptive hypothesis engine (researcher/evolution.py) into
the graph: consumes the CURRENT hypothesis pool, and for every
RESOLVED_FALSE (refuted) hypothesis it (a) emits deterministic
mutations and SKG-grounded competitors as ORDINARY canonical
hypotheses, (b) records a deterministic negative-evidence lesson and
decays the related open hypotheses (via the upsert-by-id reducer), and
(c) publishes the info-gain selection as an advisory priority channel.

Hard limits: no network I/O, no lifecycle authority (never
promotes/confirms/closes), never bypasses CausalGuard / ProofBundle /
Replay. Pool additions flow through ``merge_hypotheses`` — the same
strategist ranking, the same promotion gates.
"""
from __future__ import annotations

import logging
from typing import Any

from webpent.appmodel.skg import build_security_knowledge_graph
from webpent.researcher.evolution import (
    competing_hypotheses,
    learn_from_negative_evidence,
    mutate_hypothesis,
    select_by_info_gain,
)

logger = logging.getLogger(__name__)

__all__ = ["hypothesis_evolution_node"]

_MAX_REFUTED_PER_PASS = 4
_MAX_PRIORITY_IDS = 12


def _pool_of(state: Any) -> list[Any]:
    pool = state.get("hypotheses") if isinstance(state, dict) else None
    return list(pool) if isinstance(pool, (list, tuple)) else []


def _status_of(hyp: Any) -> str:
    raw = str(getattr(hyp, "status", ""))
    return raw.split(".")[-1] if raw.startswith("HypothesisStatus.") else raw


def hypothesis_evolution_node(state: Any) -> dict[str, Any]:
    """Run the deterministic evolution over the current pool."""
    pool = _pool_of(state)
    refuted = [
        hyp for hyp in pool if _status_of(hyp) == "resolved_false"
    ][:_MAX_REFUTED_PER_PASS]

    additions: list[Any] = []
    lessons: list[dict[str, Any]] = []
    mutation_count = 0
    competitor_count = 0
    decayed_count = 0

    if refuted:
        try:
            model = build_security_knowledge_graph(state)
        except Exception as exc:  # noqa: BLE001 — advisory node, never fatal
            logger.warning(
                "hypothesis evolution SKG build failed (advisory): %s", exc)
            model = None

        current_pool = list(pool)
        for parent in refuted:
            additions.extend(mutate_hypothesis(parent))
            mutation_count += len(additions)
            if model is not None:
                competitors = competing_hypotheses(parent, model)
                additions.extend(competitors)
                competitor_count += len(competitors)
            updated_pool, lesson = learn_from_negative_evidence(
                current_pool, parent)
            before = {
                str(h.id): float(h.info_gain) for h in current_pool}
            for hyp in updated_pool:
                if (str(hyp.id) in before
                        and float(hyp.info_gain) < before[str(hyp.id)]):
                    additions.append(hyp)
                    decayed_count += 1
            current_pool = updated_pool
            lessons.append(lesson)

    priorities = select_by_info_gain(pool, limit=_MAX_PRIORITY_IDS)
    summary = {
        "built": True,
        "advisory_only": True,
        "pool_size": len(pool),
        "refuted_processed": len(refuted),
        "mutation_count": mutation_count,
        "competitor_count": competitor_count,
        "decayed_count": decayed_count,
        "lesson_count": len(lessons),
        "priority_count": len(priorities),
        "influence_contract": (
            "advisory for research prioritization only — never authorizes, "
            "never confirms, never bypasses CausalGuard/ProofBundle/Replay"
        ),
    }
    return {
        "researcher_evolution": summary,
        "researcher_priorities": {
            "advisory_only": True,
            "method": (
                "deterministic-match first, then info_gain desc, id "
                "tiebreak (Phase C selection over the OPEN pool)"
            ),
            "selected_count": len(priorities),
            "selected_ids": [str(h.id) for h in priorities],
        },
        "research_lessons": lessons,
        "hypotheses": additions,
    }
