"""UM-DR-40 RC-6/RC-7 — the production decision-ledger measurements.

The 39 register's two remaining research-economics gaps:

* **RC-6** — production information gain was a lookup prior, never a
  measurement. Acceptance: compute per-experiment gain from the
  before/after information state (which hypotheses the experiment
  distinguished; which preconditions it resolved), recorded in the
  decision log — adapted INTO the strategist, not a parallel
  orchestrator.
* **RC-7** — the production decision record carries only
  rule_fired+outcome. Acceptance: the coverage ledger gains the
  ranked runner-up slice.

Both functions are pure and bounded; the strategist (the only
caller) wires them at its ranking loop, per the 39 register's
"adapted INTO the strategist" constraint.

RC-5 is the enabler: with generation-time deterministic hypothesis
ids, the before/after set difference is stable — identities match
across passes, so "which hypotheses did this batch distinguish" is
a real measurement, not a content guess.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

__all__ = [
    "ranked_alternatives",
    "information_gain_snapshot",
]

#: The bounded runner-up slice size (RC-7: "the ranked runner-up
#: slice" — bounded so the ledger stays report-safe).
ALTERNATIVES_SLICE_SIZE = 5


def ranked_alternatives(
    ranked: Iterable[tuple[Any, float]],
    *,
    k: int = ALTERNATIVES_SLICE_SIZE,
    exclude_id: str | None = None,
) -> list[dict[str, Any]]:
    """RC-7 — the ranked runner-up slice for one decision.

    ``ranked`` is the strategist's ranked candidate list
    ([(hypothesis, score), …]) in decision order. Returns the top-k
    runner-ups WITH their scores: [{hypothesis_id, score, rank}, …]
    where rank 1 is the highest-scored candidate overall. The chosen
    hypothesis (``exclude_id``) is excluded so the entry never lists
    itself as its own alternative. Bounded to k entries; scores are
    rounded for report safety. Nothing is invented: a hypothesis
    with no id is skipped.
    """
    slice_: list[dict[str, Any]] = []
    for hypothesis, score in ranked:
        hypothesis_id = str(getattr(hypothesis, "id", "") or "")
        if not hypothesis_id:
            continue
        if exclude_id is not None and hypothesis_id == exclude_id:
            continue
        slice_.append({
            "hypothesis_id": hypothesis_id,
            "score": round(float(score), 6),
            "rank": len(slice_) + 1,
        })
        if len(slice_) >= k:
            break
    return slice_


def information_gain_snapshot(
    pool_before: Iterable[str],
    pool_after: Iterable[str],
    *,
    resolved_preconditions: Iterable[str] = (),
) -> dict[str, Any]:
    """RC-6 — the measured information gain of one decision batch.

    The gain is computed from the before/after information state:
    ``distinguished`` is the set of hypothesis ids that left the
    pool because THIS batch resolved them (promoted to a finding or
    abandoned with a recorded reason) — the batch's information
    yield. ``pool_delta`` is the size change. Precondition
    resolution is carried through when the caller has a real
    precondition channel; the current strategist pass does not, so
    it records the empty list rather than inventing resolutions.
    """
    before = [str(x) for x in pool_before if x]
    after = [str(x) for x in pool_after if x]
    before_set, after_set = set(before), set(after)
    resolved = sorted(before_set - after_set)
    added = sorted(after_set - before_set)
    return {
        "pool_before": len(before),
        "pool_after": len(after),
        "pool_delta": len(after) - len(before),
        "distinguished": resolved,
        "distinguished_count": len(resolved),
        "added": added,
        "resolved_preconditions": sorted(
            {str(p) for p in resolved_preconditions if p}),
    }
