# src/webpent/targeting/selector.py
"""Deterministic UCB1 target selector (PROPOSALS_ULTIMATE_V2 §10).

Ranks candidate targets the way a professional hunter picks programs to
work: by realized reward (confirmed findings priced through the
program's bounty table) balanced against exploration. UCB1 over
per-target play counts and reward sums; unplayed targets are always
explored first (every target gets one round before any escalation).

Determinism: the selection is a pure function of (candidates, stats,
seed). Ties are broken with a seeded RNG whose seed is declared in the
selection record, so the operator can replay any recommendation.

The selector RECOMMENDS ONLY. It never issues a request, never widens
scope, and its output is a suggestion the operator accepts or rejects;
the scope enforcer remains the final judge over anything that actually
leaves the framework. Flag-gated: with ``enable_target_selector`` off
the selector refuses outright.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

__all__ = [
    "SelectorError",
    "TargetStats",
    "SelectionRecord",
    "TargetSelector",
    "selector_snapshot_entry",
]

# Standard UCB1 exploration coefficient.
_UCB1_C = math.sqrt(2.0)


class SelectorError(ValueError):
    """Raised when target selection cannot proceed fail-closed."""


@dataclass
class TargetStats:
    """Per-target attack history feeding the bandit."""

    plays: int = 0
    reward_sum: float = 0.0

    @property
    def mean_reward(self) -> float:
        return self.reward_sum / self.plays if self.plays > 0 else 0.0


@dataclass(frozen=True)
class SelectionRecord:
    """One deterministic selection decision, always logged with its reason."""

    target: str
    score: float
    rank: int
    seed: int
    reason: str
    explored_first: bool = False
    filtered_out: tuple[str, ...] = ()
    stats: Mapping[str, TargetStats] = field(default_factory=dict)

    def snapshot_entry(self) -> dict[str, Any]:
        """The status-snapshot view of this selection (full transparency).

        Every field an operator needs to audit the pick: the winner, the
        score, why (exploration vs exploitation), the seed to replay it,
        and what was filtered as out-of-program.
        """
        return {
            "recommended_target": self.target,
            "score": round(self.score, 6) if math.isfinite(self.score) else "explore_first",
            "rank": self.rank,
            "reason": self.reason,
            "explored_first": self.explored_first,
            "seed": self.seed,
            "filtered_out_of_scope": list(self.filtered_out),
            "plays": {
                t: s.plays for t, s in sorted(self.stats.items())
            },
            "mean_reward": {
                t: round(s.mean_reward, 6)
                for t, s in sorted(self.stats.items())
                if s.plays > 0
            },
        }


def selector_snapshot_entry(record: SelectionRecord) -> dict[str, Any]:
    """Adapter for the worker status snapshot (delegates to the record)."""
    return record.snapshot_entry()


# Last selection this process made. The status snapshot surfaces it so a
# recommendation is ALWAYS auditable with its reason — never a silent pick.
_last_selection: SelectionRecord | None = None


def last_selection() -> SelectionRecord | None:
    return _last_selection


def _remember(record: SelectionRecord) -> None:
    global _last_selection
    _last_selection = record


def _ucb1_score(stats: TargetStats, total_plays: int) -> float:
    if stats.plays <= 0:
        return math.inf  # unplayed arms are always explored first
    mean = stats.mean_reward
    bonus = _UCB1_C * math.sqrt(math.log(max(total_plays, 1)) / stats.plays)
    return mean + bonus


class TargetSelector:
    """Deterministic UCB1 selector over candidate targets.

    Fail-closed refusals: ``target_selector_flag_off`` (the flag gates
    the whole engine), ``target_selector_no_candidates`` (nothing to
    rank — an empty recommendation would look like consent).
    """

    def __init__(
        self,
        *,
        enable_target_selector: bool,
        seed: int = 0,
        brief: Any = None,
    ) -> None:
        if not enable_target_selector:
            raise SelectorError("target_selector_flag_off")
        self.seed = int(seed)
        self.brief = brief

    def select(
        self,
        candidates: Iterable[str],
        stats: Mapping[str, TargetStats] | None = None,
    ) -> SelectionRecord:
        """Rank ``candidates`` and return the top recommendation.

        Out-of-program candidates (against the brief, when one is set)
        are FILTERED before ranking and reported in the record — they
        are never silently dropped, and never recommended. Scope
        enforcement itself stays with the scope enforcer.
        """
        pool = [str(c) for c in candidates if str(c).strip()]
        if not pool:
            raise SelectorError("target_selector_no_candidates")
        filtered: list[str] = []
        excluded: list[str] = []
        if self.brief is not None:
            from webpent.targeting.program_brief import matches_scope

            for cand in pool:
                (filtered if matches_scope(cand, self.brief) else excluded).append(cand)
        else:
            filtered = list(pool)
        if not filtered:
            raise SelectorError(
                "target_selector_no_candidates_in_scope: "
                f"{len(excluded)} candidate(s) out of program scope"
            )

        stats = dict(stats or {})
        table = {c: stats.get(c, TargetStats()) for c in filtered}
        total_plays = sum(s.plays for s in table.values())
        scored = [(c, _ucb1_score(s, total_plays)) for c, s in table.items()]

        # Deterministic ordering: primary = score (inf first, i.e. the
        # unplayed/explore-first arms), secondary = seeded tiebreak.
        rng = random.Random(self.seed)
        tiebreak = {c: rng.random() for c in filtered}
        ranked = sorted(
            scored,
            key=lambda kv: (
                -kv[1] if math.isfinite(kv[1]) else float("-inf"),
                tiebreak[kv[0]],
                kv[0],
            ),
        )
        winner, best = ranked[0]
        winner_stats = table[winner]
        explored_first = winner_stats.plays == 0
        reason = (
            "ucb1_explore_first_play"
            if explored_first
            else f"ucb1_exploit:mean={winner_stats.mean_reward:.6f}"
        )
        record = SelectionRecord(
            target=winner,
            score=best,
            rank=1,
            seed=self.seed,
            reason=reason,
            explored_first=explored_first,
            filtered_out=tuple(sorted(excluded)),
            stats=table,
        )
        _remember(record)
        return record


def update_stats(
    stats: dict[str, TargetStats],
    target: str,
    reward: float,
) -> TargetStats:
    """Record one played round (plays +1, reward added). Bookkeeping only."""
    entry = stats.setdefault(str(target), TargetStats())
    entry.plays += 1
    entry.reward_sum += float(reward)
    return entry
