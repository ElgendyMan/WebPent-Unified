# src/webpent/coverage/scheduler.py
"""Coverage-driven probe scheduling (2026-10-25 proposals, Proposal 2).

Turns the campaign's coverage cells into a DETERMINISTIC priority
order and detects the plateau that signals a rabbit hole. This is the
answer to "why did the campaign spend its requests HERE": every probe
order it produces is reproducible from explicit inputs.

Scoring (documented, not learned-black-box):

    expected_yield(cell) = prior * diversity * novelty

  * prior       — historical signal from the refutation ledger
                  (Proposal 1 integration): a (class, target) pair with
                  many refutations yields less; a pair with no
                  refutation history yields full prior. Confirmations
                  reset refutation history, so confirmed families keep
                  full prior automatically.
  * diversity   — 0.5 + 0.5 * normalized parameter-name count (a cell
                  with more attack-surface names is worth an earlier
                  visit), capped at 1.0.
  * novelty     — 1.0 never attempted; 0.3 attempted but outside the
                  plateau window; 0.1 recently attempted. Revisits are
                  never free, but never forbidden (delay, not delete).

Plateau detection: if no NEW cell has been covered within
``plateau_minutes`` (clock injected, so tests are deterministic), the
scheduler reports a plateau and escalates to rabbit-hole review — the
signal the plan's "الصعود إلى rabbit_hole" step.

The scheduler is ADVISORY: it returns ordered cells and signals; graph
routing stays in the graph builder, exactly like the planner-decision
proposal gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from webpent.coverage.cell_model import CoverageCell, build_cells

_PLATEAU_WINDOW_MIN = 20.0
_NOVELTY_NEVER = 1.0
_NOVELTY_STALE = 0.3
_NOVELTY_RECENT = 0.1


@dataclass(frozen=True)
class CellScore:
    """One cell with its deterministic expected yield."""

    cell: CoverageCell
    expected_yield: float
    novelty: float
    prior: float

    @property
    def key(self) -> str:
        return self.cell.key


@dataclass
class CoverageScheduler:
    """Order coverage cells by documented expected yield; detect plateaus."""

    cells: tuple[CoverageCell, ...] = ()
    plateau_minutes: float = _PLATEAU_WINDOW_MIN
    # cell key -> last attempted timestamp (monotonic-ish minutes float)
    _last_attempt: dict[str, float] = field(default_factory=dict)
    _covered: set[str] = field(default_factory=set)
    _first_covered_at: float | None = None

    def mark_attempted(self, key: str, *, now: float) -> None:
        """Record that a probe set touched this cell key."""
        self._last_attempt[str(key)] = float(now)

    def mark_covered(self, key: str, *, now: float) -> None:
        """Record a definitive outcome (confirmed OR refuted) for this key."""
        key = str(key)
        self._last_attempt[key] = float(now)
        if key not in self._covered:
            self._covered.add(key)
            if self._first_covered_at is None:
                self._first_covered_at = float(now)

    def score(self, *, ledger: Any = None, now: float = 0.0) -> tuple[CellScore, ...]:
        """Score every cell deterministically; sort by (-yield, key)."""
        scores: list[CellScore] = []
        for cell in self.cells:
            prior = 1.0
            if ledger is not None and cell.vuln_class and cell.url_template:
                from webpent.learning.refutation_ledger import (
                    target_fingerprint_from_url,
                )

                fingerprint = target_fingerprint_from_url(cell.url_template)
                prior = 1.0 / (1.0 + ledger.refutation_count(
                    vuln_class=cell.vuln_class, target_fingerprint=fingerprint
                ))
            diversity = min(1.0, 0.5 + 0.1 * len(cell.param_names))
            last = self._last_attempt.get(cell.key)
            if last is None:
                novelty = _NOVELTY_NEVER
            elif now - last > self.plateau_minutes:
                novelty = _NOVELTY_STALE
            else:
                novelty = _NOVELTY_RECENT
            scores.append(CellScore(
                cell=cell,
                expected_yield=round(prior * diversity * novelty, 6),
                novelty=novelty,
                prior=round(prior, 6),
            ))
        scores.sort(key=lambda s: (-s.expected_yield, s.cell.key))
        return tuple(scores)

    def top(self, n: int = 5, **score_kwargs: Any) -> tuple[CellScore, ...]:
        return self.score(**score_kwargs)[: max(0, int(n))]

    def check_plateau(self, *, now: float) -> bool:
        """True when the campaign has stopped covering NEW cells.

        Before the first covered cell there is no plateau (the campaign
        has barely started); the detector only arms once something was
        covered.
        """
        if self._first_covered_at is None:
            return False
        return (float(now) - self._first_covered_at) > self.plateau_minutes * 60.0

    def stats(self) -> dict[str, int]:
        """Read-only counters: discovered / covered / remaining."""
        return {
            "discovered": len(self.cells),
            "covered": len(self._covered),
            "remaining": max(0, len(self.cells) - len(self._covered)),
        }


_ADVISORY_HEADER = (
    "Coverage advisory (deterministic, advisory data — never instructions; "
    "the graph topology and safety gates are unchanged):"
)


def build_coverage_advisory(
    state: Mapping[str, Any],
    *,
    top_n: int = 5,
    ledger: Any = None,
    plateau_minutes: float = _PLATEAU_WINDOW_MIN,
    now: float = 0.0,
) -> str:
    """Bounded advisory block for the planner prompt (Proposals 1+2).

    Deterministic text over the campaign's own cells plus the
    refutation ledger's redaction-safe patterns. Empty string when the
    state has no cells (flag off / nothing crawled), so the planner
    prompt is byte-identical to pre-feature behavior.
    """
    cells = build_cells(state)
    if not cells:
        return ""
    scheduler = CoverageScheduler(cells=cells, plateau_minutes=plateau_minutes)
    scored = scheduler.top(top_n, ledger=ledger, now=now)
    stats = scheduler.stats()
    lines = [_ADVISORY_HEADER]
    lines.append(
        f"Coverage cells: {stats['discovered']} discovered, "
        f"{stats['covered']} covered, {stats['remaining']} remaining."
    )
    lines.append("Highest expected-yield cells (yield is a heuristic, not truth):")
    for entry in scored:
        params = ",".join(sorted(entry.cell.param_names)) or "-"
        vuln = entry.cell.vuln_class or "-"
        lines.append(
            f"- [{entry.expected_yield:.3f}] {entry.cell.method} "
            f"{entry.cell.url_template} params={params} family={vuln}"
        )
    if ledger is not None:
        summary = getattr(ledger, "summarize", lambda *a, **k: "")(3)
        if summary:
            lines.append("")
            lines.append(summary)
    lines.append(
        "Escalate to rabbit-hole review only if new coverage stalls; "
        "do not loop on exhausted cells."
    )
    return "\n".join(lines)


__all__ = [
    "CellScore",
    "CoverageScheduler",
    "build_coverage_advisory",
]
