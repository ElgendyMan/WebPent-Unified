"""The Apex Predator — U-APEX-12, the Continuous Learn Loop (v87).

Laws under proof: APEX-L-6 FUSE RESULTS + APEX-L-7 LEARN FROM EVERYTHING.
Every chain outcome and every tool result is recorded to a capped JSONL
ledger on disk. The ledger stores no raw targets (redacted paths — no
secrets in the ledger) and asserts no accuracy number before MIN_SAMPLES
observations exist (no claim before evidence). Best-chain retrieval,
failure-driven improvement suggestions and persistence round-trips are
all deterministic.

Advisory only (APEX-L-9): the loop learns; it never acts on its own.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from webpent.apex.parallel_runner import ChainRunResult
from webpent.apex.tool_chain_builder import ChainStep, ToolChain

PREAMBLE_LINE = (
    "advisory: the learning loop records outcomes and proposes lessons; "
    "it never runs anything itself."
)


@dataclass
class Improvement:
    """One advisory lesson drawn from recorded failures."""

    tool_id: str
    suggestion: str
    failure_count: int = 0
    advisory_note: str = PREAMBLE_LINE


@dataclass
class _Pattern:
    """Aggregate success record for one (hypothesis, chain) pair."""

    chain_id: str
    hypothesis_type: str
    steps: list[dict] = field(default_factory=list)
    success_count: int = 0
    failure_count: int = 0


class ApexLearning:
    """Capped, persistent ledger of chain outcomes and tool results."""

    MIN_SAMPLES = 5
    MAX_OUTCOMES = 500
    MIN_FAILURES_FOR_SUGGESTION = 2

    def __init__(self, path: Path, max_outcomes: int | None = None) -> None:
        self._path = path
        self._max_outcomes = (
            max_outcomes if max_outcomes is not None else self.MAX_OUTCOMES
        )
        self._outcomes: list[dict] = []
        self._tool_results: dict[str, list[bool]] = {}
        self.advisory_note = PREAMBLE_LINE

    # -- loading ----------------------------------------------------------------

    @classmethod
    def load(cls, path: Path, max_outcomes: int | None = None) -> ApexLearning:
        learn = cls(path, max_outcomes=max_outcomes)
        if not path.is_file():
            return learn
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue  # corrupt lines load as nothing, never crash
            if not isinstance(row, dict):
                continue
            kind = row.get("kind")
            if kind == "outcome":
                learn._outcomes.append(row)
            elif kind == "tool_result":
                tool_id = str(row.get("tool_id", ""))
                if tool_id:
                    learn._tool_results.setdefault(tool_id, []).append(
                        bool(row.get("success"))
                    )
        if learn._max_outcomes and len(learn._outcomes) > learn._max_outcomes:
            learn._outcomes = learn._outcomes[-learn._max_outcomes:]
        return learn

    # -- recording ----------------------------------------------------------------

    def record_chain_outcome(
        self, chain: ToolChain, result: ChainRunResult, target: str
    ) -> None:
        """Record one chain run. The raw target is redacted: the ledger
        keys patterns by hypothesis and chain, never by host."""
        exits = {
            r.step_id: r.exit_code
            for r in result.step_results
        }
        steps = [
            {
                "step_id": s.step_id,
                "tool_id": s.tool_id,
                "capability": s.capability,
                # RT-17: a step absent from the run result never ran —
                # recording it as 0 (success) would forge evidence. -1
                # marks "not executed" in the ledger.
                "exit_code": exits.get(s.step_id, -1),
            }
            for s in chain.steps
        ]
        success = result.completed > 0
        row = {
            "kind": "outcome",
            "chain_id": chain.chain_id,
            "hypothesis_type": chain.hypothesis_type,
            "success": success,
            "steps": steps,
            "target_hash": hashlib.sha256(target.encode()).hexdigest()[:16],
        }
        self._outcomes.append(row)
        if self._max_outcomes and len(self._outcomes) > self._max_outcomes:
            self._outcomes = self._outcomes[-self._max_outcomes:]
        # RT-07/RT-08: append in recording order; the cap then applies to
        # ALL ledger lines (any kind), not just outcomes.
        self._append_line(row)

    def record_tool_result(self, tool_id: str, success: bool) -> None:
        """Record one observed tool result (success/failure)."""
        self._tool_results.setdefault(tool_id, []).append(bool(success))
        row = {"kind": "tool_result", "tool_id": tool_id, "success": bool(success)}
        self._append_line(row)

    # -- queries -----------------------------------------------------------------

    def get_tool_accuracy(self, tool_id: str) -> float | None:
        """Observed success rate, or None until MIN_SAMPLES observations
        exist — no accuracy claim before evidence (APEX-L-7)."""
        results = self._tool_results.get(tool_id, [])
        if len(results) < self.MIN_SAMPLES:
            return None
        return sum(1 for r in results if r) / len(results)

    def get_best_chain_for(self, hypothesis_type: str) -> ToolChain | None:
        """The most-successfully-recorded chain for this hypothesis, or
        None. Deterministic: ties break by chain_id ascending."""
        best: tuple[int, str, str, list[dict]] | None = None
        for _key, pattern in self._patterns().items():
            if pattern.hypothesis_type != hypothesis_type:
                continue
            # RT-18: a recommendation needs evidence, same bar as
            # get_tool_accuracy — a 1/1 pattern must not outrank a 9/10
            # one just because its sample is smaller.
            if pattern.success_count < self.MIN_SAMPLES:
                continue
            key = (pattern.success_count, pattern.chain_id)
            if best is None or key > (best[0], best[1]):
                best = (pattern.success_count, pattern.chain_id, _key,
                        pattern.steps)
        if best is None:
            return None
        steps = [
            ChainStep(
                tool_id=s["tool_id"],
                capability=s.get("capability", ""),
                step_id=s.get("step_id", s["tool_id"]),
            )
            for s in best[3]
        ]
        return ToolChain(
            chain_id=best[1],
            hypothesis_type=hypothesis_type,
            target="learned-from-recorded-outcomes",
            steps=steps,
        )

    def suggest_improvements(self) -> list[Improvement]:
        """Advisory lessons from recorded failures: tools that failed
        repeatedly are named, deterministically ordered."""
        failures: Counter[str] = Counter()
        for row in self._outcomes:
            for step in row.get("steps", []):
                if step.get("exit_code", 0) != 0:
                    failures[step.get("tool_id", "?")] += 1
        improvements: list[Improvement] = []
        for tool_id in sorted(failures):
            count = failures[tool_id]
            if count < self.MIN_FAILURES_FOR_SUGGESTION:
                continue
            improvements.append(
                Improvement(
                    tool_id=tool_id,
                    suggestion=(
                        f"{tool_id} failed {count} time(s) in recorded "
                        f"chains — review its arguments, placement, or "
                        f"replace it in the chain template."
                    ),
                    failure_count=count,
                )
            )
        return improvements

    def pattern_count(self) -> int:
        return len(self._patterns())

    def outcome_count(self) -> int:
        return len(self._outcomes)

    # -- internals ------------------------------------------------------------------

    def _patterns(self) -> dict[str, _Pattern]:
        patterns: dict[str, _Pattern] = {}
        for row in self._outcomes:
            key = (
                f"{row.get('hypothesis_type')}|{row.get('chain_id')}"
                f"|{row.get('target_hash', '-')}"
            )
            pattern = patterns.setdefault(
                key,
                _Pattern(
                    chain_id=row.get("chain_id", ""),
                    hypothesis_type=row.get("hypothesis_type", ""),
                ),
            )
            pattern.steps = row.get("steps", pattern.steps)
            if row.get("success"):
                pattern.success_count += 1
            else:
                pattern.failure_count += 1
        return patterns

    def _append_line(self, row: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
        self._enforce_cap()

    def _enforce_cap(self) -> None:
        """RT-07: the file holds at most max_outcomes lines in total, of
        any kind — the newest survive, oldest are dropped, so the ledger
        can never grow without bound."""
        if not self._max_outcomes or not self._path.is_file():
            return
        lines = [
            line for line in
            self._path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if len(lines) <= self._max_outcomes:
            return
        self._path.write_text(
            "".join(line + "\n" for line in lines[-self._max_outcomes:]),
            encoding="utf-8",
        )

    def _flush(self) -> None:
        """RT-08: retained for callers; the ledger is now append-only in
        recording order, so flushing only re-asserts the line cap."""
        self._enforce_cap()
