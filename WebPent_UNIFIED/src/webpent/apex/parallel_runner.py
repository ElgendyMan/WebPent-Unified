"""The Apex Predator — U-APEX-5, the Parallel Runner (v87).

APEX-L-5 PARALLEL BY DEFAULT: independent chain steps run concurrently on
a thread pool, dependencies are respected topologically, and results are
ordered by step id regardless of completion order — determinism is part
of the contract. APEX-L-8 SPEED IS THE EDGE: the runner measures the real
wall clock and reports the measured speedup (sum of step durations over
the observed total), never an estimate dressed up as a measurement.

The step runner is injected, so tests drive this module with fakes and
the executor wires the real sandbox in production (APEX-L-4).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field

from webpent.apex.tool_chain_builder import ChainStep, ToolChain
from webpent.apex.tool_registry import ToolRegistry

PREAMBLE_LINE = (
    "advisory: parallel execution plans are proposals — the operator "
    "approves the run; measurements here are advisory evidence."
)

#: exit code when a step never ran because its dependency failed
SKIPPED_EXIT = 130


@dataclass
class StepResult:
    """Outcome of one chain step."""

    step_id: str
    tool_id: str
    exit_code: int = 0
    output: dict = field(default_factory=dict)
    error: str = ""
    skipped: bool = False
    duration_seconds: float = 0.0

    def as_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "tool_id": self.tool_id,
            "exit_code": self.exit_code,
            "output": self.output,
            "error": self.error,
            "skipped": self.skipped,
            "duration_seconds": round(self.duration_seconds, 4),
        }


@dataclass
class ChainRunResult:
    """Outcome of one full chain run."""

    chain_id: str
    step_results: list[StepResult] = field(default_factory=list)
    total_duration_seconds: float = 0.0
    sum_step_durations: float = 0.0
    advisory_note: str = PREAMBLE_LINE

    @property
    def completed(self) -> int:
        return sum(1 for r in self.step_results if not r.skipped and not r.error)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.step_results if r.error and not r.skipped)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.step_results if r.skipped)

    @property
    def measured_speedup(self) -> float:
        """sum(step durations) / observed wall clock. 1.0 == serial."""
        if self.total_duration_seconds <= 0:
            return 1.0
        return self.sum_step_durations / self.total_duration_seconds

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "steps": [r.as_dict() for r in self.step_results],
            "total_duration_seconds": round(self.total_duration_seconds, 4),
            "sum_step_durations": round(self.sum_step_durations, 4),
            "measured_speedup": round(self.measured_speedup, 3),
            "completed": self.completed,
            "failed": self.failed,
            "skipped": self.skipped,
            "advisory_note": self.advisory_note,
        }


class ParallelRunner:
    """Dependency-aware concurrent executor for tool chains."""

    def __init__(self, max_parallel: int = 4) -> None:
        if max_parallel < 1:
            raise ValueError("max_parallel must be >= 1")
        self._max_parallel = max_parallel

    # -- planning ------------------------------------------------------------

    @staticmethod
    def estimate_speedup(sum_durations: float, critical_path: float) -> float:
        """sum(step durations) / critical path — pure planning math, clearly
        separate from the measured speedup on ChainRunResult."""
        if critical_path <= 0:
            return 1.0
        return sum_durations / critical_path

    @staticmethod
    def durations_from_chain(
        chain: ToolChain, registry: ToolRegistry
    ) -> dict[str, float]:
        """Planning durations per step from registry speed tiers."""
        from webpent.apex.tool_chain_builder import SPEED_SECONDS

        return {
            step.step_id: SPEED_SECONDS.get(
                registry.get(step.tool_id).speed, 120.0
            )
            for step in chain.steps
        }

    # -- execution -----------------------------------------------------------

    def run(
        self,
        chain: ToolChain,
        runner: Callable[[ChainStep], dict],
    ) -> ChainRunResult:
        """Execute the chain concurrently, dependencies respected.

        `runner(step)` performs one step and returns its output dict;
        exceptions are captured as failed StepResults, never raised, so
        one tool's crash cannot take down the run.
        """
        import time

        started = time.monotonic()
        steps_by_id = {s.step_id: s for s in chain.steps}
        results: dict[str, StepResult] = {
            sid: StepResult(step_id=sid, tool_id=s.tool_id)
            for sid, s in steps_by_id.items()
        }
        dependents: dict[str, list[str]] = {sid: [] for sid in steps_by_id}
        pending_parents: dict[str, int] = {}
        for step in chain.steps:
            parents = [p for p in step.after if p in steps_by_id]
            pending_parents[step.step_id] = len(parents)
            for parent in parents:
                dependents[parent].append(step.step_id)

        ready: list[str] = [
            sid for sid, n in pending_parents.items() if n == 0
        ]
        lock = threading.Lock()
        def _finish(sid: str, result: StepResult) -> None:
            with lock:
                results[sid] = result
                if result.exit_code != 0 or result.skipped:
                    # RT-05: skipping must reach the grandchildren too,
                    # not just the direct dependents, or they never get
                    # scheduled and are left with fabricated defaults.
                    stack = list(dependents[sid])
                    while stack:
                        child = stack.pop()
                        if results[child].skipped:
                            continue
                        results[child] = StepResult(
                            step_id=child,
                            tool_id=steps_by_id[child].tool_id,
                            exit_code=SKIPPED_EXIT,
                            skipped=True,
                            error=f"dependency {sid} failed",
                        )
                        stack.extend(dependents[child])
            # wake scheduler by processing children inline below

        def _run_step(step: ChainStep) -> StepResult:
            t0 = time.monotonic()
            try:
                output = runner(step)
                # RT-05: runners report a tool's real exit code in the
                # output dict; a non-zero one is a failed step, so its
                # dependents (and grandchildren) must be skipped.
                exit_code = 0
                if isinstance(output, dict) and output.get("exit_code") is not None:
                    try:
                        exit_code = int(output["exit_code"])
                    except (TypeError, ValueError):
                        exit_code = 0
                return StepResult(
                    step_id=step.step_id,
                    tool_id=step.tool_id,
                    exit_code=exit_code,
                    output=output,
                    error=(
                        str(output.get("stderr", ""))
                        if exit_code != 0 and isinstance(output, dict) else ""
                    ),
                    duration_seconds=time.monotonic() - t0,
                )
            except Exception as exc:  # noqa: BLE001 - captured, not raised
                return StepResult(
                    step_id=step.step_id,
                    tool_id=step.tool_id,
                    exit_code=1,
                    error=str(exc),
                    duration_seconds=time.monotonic() - t0,
                )

        with ThreadPoolExecutor(max_workers=self._max_parallel) as pool:
            futures: dict[Future[StepResult], str] = {}

            def _schedule(step: ChainStep) -> None:
                fut = pool.submit(_run_step, step)
                futures[fut] = step.step_id

            def _drain_ready() -> list[Future[StepResult]]:
                scheduled: list[Future[StepResult]] = []
                for sid in list(ready):
                    if sid in results and results[sid].skipped:
                        continue
                    _schedule(steps_by_id[sid])
                    scheduled.append(
                        next(f for f, s in futures.items() if s == sid)
                    )
                return scheduled

            initial = _drain_ready()
            ready.clear()
            pending = set(initial)
            while pending:
                done = {f for f in pending if f.done()}
                if not done:
                    # small sleep to avoid busy spin; bounded and only here
                    time.sleep(0.001)
                    continue
                for fut in list(done):
                    pending.discard(fut)
                    step_result = fut.result()
                    sid = futures.pop(fut)
                    _finish(sid, step_result)
                    newly_ready: list[str] = []
                    for child in dependents[sid]:
                        if results[child].skipped:
                            continue
                        pending_parents[child] -= 1
                        if pending_parents[child] == 0:
                            newly_ready.append(child)
                    for child in newly_ready:
                        _schedule(steps_by_id[child])
                        pending.add(
                            next(f for f, s in futures.items() if s == child)
                        )

        ordered = [
            results[s.step_id] for s in chain.steps
        ]
        total = time.monotonic() - started
        return ChainRunResult(
            chain_id=chain.chain_id,
            step_results=ordered,
            total_duration_seconds=total,
            sum_step_durations=sum(r.duration_seconds for r in ordered),
        )
