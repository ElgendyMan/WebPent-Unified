"""U-APEX-5 — The Parallel Runner (v87).

Laws under proof: APEX-L-5 (parallel by default, dependencies respected),
APEX-L-8 (speed is the edge — the speedup is MEASURED, not claimed).
Determinism: results are ordered by step id regardless of completion order.
No real subprocesses: the runner takes an injected step function.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from webpent.apex.parallel_runner import (
    PREAMBLE_LINE,
    ChainRunResult,
    ParallelRunner,
    StepResult,
)
from webpent.apex.tool_chain_builder import ChainStep, ToolChain
from webpent.apex.tool_registry import ToolRegistry

WORK = Path(__file__).resolve().parents[2]


def _chain(steps: list[tuple[str, list[str]]]) -> ToolChain:
    return ToolChain(
        chain_id="chain-test",
        hypothesis_type="test",
        target="t.test",
        steps=[
            ChainStep(tool_id=tid, capability="cap", after=afters, step_id=tid)
            for tid, afters in steps
        ],
    )


def _ok(tool_id: str) -> dict:
    return {"tool_id": tool_id, "exit_code": 0}


def test_parallel_speedup_measured_over_three_independent_steps() -> None:
    """Three independent 0.15s sleeps must complete in well under the
    0.45s serial time — the speedup is proven by the wall clock."""
    chain = _chain([("a", []), ("b", []), ("c", [])])

    def runner(step: ChainStep) -> dict:
        time.sleep(0.15)
        return _ok(step.tool_id)

    result = ParallelRunner(max_parallel=3).run(chain, runner)
    assert result.total_duration_seconds < 0.40, (
        f"independent steps did not run in parallel: "
        f"{result.total_duration_seconds:.3f}s"
    )
    measured = result.measured_speedup
    assert measured > 1.5, f"speedup {measured:.2f} too low"


def test_dependencies_respected() -> None:
    chain = _chain([("root", []), ("child", ["root"]), ("grand", ["child"])])
    order: list[str] = []
    lock = threading.Lock()

    def runner(step: ChainStep) -> dict:
        with lock:
            order.append(step.tool_id)
        return _ok(step.tool_id)

    ParallelRunner(max_parallel=4).run(chain, runner)
    assert order.index("root") < order.index("child") < order.index("grand")


def test_results_sorted_by_step_id_regardless_of_completion_order() -> None:
    chain = _chain([("a", []), ("b", []), ("c", [])])

    def runner(step: ChainStep) -> dict:
        # reverse sleep: 'a' finishes last
        time.sleep({"a": 0.30, "b": 0.20, "c": 0.10}[step.tool_id])
        return _ok(step.tool_id)

    result = ParallelRunner(max_parallel=3).run(chain, runner)
    assert [r.step_id for r in result.step_results] == ["a", "b", "c"]


def test_max_parallel_caps_concurrency() -> None:
    chain = _chain([(f"s{i}", []) for i in range(6)])
    live = 0
    peak = 0
    lock = threading.Lock()

    def runner(step: ChainStep) -> dict:  # noqa: ARG001
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        time.sleep(0.05)
        with lock:
            live -= 1
        return {}

    ParallelRunner(max_parallel=2).run(chain, runner)
    assert peak <= 2


def test_failed_step_skips_dependents() -> None:
    chain = _chain([("root", []), ("child", ["root"])])

    def runner(step: ChainStep) -> dict:
        if step.tool_id == "root":
            raise RuntimeError("tool exploded")
        return _ok(step.tool_id)

    result = ParallelRunner(max_parallel=2).run(chain, runner)
    root = next(r for r in result.step_results if r.step_id == "root")
    child = next(r for r in result.step_results if r.step_id == "child")
    assert root.exit_code != 0
    assert child.skipped is True


def test_step_result_shape() -> None:
    chain = _chain([("a", [])])
    result = ParallelRunner(max_parallel=1).run(chain, lambda s: _ok(s.tool_id))
    step_result = result.step_results[0]
    assert isinstance(step_result, StepResult)
    assert step_result.step_id == "a"
    assert step_result.exit_code == 0
    assert step_result.skipped is False


def test_diamond_dependencies_run() -> None:
    chain = _chain([
        ("root", []),
        ("left", ["root"]),
        ("right", ["root"]),
        ("join", ["left", "right"]),
    ])

    def runner(step: ChainStep) -> dict:
        return _ok(step.tool_id)

    result = ParallelRunner(max_parallel=4).run(chain, runner)
    assert [r.step_id for r in result.step_results] == [
        "root", "left", "right", "join",
    ]
    assert all(not r.skipped for r in result.step_results)


def test_estimate_speedup_formula() -> None:
    # steps a=1s, b=2s, c=3s all independent → sum 6, critical path 3
    assert ParallelRunner.estimate_speedup(6.0, 3.0) == pytest.approx(2.0)


def test_estimate_speedup_serial_when_chained() -> None:
    # critical path 6 == sum 6 → no speedup
    assert ParallelRunner.estimate_speedup(6.0, 6.0) == pytest.approx(1.0)


def test_run_result_shape() -> None:
    chain = _chain([("a", []), ("b", ["a"])])
    result = ParallelRunner(max_parallel=2).run(chain, lambda s: _ok(s.tool_id))
    assert isinstance(result, ChainRunResult)
    assert result.chain_id == "chain-test"
    assert result.completed == 2
    assert result.failed == 0
    assert result.skipped == 0
    assert PREAMBLE_LINE in result.advisory_note


def test_exception_captured_not_raised() -> None:
    chain = _chain([("a", [])])

    def runner(step: ChainStep) -> dict:  # noqa: ARG001
        raise ValueError("boom")

    result = ParallelRunner(max_parallel=1).run(chain, runner)
    assert result.step_results[0].exit_code != 0
    assert "boom" in result.step_results[0].error


def test_registry_speeds_feed_estimates() -> None:
    registry = ToolRegistry.load(WORK / "config" / "apex" / "tools.yaml")
    durations = ParallelRunner.durations_from_chain(
        ToolChain(
            chain_id="c",
            hypothesis_type="h",
            target="t",
            steps=[ChainStep(tool_id="nuclei", capability="x", step_id="nuclei")],
            registry=registry,
        ),
        registry,
    )
    assert durations["nuclei"] > 0
