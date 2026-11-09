"""U-APEX-9 — The Speed Optimizer (v87).

Law under proof: APEX-L-8 SPEED IS THE EDGE — result caching with TTL
(injected clock, no hidden wall-clock dependence), predictive prefetch
that warms the cache for likely chains, adaptive timeouts that learn a
target's speed within hard clamps, and chain ordering by estimated
duration. The executor stays injected; no real tools run here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from webpent.apex.speed_optimizer import (
    PREAMBLE_LINE,
    SpeedOptimizer,
)
from webpent.apex.tool_chain_builder import (
    ChainStep,
    ToolChain,
    ToolChainBuilder,
)
from webpent.apex.tool_registry import ToolRegistry

WORK = Path(__file__).resolve().parents[2]
REGISTRY_PATH = WORK / "config" / "apex" / "tools.yaml"
CHAINS_PATH = WORK / "config" / "apex" / "chains.yaml"


@pytest.fixture()
def registry() -> ToolRegistry:
    return ToolRegistry.load(REGISTRY_PATH)


@pytest.fixture()
def builder(registry: ToolRegistry) -> ToolChainBuilder:
    return ToolChainBuilder.load(CHAINS_PATH, registry)


def _chain(hyp: str, steps: list[tuple[str, list[str]]]) -> ToolChain:
    return ToolChain(
        chain_id=f"chain-{hyp}",
        hypothesis_type=hyp,
        target="t.test",
        steps=[
            ChainStep(tool_id=tid, capability="cap", after=afters, step_id=tid)
            for tid, afters in steps
        ],
    )


def _tick():
    state = {"now": 100.0}

    def advance(delta: float) -> None:
        state["now"] += delta

    def now() -> float:
        return state["now"]

    return now, advance


def test_cache_hit_returns_stored_result_without_reexecution() -> None:
    now, _ = _tick()
    executions: list[str] = []

    def executor(key: str) -> str:
        executions.append(key)
        return f"result-for-{key}"

    opt = SpeedOptimizer(clock=now, executor=executor, ttl_seconds=60.0)
    first = opt.cached_call("k1")
    second = opt.cached_call("k1")
    assert first == "result-for-k1"
    assert second == first
    assert executions == ["k1"], "cache hit must not re-execute"
    assert opt.stats()["hits"] == 1
    assert opt.stats()["misses"] == 1


def test_ttl_expiry_with_injected_clock() -> None:
    now, advance = _tick()
    opt = SpeedOptimizer(
        clock=now, executor=lambda k: f"r-{k}", ttl_seconds=60.0
    )
    opt.cached_call("k1")
    advance(30.0)
    assert opt.cache_get("k1") == "r-k1", "inside TTL: still cached"
    advance(40.0)  # now 70s after the write, past the 60s TTL
    assert opt.cache_get("k1") is None, "expired entries must be dropped"
    # and the next cached_call re-executes
    assert opt.cached_call("k1") == "r-k1"


def test_prefetch_warms_cache_for_likely_chains() -> None:
    now, _ = _tick()
    warmed: list[str] = []

    def executor(key: str) -> str:
        warmed.append(key)
        return f"r-{key}"

    opt = SpeedOptimizer(clock=now, executor=executor, ttl_seconds=60.0)
    likely = [_chain("xss", [("gau", []), ("dalfox", ["gau"])])]
    opt.prefetch(likely)
    assert warmed, "prefetch must warm the cache"
    # every subsequent cached call for those steps is a hit
    hits_before = opt.stats()["hits"]
    for step in likely[0].steps:
        opt.cached_call(opt.cache_key(step.tool_id, "t.test"))
    assert opt.stats()["hits"] == hits_before + 2
    assert len(warmed) == 2, "prefetch itself executes each step once"


def test_adaptive_timeout_shrinks_and_grows_within_clamps() -> None:
    now, advance = _tick()
    opt = SpeedOptimizer(clock=now, executor=lambda k: "ok")
    base = opt.adaptive_timeout("t.slow", "nuclei")
    # observed fast completions shrink the timeout
    for _ in range(5):
        opt.record_duration("t.slow", "nuclei", 2.0)
        advance(1.0)
    fast = opt.adaptive_timeout("t.slow", "nuclei")
    # observed slow completions grow it back
    for _ in range(5):
        opt.record_duration("t.slow", "nuclei", 120.0)
        advance(1.0)
    slow = opt.adaptive_timeout("t.slow", "nuclei")
    assert fast < base, "fast target must shrink the timeout"
    assert slow > fast, "slow target must grow the timeout"
    lo, hi = opt.timeout_clamps()
    assert lo <= fast <= hi and lo <= slow <= hi, "clamps always bind"


def test_optimize_orders_chains_by_estimated_duration() -> None:
    now, _ = _tick()
    opt = SpeedOptimizer(clock=now, executor=lambda k: "ok")
    chains = [
        _chain("sqli", [("sqlmap", [])]),   # slow tier
        _chain("xss", [("gau", [])]),       # fast tier
    ]
    ordered = opt.optimize(chains, registry=ToolRegistry.load(REGISTRY_PATH))
    assert [c.hypothesis_type for c in ordered] == ["xss", "sqli"], (
        "fastest-first ordering (APEX-L-8)"
    )
    assert PREAMBLE_LINE in opt.advisory_note


def test_batching_reduces_overhead() -> None:
    now, _ = _tick()
    calls: list[list[str]] = []

    def batch_executor(keys: list[str]) -> list[str]:
        calls.append(list(keys))
        return [f"r-{k}" for k in keys]

    opt = SpeedOptimizer(clock=now, batch_executor=batch_executor)
    keys = [f"k{i}" for i in range(5)]
    results = opt.cached_many(keys)
    assert results == [f"r-k{i}" for i in range(5)]
    assert len(calls) == 1, "5 keys must be one batched call, not five"
