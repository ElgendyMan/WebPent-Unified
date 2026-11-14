"""U-APEX-12 — The Continuous Learn Loop (v87).

Laws under proof: APEX-L-6 FUSE RESULTS + APEX-L-7 LEARN FROM EVERYTHING.
Chain outcomes recorded (redacted paths — no secrets in the ledger),
tool accuracy returns nothing until MIN_SAMPLES observations exist (no
claim before evidence), best-chain retrieval from recorded outcomes,
improvement suggestions from failures, capped ledger, corrupt file loads
as empty. Deterministic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from webpent.apex.learning import PREAMBLE_LINE, ApexLearning, Improvement
from webpent.apex.parallel_runner import ChainRunResult, StepResult
from webpent.apex.tool_chain_builder import ChainStep, ToolChain

MIN_SAMPLES = ApexLearning.MIN_SAMPLES


def _chain(hyp: str = "xss", steps: list[str] | None = None) -> ToolChain:
    steps = steps or ["gau", "dalfox"]
    return ToolChain(
        chain_id=f"chain-{hyp}",
        hypothesis_type=hyp,
        target="t.test",
        steps=[
            ChainStep(tool_id=t, capability="cap", step_id=t) for t in steps
        ],
    )


def _run(completed: int = 2, failed: int = 0, speedup: float = 1.8,
         tool_exits: dict[str, int] | None = None) -> ChainRunResult:
    tool_exits = tool_exits or {}
    step_results = [
        StepResult(
            step_id=s, tool_id=s,
            exit_code=tool_exits.get(s, 0),
            error="boom" if tool_exits.get(s, 0) != 0 else "",
            skipped=False,
        )
        for s in ["gau", "dalfox"]
    ]
    for name in tool_exits:
        if name not in {s.step_id for s in step_results}:
            step_results.append(
                StepResult(step_id=name, tool_id=name,
                           exit_code=tool_exits[name], error="boom")
            )
    return ChainRunResult(
        chain_id="chain-xss",
        step_results=step_results,
        total_duration_seconds=10.0,
        sum_step_durations=10.0 * speedup,
    )


def test_chain_outcome_recorded(tmp_path: Path) -> None:
    learn = ApexLearning.load(tmp_path / "learning.jsonl")
    # RT-18: a recommendation now needs MIN_SAMPLES evidence, so record
    # a full sample of successful runs before querying the best chain.
    for _ in range(MIN_SAMPLES):
        learn.record_chain_outcome(_chain(), _run(), target="t.test")
    assert learn.pattern_count() == 1
    pattern = learn.get_best_chain_for("xss")
    assert pattern is not None
    assert pattern.hypothesis_type == "xss"
    assert pattern.chain_id == "chain-xss"
    # the recorded pattern must not leak the target host into storage keys
    # (redacted paths: recording works for any target without storing it raw)
    learn.record_chain_outcome(_chain(), _run(), target="secret.host.test")
    assert learn.pattern_count() == 2


def test_tool_accuracy_needs_min_samples(tmp_path: Path) -> None:
    learn = ApexLearning.load(tmp_path / "learning.jsonl")
    assert learn.get_tool_accuracy("dalfox") is None, (
        "no number before MIN_SAMPLES observations"
    )
    for i in range(MIN_SAMPLES - 1):
        learn.record_tool_result("dalfox", success=(i % 2 == 0))
    assert learn.get_tool_accuracy("dalfox") is None
    learn.record_tool_result("dalfox", success=True)
    rate = learn.get_tool_accuracy("dalfox")
    assert rate is not None
    assert rate == pytest.approx((MIN_SAMPLES + 1) / (2 * MIN_SAMPLES))
    assert PREAMBLE_LINE in learn.advisory_note


def test_best_chain_retrieval_prefers_higher_success(tmp_path: Path) -> None:
    learn = ApexLearning.load(tmp_path / "learning.jsonl")
    strong = _chain("xss")
    weak = _chain("xss", steps=["waybackurls"])
    for _ in range(MIN_SAMPLES):
        learn.record_chain_outcome(strong, _run(), target="t.test")
    learn.record_chain_outcome(weak, _run(failed=2), target="t.test")
    best = learn.get_best_chain_for("xss")
    assert best is not None
    assert best.chain_id == "chain-xss", "higher-success pattern wins"
    assert learn.get_best_chain_for("sqli") is None


def test_improvements_suggested_from_failures(tmp_path: Path) -> None:
    learn = ApexLearning.load(tmp_path / "learning.jsonl")
    learn.record_chain_outcome(
        _chain(), _run(tool_exits={"dalfox": 1}), target="t.test"
    )
    learn.record_chain_outcome(
        _chain(), _run(tool_exits={"dalfox": 1}), target="t.test"
    )
    improvements = learn.suggest_improvements()
    assert improvements, "repeated failures must produce suggestions"
    assert all(isinstance(imp, Improvement) for imp in improvements)
    tool_imps = [imp for imp in improvements if imp.tool_id == "dalfox"]
    assert tool_imps, "dalfox failed twice — it must be named"
    assert "dalfox" in tool_imps[0].suggestion


def test_ledger_capped(tmp_path: Path) -> None:
    learn = ApexLearning.load(
        tmp_path / "learning.jsonl", max_outcomes=ApexLearning.MAX_OUTCOMES
    )
    for i in range(ApexLearning.MAX_OUTCOMES + 10):
        learn.record_chain_outcome(_chain(), _run(), target=f"t{i}.test")
    assert learn.outcome_count() == ApexLearning.MAX_OUTCOMES


def test_corrupt_file_loads_empty(tmp_path: Path) -> None:
    path = tmp_path / "learning.jsonl"
    path.write_text("{not json at all\n", encoding="utf-8")
    learn = ApexLearning.load(path)
    assert learn.outcome_count() == 0
    assert learn.pattern_count() == 0


def test_persistence_roundtrip(tmp_path: Path) -> None:
    learn = ApexLearning.load(tmp_path / "learning.jsonl")
    learn.record_chain_outcome(_chain(), _run(), target="t.test")
    learn.record_tool_result("gau", success=True)
    reloaded = ApexLearning.load(tmp_path / "learning.jsonl")
    assert reloaded.outcome_count() == 1
    assert reloaded.get_tool_accuracy("gau") is None  # below MIN_SAMPLES
