"""U-APEX-6 — The Adaptive Orchestrator (v87).

Law under proof: APEX-L-6 FUSE RESULTS, APEX-L-7 LEARN FROM EVERYTHING,
APEX-L-9 ADVISORY-ONLY. The orchestrator is the heartbeat: decision →
chain → parallel run → fused result → learning record. Deterministic for
identical decisions. The step runner is injected; no real tools run here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from webpent.apex.orchestrator import (
    PREAMBLE_LINE,
    BrainDecision,
    OrchestrationStatus,
    Target,
)
from webpent.apex.parallel_runner import ParallelRunner
from webpent.apex.sandbox import ScopeViolationError
from webpent.apex.tool_chain_builder import ToolChainBuilder
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


@pytest.fixture()
def decision() -> BrainDecision:
    return BrainDecision(
        decision_id="dec-001",
        hypothesis_type="xss",
        target="target.test",
        rationale="reflected input observed at /search",
    )


def _recording_runner(calls: list[str]):
    def runner(step):
        calls.append(step.tool_id)
        return {"tool_id": step.tool_id, "exit_code": 0, "findings": 1}

    return runner


def test_orchestrate_full_cycle(
    builder: ToolChainBuilder, decision: BrainDecision
) -> None:
    calls: list[str] = []
    orch = _make_orchestrator(builder)
    result = orch.orchestrate(
        decision, Target(host="target.test", allowed_scopes=["target.test"]),
        runner=_recording_runner(calls),
    )
    # chain was built from the decision's hypothesis
    assert result.chain.hypothesis_type == "xss"
    assert [s.tool_id for s in result.chain.steps] == ["gau", "dalfox"]
    # every step executed via the injected runner, in dependency order
    assert calls == ["gau", "dalfox"]
    # results collected and fused (L-6): per-step outputs visible in one place
    assert "gau" in result.fused_outputs
    assert "dalfox" in result.fused_outputs
    assert result.fused_outputs["dalfox"]["findings"] == 1
    # learning recorded (L-7)
    events = orch.learning_events()
    assert len(events) == 1
    assert events[0]["decision_id"] == "dec-001"
    assert events[0]["chain_id"] == result.chain.chain_id
    assert PREAMBLE_LINE in result.advisory_note


def test_brain_feedback_loop(
    builder: ToolChainBuilder, decision: BrainDecision
) -> None:
    orch = _make_orchestrator(builder)
    calls: list[str] = []
    result = orch.orchestrate(
        decision, Target(host="target.test", allowed_scopes=["target.test"]),
        runner=_recording_runner(calls),
    )
    # feeding a tool result back lands in the feedback queue (alongside the
    # automatic chain_complete entry orchestrate appends per cycle)
    orch.on_tool_result({"step_id": "gau-1", "exit_code": 0})
    status = orch.get_status()
    tool_feedback = [
        f for f in status.feedback_queue if "kind" not in f
    ]
    assert len(tool_feedback) == 1
    assert tool_feedback[0]["step_id"] == "gau-1"
    # the completed chain itself is also available as feedback
    orch.on_chain_complete(result.chain)
    assert orch.get_status().chains_completed == 1


def test_status_reflects_state(
    builder: ToolChainBuilder, decision: BrainDecision
) -> None:
    orch = _make_orchestrator(builder)
    seen_states: list[str] = []

    def runner(step):
        # capture the state from inside a live step
        seen_states.append(orch.get_status().state)
        return {"tool_id": step.tool_id, "exit_code": 0}

    before = orch.get_status()
    assert isinstance(before, OrchestrationStatus)
    assert before.state == "idle"
    assert before.chains_run == 0

    orch.orchestrate(
        decision,
        Target(host="target.test", allowed_scopes=["target.test"]),
        runner=runner,
    )
    assert seen_states == ["running", "running"], (
        "orchestrator must report 'running' while steps execute"
    )
    after = orch.get_status()
    assert after.state == "idle"
    assert after.chains_run == 1
    assert after.last_decision_id == "dec-001"


def _deterministic_view(data: dict) -> dict:
    """Strip wall-clock measurements — they are observations, not plan
    content. Determinism covers everything else."""
    import copy

    data = copy.deepcopy(data)
    data["run"].pop("total_duration_seconds")
    data["run"].pop("sum_step_durations")
    data["run"].pop("measured_speedup")
    for step in data["run"]["steps"]:
        step.pop("duration_seconds")
    return data


def test_deterministic_orchestration(
    builder: ToolChainBuilder, decision: BrainDecision
) -> None:
    orch = _make_orchestrator(builder)
    target = Target(host="target.test", allowed_scopes=["target.test"])
    first = _deterministic_view(
        orch.orchestrate(decision, target, runner=_recording_runner([])).to_dict()
    )
    second = _deterministic_view(
        orch.orchestrate(decision, target, runner=_recording_runner([])).to_dict()
    )
    assert first == second, "same decision must produce identical result"


def test_out_of_scope_target_is_refused(
    builder: ToolChainBuilder, decision: BrainDecision
) -> None:
    """APEX-L-3 SCOPE BEFORE TOOL: a target outside the allowed scope is
    refused before any tool is scheduled — fail closed."""
    orch = _make_orchestrator(builder)
    calls: list[str] = []
    with pytest.raises(ScopeViolationError):
        orch.orchestrate(
            decision,
            Target(host="evil.test", allowed_scopes=["target.test"]),
            runner=_recording_runner(calls),
        )
    assert calls == [], "no tool may run for an out-of-scope target"


def test_unknown_hypothesis_still_orchestrates_with_fallback(
    builder: ToolChainBuilder,
) -> None:
    orch = _make_orchestrator(builder)
    decision = BrainDecision(
        decision_id="dec-002", hypothesis_type="telepathy",
        target="target.test",
    )
    result = orch.orchestrate(
        decision,
        Target(host="target.test", allowed_scopes=["target.test"]),
        runner=_recording_runner([]),
    )
    assert result.chain.hypothesis_type == "fallback"
    assert result.chain.fallback_reason


def _make_orchestrator(builder: ToolChainBuilder):
    from webpent.apex.orchestrator import AdaptiveOrchestrator

    return AdaptiveOrchestrator(builder=builder, runner_factory=ParallelRunner)
