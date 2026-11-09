"""The Apex Predator — U-APEX-6, the Adaptive Orchestrator (v87).

The heartbeat: a brain decision becomes a chain, the chain runs on the
parallel runner, results are fused in one place (APEX-L-6), and every
completion is recorded for the learning loop (APEX-L-7). APEX-L-3 SCOPE
BEFORE TOOL: the target is checked against the declared scope before any
step is scheduled, and the refusal is loud. APEX-L-9 ADVISORY-ONLY:
nothing here runs on its own — the caller supplies the step runner and
therefore the approval.

Deterministic for identical decisions: same decision + target produces a
byte-identical OrchestrationResult dict.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from webpent.apex.parallel_runner import ChainRunResult, ParallelRunner
from webpent.apex.sandbox import ScopeGuard
from webpent.apex.tool_chain_builder import ToolChain, ToolChainBuilder

PREAMBLE_LINE = (
    "advisory: orchestration translates brain decisions into vetted tool "
    "chains; the operator approves every run and scope gates every target."
)


@dataclass
class BrainDecision:
    """A decision handed over by the reasoning layer."""

    decision_id: str
    hypothesis_type: str
    target: str
    rationale: str = ""


@dataclass
class Target:
    """An in-scope target the operator has authorized work against."""

    host: str
    allowed_scopes: list[str] = field(default_factory=list)


@dataclass
class OrchestrationResult:
    """Everything one orchestration cycle produced, fused in one place."""

    decision_id: str
    hypothesis_type: str
    chain: ToolChain
    run: ChainRunResult
    fused_outputs: dict[str, dict] = field(default_factory=dict)
    advisory_note: str = PREAMBLE_LINE

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "hypothesis_type": self.hypothesis_type,
            "chain_id": self.chain.chain_id,
            "chain": self.chain.to_dict(),
            "run": self.run.to_dict(),
            "fused_outputs": self.fused_outputs,
            "advisory_note": self.advisory_note,
        }


@dataclass
class OrchestrationStatus:
    """A point-in-time view of the orchestrator."""

    state: str = "idle"
    chains_run: int = 0
    chains_completed: int = 0
    last_decision_id: str = ""
    feedback_queue: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "chains_run": self.chains_run,
            "chains_completed": self.chains_completed,
            "last_decision_id": self.last_decision_id,
            "feedback_queue": list(self.feedback_queue),
        }


StepRunner = Callable[[object], dict]


class AdaptiveOrchestrator:
    """Decision → chain → parallel run → fused result → learning record."""

    def __init__(
        self,
        builder: ToolChainBuilder,
        runner_factory: Callable[[], ParallelRunner] | None = None,
        scope_guard: ScopeGuard | None = None,
    ) -> None:
        self._builder = builder
        self._runner_factory = runner_factory or (lambda: ParallelRunner())
        self._scope_guard = scope_guard
        self._state = "idle"
        self._chains_run = 0
        self._chains_completed = 0
        self._last_decision_id = ""
        self._feedback: list[dict] = []
        self._learning: list[dict] = []

    # -- the main cycle ------------------------------------------------------

    def orchestrate(
        self,
        decision: BrainDecision,
        target: Target,
        runner: StepRunner | None = None,
    ) -> OrchestrationResult:
        """Run one full cycle for a decision. `runner` (per step → dict)
        is injected by the caller: nothing runs without it (APEX-L-9)."""
        # APEX-L-3 SCOPE BEFORE TOOL: refuse before anything is scheduled.
        guard = self._scope_guard or ScopeGuard(
            allowed_hosts=set(target.allowed_scopes)
        )
        guard.check([target.host])

        chain = self._builder.build(decision.hypothesis_type, decision.target)
        self._state = "running"
        self._last_decision_id = decision.decision_id
        self._chains_run += 1
        if runner is None:
            # RT-13: no runner injected means nothing was executed. The
            # honest result is a plan report with every step skipped, no
            # learning event, no completion count, and a feedback entry
            # that declares the planned-only nature of this cycle.
            from webpent.apex.parallel_runner import SKIPPED_EXIT, StepResult

            run = ChainRunResult(
                chain_id=chain.chain_id,
                step_results=[
                    StepResult(
                        step_id=s.step_id,
                        tool_id=s.tool_id,
                        exit_code=SKIPPED_EXIT,
                        skipped=True,
                        error="no runner injected",
                    )
                    for s in chain.steps
                ],
            )
            self._state = "idle"
            self._feedback.append(
                {
                    "kind": "chain_planned",
                    "decision_id": decision.decision_id,
                    "chain_id": chain.chain_id,
                    "planned_only": True,
                    "note": "no runner injected; nothing executed",
                }
            )
            return OrchestrationResult(
                decision_id=decision.decision_id,
                hypothesis_type=chain.hypothesis_type,
                chain=chain,
                run=run,
            )
        try:
            run = self._runner_factory().run(chain, runner)
        finally:
            self._state = "idle"
        steps_by_id = {s.step_id: s for s in chain.steps}
        fused = {
            steps_by_id[r.step_id].tool_id: dict(r.output)
            for r in run.step_results
            if not r.skipped and r.output
        }
        result = OrchestrationResult(
            decision_id=decision.decision_id,
            hypothesis_type=chain.hypothesis_type,
            chain=chain,
            run=run,
            fused_outputs=fused,
        )
        self._record_learning(decision, chain, run)
        self._chains_completed += 1
        self._feedback.append(
            {
                "kind": "chain_complete",
                "decision_id": decision.decision_id,
                "chain_id": chain.chain_id,
                "completed": run.completed,
                "failed": run.failed,
                "skipped": run.skipped,
            }
        )
        return result

    # -- feedback (the loop back to the brain) --------------------------------

    def on_tool_result(self, result: dict) -> None:
        """Feed one tool result back to the reasoning layer's queue."""
        self._feedback.append(dict(result))

    def on_chain_complete(self, chain: ToolChain) -> None:
        self._feedback.append(
            {
                "kind": "chain_complete",
                "chain_id": chain.chain_id,
                "hypothesis_type": chain.hypothesis_type,
            }
        )

    # -- observation -----------------------------------------------------------

    def get_status(self) -> OrchestrationStatus:
        return OrchestrationStatus(
            state=self._state,
            chains_run=self._chains_run,
            chains_completed=self._chains_completed,
            last_decision_id=self._last_decision_id,
            feedback_queue=list(self._feedback),
        )

    def learning_events(self) -> list[dict]:
        """APEX-L-7 LEARN FROM EVERYTHING: every completed cycle is on record."""
        return list(self._learning)

    # -- internal ---------------------------------------------------------------

    def _record_learning(
        self, decision: BrainDecision, chain: ToolChain, run: ChainRunResult
    ) -> None:
        self._learning.append(
            {
                "decision_id": decision.decision_id,
                "hypothesis_type": chain.hypothesis_type,
                "chain_id": chain.chain_id,
                "target": decision.target,
                "completed": run.completed,
                "failed": run.failed,
                "skipped": run.skipped,
                "measured_speedup": round(run.measured_speedup, 3),
                "total_duration_seconds": round(run.total_duration_seconds, 4),
            }
        )
