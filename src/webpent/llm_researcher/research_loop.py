"""LLM Research Loop — bounded autonomous research.

Track F of GOED v1.8:

OBSERVATION
→ WORLD MODEL UPDATE
→ HYPOTHESES
→ COMPETING HYPOTHESES
→ EXPERIMENT SELECTION
→ TOOL EXECUTION
→ EVIDENCE
→ INTERPRETATION
→ DETERMINISTIC VALIDATION
→ PROOF OR REJECTION

The loop continues only when expected information gain justifies another
bounded experiment. Blind probe flooding is prevented by:
1. Information gain estimation before each experiment
2. Maximum loop count
3. Maximum tool calls per loop
4. Minimum information gain threshold
"""
from dataclasses import dataclass, field
from typing import Any

from .interface import (
    Hypothesis,
    HypothesisStatus,
    LLMResearcher,
)
from .tool_boundary import ToolBoundary, ToolCall


@dataclass
class LoopResult:
    loop_count: int = 0
    hypotheses_generated: int = 0
    hypotheses_supported: int = 0
    hypotheses_rejected: int = 0
    tool_calls: int = 0
    experiments_run: int = 0
    information_gain_estimate: float = 0.0
    stop_reason: str = ""
    findings_for_deterministic_validation: list[dict[str, Any]] = field(default_factory=list)


class ResearchLoop:
    """Bounded autonomous research loop.

    CRITICAL SAFETY:
    The loop produces CANDIDATE findings that are then passed to the
    deterministic CausalGuard engine for authoritative validation.
    The loop itself NEVER confirms a vulnerability.
    The deterministic oracle remains the SOLE authority for verdicts.
    """

    def __init__(self, researcher: LLMResearcher, tool_boundary: ToolBoundary,
                 max_loops: int = 10,
                 min_information_gain: float = 0.05):
        self.researcher = researcher
        self.tool_boundary = tool_boundary
        self.max_loops = max_loops
        self.min_information_gain = min_information_gain

    def run(self, initial_observations: list[dict[str, Any]]) -> LoopResult:
        """Run the bounded research loop."""
        result = LoopResult()

        # Phase 1: Ingest initial observations
        for obs in initial_observations:
            self.researcher.ingest_observation(obs)

        for loop_idx in range(self.max_loops):
            self.researcher.memory.loop_count += 1
            result.loop_count = loop_idx + 1

            # Step 1: WORLD MODEL UPDATE — generate hypotheses from observations
            hypotheses = self.researcher.generate_hypotheses()
            result.hypotheses_generated += len(hypotheses)

            if not hypotheses:
                result.stop_reason = "no_new_hypotheses"
                break

            # Step 2: Identify COMPETING hypotheses
            self._identify_competing_hypotheses(hypotheses)

            # Step 3: Select highest-value experiment (top hypothesis)
            active_hypotheses = [h for h in hypotheses
                                 if h.status in (HypothesisStatus.PROPOSED,
                                                HypothesisStatus.COMPETING)]
            if not active_hypotheses:
                result.stop_reason = "no_active_hypotheses"
                break

            top_hypothesis = max(active_hypotheses, key=lambda h: h.confidence)

            # Step 4: Estimate information gain — stop if too low (prevents blind probing)
            info_gain = self._estimate_information_gain(top_hypothesis)
            result.information_gain_estimate = info_gain

            if info_gain < self.min_information_gain and loop_idx > 0:
                result.stop_reason = (
                    f"information_gain_below_threshold "
                    f"({info_gain:.3f} < {self.min_information_gain})"
                )
                break

            # Step 5: Select experiment plan
            experiment = self.researcher.select_experiment(top_hypothesis)
            if experiment is None:
                result.stop_reason = "no_experiment_selected"
                break

            # Step 6: Execute BOUNDED tool call via strict boundary
            tool_call = ToolCall(
                tool_name=experiment.get("tool", "request"),
                parameters=experiment.get("parameters", {}),
                hypothesis=top_hypothesis.description,
            )
            tool_result = self.tool_boundary.execute(tool_call)
            result.tool_calls += 1
            result.experiments_run += 1

            # Step 7: INTERPRET result and update hypothesis
            if tool_result.get("error"):
                top_hypothesis.status = HypothesisStatus.REJECTED
                result.hypotheses_rejected += 1
                top_hypothesis.evidence_against.append({
                    "loop": loop_idx,
                    "error": tool_result.get("error"),
                })
            else:
                top_hypothesis.status = HypothesisStatus.SUPPORTED
                result.hypotheses_supported += 1
                top_hypothesis.evidence_supporting.append({
                    "loop": loop_idx,
                    "tool": experiment.get("tool"),
                    "result_summary": str(tool_result)[:300],
                })

                # Pass to DETERMINISTIC VALIDATION queue
                # IMPORTANT: This is a CANDIDATE only. Final verdict comes from
                # CausalGuard, not from the LLM or research loop.
                result.findings_for_deterministic_validation.append({
                    "hypothesis_id": top_hypothesis.hypothesis_id,
                    "description": top_hypothesis.description,
                    "llm_confidence": top_hypothesis.confidence,
                    "evidence": tool_result,
                    "loop_index": loop_idx,
                    "note": "CANDIDATE_ONLY — requires deterministic CausalGuard validation",
                })

            # Step 8: Ingest tool result as new observation (sanitized)
            if not tool_result.get("error"):
                self.researcher.ingest_observation({
                    "source": "tool_call_result",
                    "tool": experiment.get("tool"),
                    "loop_index": loop_idx,
                    "status": "completed_bounded",
                })

            # Safety: bounded tool calls per loop
            if (self.tool_boundary.tool_calls_total
                    > self.researcher.max_tool_calls_per_loop):
                result.stop_reason = "tool_call_budget_exceeded"
                break

        if not result.stop_reason:
            result.stop_reason = "max_loops_reached"

        return result

    def _identify_competing_hypotheses(self, hypotheses: list[Hypothesis]) -> None:
        """Mark hypotheses that compete to explain overlapping observations."""
        for i, h1 in enumerate(hypotheses):
            for j, h2 in enumerate(hypotheses):
                if i < j and self._hypotheses_compete(h1, h2):
                    h1.status = HypothesisStatus.COMPETING
                    h2.status = HypothesisStatus.COMPETING
                    h1.competing_with = h2.hypothesis_id
                    h2.competing_with = h1.hypothesis_id

    def _hypotheses_compete(self, h1: Hypothesis, h2: Hypothesis) -> bool:
        """Two hypotheses compete if they address overlapping observations
        with substantially different explanations."""
        words1 = set(h1.description.lower().split())
        words2 = set(h2.description.lower().split())
        if not words1 or not words2:
            return False
        overlap = len(words1 & words2) / max(len(words1 | words2), 1)
        return overlap > 0.3

    def _estimate_information_gain(self, hypothesis: Hypothesis) -> float:
        """Estimate expected information gain from testing a hypothesis.

        Simple heuristic: uncertainty * relevance.
        - Hypotheses near 0.5 confidence have highest uncertainty
        - Higher confidence hypotheses are more relevant

        This prevents blind probe flooding by gating low-value experiments.
        """
        # Uncertainty: peaks at confidence = 0.5
        uncertainty = 1.0 - abs(hypothesis.confidence - 0.5) * 2
        # Relevance: how confident we are that there's something to find
        relevance = min(1.0, hypothesis.confidence + 0.2)
        return uncertainty * relevance
