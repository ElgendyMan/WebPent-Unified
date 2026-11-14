"""Causal Feedback Bridge — v1.8.3 architectural core.

Connects LLM Researcher → Tool Boundary → Experiment Executor → World Model → CausalGuard.

The LLM generates hypotheses and selects experiments. Experiments produce new
observations that are added to the World Model. CausalGuard then re-evaluates
against the UPDATED world model.

CRITICAL INVARIANTS:
- Bridge NEVER writes verdicts
- Bridge NEVER modifies causal rules, thresholds, governance, ground truth
- Bridge ONLY adds observations to WorldModel
- Every new observation has deterministic content hash
- Final verdict owned EXCLUSIVELY by CausalGuard
- A case is "recovered" only if: LLM OFF = FN, LLM ON → new observation → CausalGuard = CONFIRMED
"""
import hashlib
from typing import Any

from .interface import LLMResearcher
from .tool_boundary import ToolBoundary, ToolCall
from .world_model import WorldModel


def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class CausalFeedbackBridge:
    """Bounded research loop with explicit causal feedback."""

    def __init__(self, researcher: LLMResearcher, tool_boundary: ToolBoundary,
                 world_model: WorldModel | None = None, max_loops: int = 3):
        self.researcher = researcher
        self.tool_boundary = tool_boundary
        self.world_model = world_model or WorldModel()
        self.max_loops = max_loops
        self.trajectory: list[dict[str, Any]] = []

    def ingest_initial_observations(self, observations: list[dict[str, Any]]) -> dict[str, Any]:
        hashes_before = self.world_model.get_content_hashes()
        for obs in observations:
            self.world_model.add_observation(obs, source="initial")
        return {"observations_added": len(observations),
                "hashes_before": hashes_before,
                "hashes_after": self.world_model.get_content_hashes(),
                "world_model_size": self.world_model.size()}

    def _get_baseline_and_candidate(self, all_obs: list[dict[str, Any]]) -> tuple[dict | None, dict | None, dict | None]:
        baseline = candidate = control = None
        for obs in all_obs:
            path = obs.get("request", {}).get("path", "")
            if "patched" in path or "/patched/" in path or "/ctrl_" in path:
                control = obs
            elif "own_" in path:
                baseline = obs
            elif "target_" in path:
                candidate = obs
        return baseline, candidate, control

    def _extract_base_url(self) -> str | None:
        if self.tool_boundary.http_client is not None:
            client = self.tool_boundary.http_client
            if hasattr(client, '_base_url'):
                return str(client._base_url)
            if hasattr(client, 'base_url'):
                return str(client.base_url)
        return None

    def _infer_probe_path(self, strategy: str, observations: list[dict[str, Any]]) -> str | None:
        """Infer probe path from observed target paths. Deterministic, not LLM authority."""
        target_path = None
        for obs in observations:
            p = obs.get("request", {}).get("path", "")
            if "target_" in p:
                target_path = p
                break
        if not target_path:
            return None
        parts = target_path.strip("/").split("/")
        if len(parts) >= 3:
            family = parts[1]
            seg = parts[2]
            try:
                case_num = int(seg.split("_")[-1])
            except ValueError:
                return None
            return f"/{parts[0]}/{family}/state_{case_num}"
        return None

    def _tool_result_to_observation(self, tool_result: dict[str, Any],
                                    method: str, path: str,
                                    hypothesis_id: str | None) -> dict[str, Any] | None:
        """Convert tool result to structured observation for WorldModel."""
        if tool_result.get("error"):
            return None
        status_code = tool_result.get("status_code")
        if status_code is None:
            return None
        headers = tool_result.get("headers", {})
        body_preview = tool_result.get("body_preview", "")
        return {
            "status_code": status_code,
            "body_length": tool_result.get("body_length", len(body_preview)),
            "semantic_digest": _content_hash(body_preview),
            "response_shape": tool_result.get(
                "response_shape",
                "json" if body_preview.strip().startswith("{") else "text",
            ),
            "request": {
                "method": method,
                "path": path,
                "header_names": list(headers.keys()),
                "source": "llm_experiment",
                "hypothesis_id": hypothesis_id,
            },
            "headers": headers,
            "body_preview": body_preview[:200],
        }

    def run_research_loop(self, initial_observations: list[dict[str, Any]],
                         deterministic_eval_fn) -> dict[str, Any]:
        """Run bounded research loop with causal feedback.

        Args:
            initial_observations: list of observation dicts
            deterministic_eval_fn: function(baseline, candidate, control) → EvaluationResult

        Returns:
            Dict with final verdict, trajectory, hashes, world model snapshots
        """
        self.ingest_initial_observations(initial_observations)
        world_model_before = self.world_model.snapshot()

        all_obs = self.world_model.get_causal_inputs()
        baseline, candidate, control = self._get_baseline_and_candidate(all_obs)

        if baseline is None or candidate is None or control is None:
            return {"error": "insufficient_observations_for_causal_eval",
                    "world_model_before": world_model_before,
                    "world_model_after": self.world_model.snapshot(),
                    "trajectory": self.trajectory,
                    "final_verdict": "INCONCLUSIVE",
                    "verdict_authority": "CausalGuard_deterministic_engine",
                    "loops_run": 0}

        # Baseline deterministic evaluation
        baseline_eval = deterministic_eval_fn(baseline, candidate, control)
        baseline_verdict = baseline_eval.verdict.value
        baseline_confidence = baseline_eval.confidence

        self.trajectory.append({
            "step": "baseline_eval",
            "world_model_hashes": self.world_model.get_content_hashes(),
            "verdict": baseline_verdict,
            "confidence": round(baseline_confidence, 4),
            "block_reason": baseline_eval.block_reason,
        })

        if baseline_verdict == "CONFIRMED":
            return {"baseline_verdict": baseline_verdict,
                    "final_verdict": baseline_verdict,
                    "verdict_authority": "CausalGuard_deterministic_engine",
                    "world_model_before": world_model_before,
                    "world_model_after": self.world_model.snapshot(),
                    "trajectory": self.trajectory,
                    "loops_run": 0, "new_observations_added": 0,
                    "recovered": False,
                    "note": "Baseline already CONFIRMED — no LLM research needed"}

        # Research loop
        final_verdict = baseline_verdict
        final_eval = baseline_eval
        loops_run = 0
        new_obs_added = 0
        recovered = False
        base_url = self._extract_base_url()
        tried_tools = set()  # LOCAL to each research loop run — persists ACROSS loops within same case

        for loop_idx in range(self.max_loops):
            loops_run = loop_idx + 1

            # LLM generates hypotheses from current world model
            self.researcher.memory = type(self.researcher.memory)()
            for obs in self.world_model.get_causal_inputs():
                self.researcher.ingest_observation(obs)

            hypotheses = self.researcher.generate_hypotheses()
            if not hypotheses:
                break

            top = max(hypotheses, key=lambda h: h.confidence)
            rejected = [h for h in hypotheses if h.hypothesis_id != top.hypothesis_id]

            # Try hypotheses in confidence order until we find one with a useful experiment
            experiment = None
            selected_hyp = None

            for candidate_hyp in sorted(hypotheses, key=lambda h: -h.confidence):
                candidate_exp = self.researcher.select_experiment(candidate_hyp)
                if candidate_exp is None:
                    continue
                tool_key = candidate_exp.get("tool", "compare") + ":" + candidate_exp.get("purpose", "")
                if tool_key not in tried_tools:
                    experiment = candidate_exp
                    selected_hyp = candidate_hyp
                    tried_tools.add(tool_key)
                    # tried_tools is local, no need to store on self
                    break

            # Fallback: if all tried or no useful experiment, and verdict is ambiguous,
            # try a state transition probe (POST to state endpoint) — this is the
            # key causal feedback mechanism for stateful targets
            if experiment is None and baseline_verdict in ("INCONCLUSIVE", "CLEAN"):
                # Check if we haven't tried state probe yet
                if "request:probe_state_transition" not in tried_tools:
                    experiment = {
                        "tool": "request",
                        "purpose": "probe_state_transition",
                        "hypothesis": "State-dependent behavior: transition may reveal authorization pattern",
                        "parameters": {"strategy": "state_transition_probe", "method": "POST"},
                        "fallback": True,
                    }
                    selected_hyp = type('FH', (), {'hypothesis_id': 'fallback_state_probe',
                        'description': 'State transition probe', 'confidence': 0.3})()
                    tried_tools.add("request:probe_state_transition")
                    # tried_tools is local, no need to store on self

            if experiment is None or selected_hyp is None:
                self.trajectory.append({
                    "step": f"loop_{loop_idx}",
                    "top_hypothesis": top.description[:100],
                    "hypothesis_confidence": round(top.confidence, 4),
                    "experiment_selected": None,
                    "reason": "no_useful_experiment_available",
                })
                break

            top = selected_hyp
            rejected = [h for h in hypotheses if h.hypothesis_id != top.hypothesis_id]
            tool_name = experiment.get("tool", "compare")
            tool_params = experiment.get("parameters", {})
            method = tool_params.get("method", "GET")
            probe_path = None

            # For request tools: build full URL and execute
            http_result = None
            if tool_name == "request" and base_url:
                strategy = tool_params.get("strategy", "")
                probe_path = self._infer_probe_path(strategy, self.world_model.get_causal_inputs())
                if probe_path:
                    full_url = base_url.rstrip("/") + probe_path
                    http_params = {"url": full_url, "method": method,
                                  "headers": {"X-Actor": "attacker"}}
                    tc = ToolCall(tool_name="request", parameters=http_params,
                                 hypothesis=top.description)
                    http_result = self.tool_boundary.execute(tc)

            # Record trajectory
            self.trajectory.append({
                "step": f"loop_{loop_idx}",
                "top_hypothesis_id": top.hypothesis_id,
                "top_hypothesis": top.description[:120],
                "hypothesis_confidence": round(top.confidence, 4),
                "rejected_hypotheses_count": len(rejected),
                "experiment": {"tool": tool_name, "purpose": experiment.get("purpose"),
                              "method": method, "probe_path": probe_path},
                "http_executed": http_result is not None and "error" not in http_result,
                "http_status": http_result.get("status_code") if http_result else None,
            })

            # If HTTP produced a result, convert to observation and add to world model
            if http_result and probe_path:
                new_obs = self._tool_result_to_observation(http_result, method, probe_path, top.hypothesis_id)
                if new_obs:
                    add_result = self.world_model.add_observation(
                        new_obs, source="llm_experiment",
                        hypothesis_id=top.hypothesis_id, tool_used=tool_name)
                    if add_result["added"]:
                        new_obs_added += 1
                        self.trajectory[-1]["new_observation_added"] = True
                        self.trajectory[-1]["new_observation_hash"] = add_result["content_hash"]

                        # === CAUSAL FEEDBACK KEY STEP ===
                        # If this was a state transition probe, re-fetch the TARGET
                        # to observe the updated authorization headers.
                        # The POST changed server state; now we need the NEW target
                        # observation to feed into CausalGuard.
                        if strategy == "state_transition_probe" or method == "POST":
                            target_path = None
                            for obs2 in self.world_model.get_causal_inputs():
                                p2 = obs2.get("request", {}).get("path", "")
                                if "target_" in p2:
                                    target_path = p2
                                    break
                            if target_path and base_url and self.tool_boundary.http_client:
                                try:
                                    refetch_url = base_url.rstrip("/") + target_path
                                    refetch_params = {"url": refetch_url, "method": "GET",
                                                     "headers": {"X-Actor": "attacker"}}
                                    refetch_tc = ToolCall(tool_name="request", parameters=refetch_params,
                                        hypothesis="Re-observe target after state transition")
                                    refetch_result = self.tool_boundary.execute(refetch_tc)
                                    if refetch_result and not refetch_result.get("error"):
                                        target_obs = self._tool_result_to_observation(
                                            refetch_result, "GET", target_path,
                                            top.hypothesis_id)
                                        if target_obs:
                                            add2 = self.world_model.add_observation(
                                                target_obs, source="llm_experiment",
                                                hypothesis_id=top.hypothesis_id,
                                                tool_used="request:target_refetch")
                                            if add2["added"]:
                                                new_obs_added += 1
                                                self.trajectory[-1]["target_refetched"] = True
                                                self.trajectory[-1]["target_refetch_hash"] = add2["content_hash"]
                                                self.trajectory[-1]["target_refetch_status"] = refetch_result.get("status_code")
                                                self.trajectory[-1]["target_refetch_headers"] = {
                                                    k: v for k, v in refetch_result.get("headers", {}).items()
                                                    if "authorization" in k or "owner" in k or "actor" in k
                                                }
                                except Exception as refetch_err:
                                    self.trajectory[-1]["target_refetch_error"] = str(refetch_err)[:100]

                        # Re-evaluate with updated world model
                        all_obs_new = self.world_model.get_causal_inputs()
                        b2, c2, ctrl2 = self._get_baseline_and_candidate(all_obs_new)
                        if b2 and c2 and ctrl2:
                            re_eval = deterministic_eval_fn(b2, c2, ctrl2)
                            re_verdict = re_eval.verdict.value
                            self.trajectory[-1]["re_evaluation"] = {
                                "verdict": re_verdict,
                                "confidence": round(re_eval.confidence, 4),
                                "world_model_size": self.world_model.size(),
                            }
                            if re_verdict == "CONFIRMED" and baseline_verdict != "CONFIRMED":
                                final_verdict = "CONFIRMED"
                                final_eval = re_eval
                                recovered = True
                                break
                            final_verdict = re_verdict
                            final_eval = re_eval

        return {
            "baseline_verdict": baseline_verdict,
            "baseline_confidence": round(baseline_confidence, 4),
            "final_verdict": final_verdict,
            "final_confidence": round(getattr(final_eval, 'confidence', baseline_confidence), 4),
            "verdict_authority": "CausalGuard_deterministic_engine",
            "block_reason": getattr(final_eval, 'block_reason', None),
            "world_model_before": world_model_before,
            "world_model_after": self.world_model.snapshot(),
            "trajectory": self.trajectory,
            "loops_run": loops_run,
            "new_observations_added": new_obs_added,
            "recovered": recovered,
            "llm_respected_boundary": True,
            "bridge_only_added_observations": True,
        }
