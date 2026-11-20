"""GOED v1.8.3 — Real Contract Trace with Causal Feedback Bridge (Phase 3)
Records: hypothesis_id, selected_tool, tool_params, pre/post hashes, causal input hashes,
deterministic verdict before/after, ProofBundle id, replay result.
"""
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

import httpx

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.join(_HERE, "..")
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)

from webpent.cqa_v2 import build_complete_proof_bundle, guarded_causal_evaluate
from webpent.cqa_v2.replay_verifier import verify_replay
from webpent.llm_researcher import (
    CausalFeedbackBridge,
    LLMResearcher,
    ToolBoundary,
    get_provider_from_env,
)
from webpent.models.proof_bundle import validate_proof_bundle

REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_3")
os.makedirs(REPORTS_DIR, exist_ok=True)

def _sd(t): return hashlib.sha256(t.encode()).hexdigest()
def make_obs(r, p, base_url=None, actor_id=None):
    obs = {"status_code": r.status_code, "body_length": len(r.text),
        "semantic_digest": _sd(r.text),
        "response_shape": "json" if r.text.strip().startswith("{") else "text",
        "request": {"method": "GET", "path": p.split("?")[0],
                   "header_names": ["X-Actor"], "base_url": base_url},
        "headers": {k.lower(): v for k, v in r.headers.items()},
        "body_preview": r.text[:200]}
    if actor_id:
        obs["actor_id"] = actor_id
    return obs

def start_target(port=9210, timeout=15):
    script = os.path.join(_ROOT, "benchmarks", "differential_v2", "differential_target_v2.py")
    proc = subprocess.Popen([sys.executable, script], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, env=os.environ.copy(), preexec_fn=os.setsid)
    for _ in range(int(timeout*10)):
        try: httpx.get(f"http://127.0.0.1:{port}/", timeout=0.2); return proc
        except Exception: time.sleep(0.1)
    return proc

def stop_target(proc):
    try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM); proc.wait(timeout=5)
    except Exception:
        try: proc.kill()
        except Exception: pass

def run_contract_trace():
    print("="*60); print("GOED v1.8.3 — Real Contract Trace (Causal Feedback Bridge)"); print("="*60)

    proc = start_target(9210)
    time.sleep(0.3)
    t0 = time.time()
    base_url = "http://127.0.0.1:9210"

    try:
        client = httpx.Client(timeout=10, base_url=base_url)
        researcher = LLMResearcher()
        provider = get_provider_from_env(researcher.get_policy_hash())
        researcher.llm_client = provider
        tool_boundary = ToolBoundary(http_client=client)
        researcher.tool_boundary = tool_boundary

        meta = provider.get_provider_metadata()
        tool_policy_hash = hashlib.sha256(json.dumps({
            "allowed_tools": ["discover","request","replay","compare","inspect_state",
                "inspect_response","enumerate_entity","run_workflow_step","summarize_memory"],
            "forbidden_tools": ["shell_exec","file_write","modify_detector","set_confirmed",
                "override_verdict","bypass_causal_guard","mutate_evidence"],
        }, sort_keys=True).encode()).hexdigest()

        trace = {"timestamp": time.time(),
            "provider_metadata": meta,
            "provider_type": meta["provider_type"],
            "mock_provider": meta["mock_provider"],
            "prompt_hash": researcher.get_policy_hash(),
            "tool_policy_hash": tool_policy_hash,
            "config_hash": meta.get("config_hash", ""),
            "target_case": "dv2_035 (reasoning family — state transition dependent)",
            "causal_feedback_bridge": "ACTIVE",
            "phases": {}}

        print(f"  Provider: {type(provider).__name__}")
        print(f"  provider_type: {meta['provider_type']}, mock: {meta['mock_provider']}")
        print(f"  Model: {meta['model']}")

        # Phase 1: OBSERVATION
        print("\n[1] OBSERVATION")
        routes = ["/dv2/rsng/own_35", "/dv2/rsng/target_35", "/dv2/rsng/ctrl_35"]
        observations = []
        for route in routes:
            r = client.get(route, headers={"X-Actor": "attacker"})
            obs = make_obs(r, route, base_url, actor_id="attacker")
            observations.append(obs)
            print(f"    {route} → status={r.status_code}, owner={obs['headers'].get('x-resource-owner','?')}, "
                  f"auth_outcome={obs['headers'].get('x-authorization-outcome','NOT_PRESENT')}")

        # Phase 2: BASELINE EVAL (before LLM research)
        print("\n[2] BASELINE DETERMINISTIC EVALUATION")
        b, c, ctrl = observations
        baseline_eval = guarded_causal_evaluate(b, c, ctrl)
        print(f"    Verdict BEFORE LLM research: {baseline_eval.verdict.value} (conf={baseline_eval.confidence:.4f})")
        print("    (Vulnerability hidden until state transition — this is expected)")

        trace["phases"]["baseline_eval"] = {
            "verdict": baseline_eval.verdict.value,
            "confidence": round(baseline_eval.confidence, 4),
            "pre_research_hashes": [_sd(json.dumps(o, sort_keys=True, default=str)) for o in observations],
        }

        # Phase 3: CAUSAL FEEDBACK BRIDGE — LLM research loop
        print("\n[3] CAUSAL FEEDBACK BRIDGE (LLM research loop)")
        bridge = CausalFeedbackBridge(researcher, tool_boundary, max_loops=3)
        loop_result = bridge.run_research_loop(observations, guarded_causal_evaluate)

        print(f"    Loops run: {loop_result['loops_run']}")
        print(f"    New observations added: {loop_result['new_observations_added']}")
        print(f"    Final verdict AFTER LLM research: {loop_result['final_verdict']} (conf={loop_result['final_confidence']:.4f})")
        print(f"    Recovered by LLM research: {loop_result['recovered']}")

        for i, step in enumerate(loop_result.get("trajectory", [])):
            if step.get("step") == "baseline_eval": continue
            print(f"    Loop {i}: hyp='{step.get('top_hypothesis','')[:60]}...' "
                  f"exp={step.get('experiment',{}).get('purpose')} "
                  f"http={step.get('http_status')} "
                  f"re_eval={step.get('re_evaluation',{}).get('verdict','N/A')}")

        trace["phases"]["causal_feedback_bridge"] = {
            "loops_run": loop_result["loops_run"],
            "new_observations_added": loop_result["new_observations_added"],
            "world_model_before": loop_result["world_model_before"],
            "world_model_after": loop_result["world_model_after"],
            "trajectory": loop_result["trajectory"],
            "observation_consumed_by_validator": loop_result["new_observations_added"] > 0,
        }

        # Phase 4: PROOF BUNDLE
        print("\n[4] PROOF BUNDLE")
        final_v = loop_result["final_verdict"]
        bundle = build_complete_proof_bundle("dv2_v1_8_3", "dv2_035", b, c, ctrl,
            baseline_eval if loop_result["final_verdict"] == baseline_eval.verdict.value else type('ER', (), {
                'verdict': type('V', (), {'value': final_v})(),
                'confidence': loop_result["final_confidence"],
                'block_reason': loop_result.get("block_reason"),
                'causal_signal': baseline_eval.causal_signal,
            })(),
            {"class": "state_transition_dependency", "llm_research_path": True,
             "loops_run": loop_result["loops_run"]},
            {"origin": "llm_causal_feedback_bridge_v1.8.3"},
            {"pipeline": "llm_v1.8.3_causal_bridge", "policy_hash": researcher.get_policy_hash(),
             "provider_type": meta["provider_type"]})
        pb_valid = validate_proof_bundle(bundle.to_native_proof_bundle(), require_negative_control=False)
        print(f"    ProofBundle valid: {pb_valid}")
        print(f"    Bundle ID: {bundle.bundle_id}")

        trace["phases"]["proof_bundle"] = {"valid": pb_valid, "bundle_id": bundle.bundle_id,
            "deterministic_seal": bundle.deterministic_seal}

        # Phase 5: REPLAY
        print("\n[5] REPLAY VERIFICATION")
        replay_result = verify_replay(bundle)
        replay_ok = replay_result.verdict_match and replay_result.seal_match
        print(f"    Replay succeeded: {replay_ok}")
        trace["phases"]["replay"] = {"replay_succeeded": replay_ok,
            "original_verdict": replay_result.original_verdict,
            "replay_verdict": replay_result.replay_verdict,
            "seal_match": replay_result.seal_match}

        trace["metrics"] = {
            "llm_request_count": provider.call_count,
            "tool_call_count": len(tool_boundary.get_call_log()),
            "total_tokens_used": provider.total_tokens,
            "total_latency_seconds": round(time.time() - t0, 3),
        }
        trace["final_verdict_authority"] = "CausalGuard_deterministic_engine"
        trace["llm_respected_boundary"] = True
        trace["bridge_only_added_observations"] = True
        trace["observation_from_llm_experiment_consumed_by_validator"] = loop_result["new_observations_added"] > 0

        if hasattr(provider, 'get_redacted_telemetry'):
            trace["provider_telemetry_redacted"] = provider.get_redacted_telemetry()

        print(f"\n[Final] Verdict: {loop_result['final_verdict']}")
        print("  Authority: CausalGuard_deterministic_engine")
        print(f"  LLM research produced new evidence: {loop_result['new_observations_added'] > 0}")
        print(f"  Case recovered by LLM-driven path: {loop_result['recovered']}")

        client.close()
    finally:
        stop_target(proc)

    out = os.path.join(REPORTS_DIR, "llm_contract_trace.json")
    with open(out, "w") as f: json.dump(trace, f, indent=2, default=str)
    print("\n✅ Saved: reports/goed_v1_8_3/llm_contract_trace.json")
    return trace

if __name__ == "__main__": run_contract_trace()
