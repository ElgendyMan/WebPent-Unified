"""GOED v1.8.4 — Phase 6: Real Contract Trace with Causal Feedback Bridge
Records: hypothesis_id, selected_tool, tool_params, pre/post hashes, causal input hashes,
deterministic verdict before/after, ProofBundle id, replay result.
Uses v1.8.4 provider pool and stricter replay verifier.
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
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
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

REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_4")
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
    print("=" * 60)
    print("GOED v1.8.4 — Phase 6: Real Contract Trace")
    print("=" * 60)

    # Check real API gate FIRST
    provider = get_provider_from_env("contract-trace")
    if provider is None or getattr(provider, 'mock_provider', True):
        result = {"phase": "6_contract_trace", "status": "REAL_API_UNAVAILABLE",
                  "note": "LLM_API_KEY not set or mock active. Phase 6 requires real LLM."}
        with open(os.path.join(REPORTS_DIR, "contract_trace_v184.json"), "w") as f:
            json.dump(result, f, indent=2)
        print("REAL_API_UNAVAILABLE — report written.")
        return

    proc = start_target(9210)
    time.sleep(0.3)
    base_url = "http://127.0.0.1:9210"

    try:
        client = httpx.Client(timeout=10, base_url=base_url)
        researcher = LLMResearcher()
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

        # Pick a reasoning-family case from differential_v2
        with open(os.path.join(_ROOT, "benchmarks", "differential_v2", "manifest.json")) as f:
            manifest = json.load(f)
        with open(os.path.join(_ROOT, "benchmarks", "differential_v2", "ground_truth.json")) as f:
            ground_truth = json.load(f)

        # Find a reasoning/vulnerable case
        target_case_id = None
        for cid, c in manifest["cases"].items():
            if c.get("family") == "reasoning" and ground_truth.get(cid, {}).get("expected_label") == "vulnerable":
                target_case_id = cid
                break

        if target_case_id is None:
            result = {"phase": "6_contract_trace", "status": "FAILED",
                      "note": "No reasoning-family vulnerable case found in manifest"}
            with open(os.path.join(REPORTS_DIR, "contract_trace_v184.json"), "w") as f:
                json.dump(result, f, indent=2)
            return

        case = manifest["cases"][target_case_id]
        rb = client.get(case["baseline"], headers={"X-Actor":"attacker"})
        rc = client.get(case["candidate"], headers={"X-Actor":"attacker"})
        rctrl = client.get(case["control"], headers={"X-Actor":"attacker"})
        b = make_obs(rb, case["baseline"], base_url, "attacker")
        c = make_obs(rc, case["candidate"], base_url, "attacker")
        ctrl = make_obs(rctrl, case["control"], base_url, "attacker")

        pre_inputs_hash = hashlib.sha256(json.dumps({
            "b_digest": b["semantic_digest"],
            "c_digest": c["semantic_digest"],
            "ctrl_digest": ctrl["semantic_digest"],
        }, sort_keys=True).encode()).hexdigest()

        bridge = CausalFeedbackBridge(researcher, tool_boundary, max_loops=3)
        loop_result = bridge.run_research_loop([b, c, ctrl], guarded_causal_evaluate)

        verdict = loop_result["final_verdict"]
        trajectory = loop_result.get("trajectory", [])

        # Build proof bundle and validate
        proof_bundle = None
        proof_valid = False
        replay_result = None
        if verdict == "CONFIRMED":
            try:
                proof_bundle = build_complete_proof_bundle(
                    observations=[b, c, ctrl],
                    trajectory=trajectory,
                    final_verdict=verdict,
                    target_info={"base_url": base_url, "case_id": target_case_id}
                )
                proof_valid = validate_proof_bundle(proof_bundle)
                replay_result = verify_replay(proof_bundle)
            except Exception as e:
                proof_bundle = {"error": str(e)}

        trace = {
            "phase": "6_contract_trace",
            "status": "OK",
            "timestamp": time.time(),
            "target_case_id": target_case_id,
            "target_case_family": case.get("family"),
            "provider_metadata": meta,
            "provider_type": meta.get("provider_type"),
            "mock_provider": meta.get("mock_provider", False),
            "prompt_hash": researcher.get_policy_hash(),
            "tool_policy_hash": tool_policy_hash,
            "pre_inputs_hash": pre_inputs_hash,
            "final_verdict": verdict,
            "loops_run": loop_result.get("loops_run", 0),
            "num_trajectory_steps": len(trajectory),
            "trajectory_steps": [
                {
                    "step": i,
                    "top_hypothesis_digest": _sd(step.get("top_hypothesis", "")[:200]),
                    "selected_tool": step.get("selected_tool"),
                    "tool_params_digest": _sd(json.dumps(step.get("tool_params", {}), sort_keys=True)),
                    "causal_verdict_before": step.get("causal_verdict_before"),
                    "causal_verdict_after": step.get("causal_verdict_after"),
                }
                for i, step in enumerate(trajectory)
            ],
            "proof_bundle_built": proof_bundle is not None and "error" not in proof_bundle,
            "proof_bundle_valid": proof_valid,
            "replay_result": replay_result,
            "expected_label": ground_truth.get(target_case_id, {}).get("expected_label"),
            "mechanism_digest": _sd(ground_truth.get(target_case_id, {}).get("mechanism", "")),
        }

        with open(os.path.join(REPORTS_DIR, "contract_trace_v184.json"), "w") as f:
            json.dump(trace, f, indent=2)

        print("\nResult: OK")
        print(f"  Case: {target_case_id} ({case.get('family')})")
        print(f"  Verdict: {verdict}")
        print(f"  Expected: {ground_truth.get(target_case_id, {}).get('expected_label')}")
        print(f"  Loops: {loop_result.get('loops_run', 0)}")
        print(f"  ProofBundle valid: {proof_valid}")
        print(f"  Replay: {replay_result}")

    finally:
        client.close()
        stop_target(proc)
if __name__ == "__main__":
    run_contract_trace()
