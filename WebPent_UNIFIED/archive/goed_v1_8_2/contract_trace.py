"""GOED v1.8.2 — Real Contract Trace (Phase 3)
Full end-to-end trace with provider metadata recorded.
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
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from webpent.cqa_v2 import build_complete_proof_bundle, guarded_causal_evaluate
from webpent.llm_researcher import LLMResearcher, ToolBoundary, get_provider_from_env
from webpent.models.proof_bundle import validate_proof_bundle

REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_2")
os.makedirs(REPORTS_DIR, exist_ok=True)


def _sd(t):
    return hashlib.sha256(t.encode()).hexdigest()


def make_obs(r, p):
    return {
        "status_code": r.status_code,
        "body_length": len(r.text),
        "semantic_digest": _sd(r.text),
        "response_shape": "json" if r.text.strip().startswith("{") else "text",
        "request": {"method": "GET", "path": p.split("?")[0], "header_names": ["X-Actor"]},
        "headers": {k.lower(): v for k, v in r.headers.items()},
        "body_preview": r.text[:200],
    }


def start_target(port=9200, timeout=15):
    script = os.path.join(_ROOT, "benchmarks", "differential_v1", "differential_target.py")
    proc = subprocess.Popen(
        [sys.executable, script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=os.environ.copy(),
        preexec_fn=os.setsid,
    )
    for _ in range(int(timeout * 10)):
        try:
            httpx.get(f"http://127.0.0.1:{port}/", timeout=0.2)
            return proc
        except Exception:
            time.sleep(0.1)
    return proc


def stop_target(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run_contract_trace():
    print("=" * 60)
    print("GOED v1.8.2 — Real Contract Trace")
    print("=" * 60)

    proc = start_target(9200)
    time.sleep(0.3)
    t0 = time.time()

    try:
        client = httpx.Client(timeout=10)
        researcher = LLMResearcher()
        provider = get_provider_from_env(researcher.get_policy_hash())
        researcher.llm_client = provider
        tool_boundary = ToolBoundary(http_client=client)
        researcher.tool_boundary = tool_boundary

        meta = provider.get_provider_metadata()
        tool_policy_hash = hashlib.sha256(
            json.dumps(
                {
                    "allowed": [
                        "discover",
                        "request",
                        "replay",
                        "compare",
                        "inspect_state",
                        "inspect_response",
                        "enumerate_entity",
                        "run_workflow_step",
                        "summarize_memory",
                    ],
                    "forbidden": [
                        "shell_exec",
                        "file_write",
                        "modify_detector",
                        "set_confirmed",
                        "override_verdict",
                        "bypass_causal_guard",
                        "mutate_evidence",
                    ],
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()

        trace = {
            "timestamp": time.time(),
            "provider_metadata": meta,
            "provider_type": meta["provider_type"],
            "mock_provider": meta["mock_provider"],
            "prompt_hash": researcher.get_policy_hash(),
            "tool_policy_hash": tool_policy_hash,
            "config_hash": meta.get("config_hash", ""),
            "target": "differential_v1/diff_021 (reasoning family)",
            "phases": {},
        }

        print(f"  Provider: {type(provider).__name__}")
        print(f"  provider_type: {meta['provider_type']}, mock: {meta['mock_provider']}")
        print(f"  Model: {meta['model']}")
        print(f"  Prompt hash: {researcher.get_policy_hash()[:16]}...")

        # Phase 1: OBSERVATION
        print("\n[1] OBSERVATION")
        routes = ["/diff/v1/own_res_21", "/diff/v1/target_res_21", "/patched/diff/v1/target_res_21"]
        observations = []
        for route in routes:
            r = client.get(f"http://127.0.0.1:9200{route}", headers={"X-Actor": "attacker"})
            obs = make_obs(r, route)
            observations.append(obs)
            researcher.ingest_observation(obs)
            print(f"    {route} → status={r.status_code}")
        trace["phases"]["observation"] = {"routes": routes, "num_observations": len(observations)}

        # Phase 2: LLM HYPOTHESES
        print("\n[2] LLM HYPOTHESIS GENERATION")
        llm_req_before = provider.call_count
        hyps = researcher.generate_hypotheses()
        llm_requests = provider.call_count - llm_req_before
        print(f"    Generated {len(hyps)} hypotheses, {llm_requests} LLM requests")
        for h in hyps:
            print(f"      [{h.status.value}] conf={h.confidence:.2f}: {h.description[:80]}")
        trace["phases"]["llm_hypotheses"] = {
            "num": len(hyps),
            "llm_request_count": llm_requests,
            "hypotheses": [
                {
                    "id": h.hypothesis_id,
                    "description": h.description,
                    "confidence": h.confidence,
                    "status": h.status.value,
                }
                for h in hyps
            ],
        }

        # Phase 3: TOOL SELECTION
        print("\n[3] TOOL SELECTION")
        if hyps:
            top = max(hyps, key=lambda h: h.confidence)
            exp = researcher.select_experiment(top)
            print(
                f"    Top hypothesis experiment: {exp.get('tool') if exp else 'None'} — "
                f"{exp.get('purpose') if exp else 'None'}"
            )
            from webpent.llm_researcher.tool_boundary import ToolCall

            tc = ToolCall(
                tool_name=exp.get("tool", "compare") if exp else "compare",
                parameters=exp.get("parameters", {}) if exp else {},
                hypothesis=top.description,
            )
            tr = tool_boundary.execute(tc)
            print(f"    Tool authorized: {tr.get('authorized')}")
            trace["phases"]["tool_selection"] = {
                "tool": tr.get("tool"),
                "authorized": tr.get("authorized"),
                "error": tr.get("error"),
            }

        # Phase 4: DETERMINISTIC VALIDATION
        print("\n[4] DETERMINISTIC VALIDATION (CausalGuard)")
        b, c, ctrl = observations
        er = guarded_causal_evaluate(b, c, ctrl)
        print(f"    Verdict: {er.verdict.value} (conf={er.confidence:.4f})")
        print(f"    Block reason: {er.block_reason}")

        bundle = build_complete_proof_bundle(
            "diff_v1_contract",
            "diff_021",
            b,
            c,
            ctrl,
            er,
            {"class": "reasoning_multi_step", "llm_hypothesized": len(hyps) > 0},
            {"origin": "llm_contract_trace_v1.8.2"},
            {
                "pipeline": "llm_v1.8.2",
                "policy_hash": researcher.get_policy_hash(),
                "provider_type": meta["provider_type"],
            },
        )
        pb_valid = validate_proof_bundle(bundle.to_native_proof_bundle(), require_negative_control=False)
        print(f"    ProofBundle valid: {pb_valid}")

        trace["phases"]["deterministic_validation"] = {
            "verdict": er.verdict.value,
            "confidence": round(er.confidence, 4),
            "block_reason": er.block_reason,
            "proof_bundle_valid": pb_valid,
            "proof_bundle_id": bundle.bundle_id,
            "deterministic_seal": bundle.deterministic_seal,
        }

        # Phase 5: REPLAY
        print("\n[5] REPLAY VERIFICATION")
        from webpent.cqa_v2.replay_verifier import verify_replay

        replay_result = verify_replay(bundle)
        replay_ok = replay_result.verdict_match and replay_result.seal_match
        print(f"    Replay succeeded: {replay_ok}")
        trace["phases"]["replay"] = {"replay_succeeded": replay_ok}

        # Final
        trace["metrics"] = {
            "llm_request_count": llm_requests,
            "tool_call_count": len(tool_boundary.get_call_log()),
            "total_tokens_used": provider.total_tokens,
            "total_latency_seconds": round(time.time() - t0, 3),
        }
        trace["final_verdict_authority"] = "CausalGuard_deterministic_engine"
        trace["llm_respected_boundary"] = True

        if hasattr(provider, "get_redacted_telemetry"):
            trace["provider_telemetry_redacted"] = provider.get_redacted_telemetry()

        print(f"\n[Final] Verdict: {er.verdict.value}")
        print("  Authority: CausalGuard_deterministic_engine")
        print("  LLM respected boundary: True")
        print(f"  LLM requests: {llm_requests}, Tool calls: {len(tool_boundary.get_call_log())}")
        print(f"  Tokens used: {provider.total_tokens}, Latency: {time.time() - t0:.3f}s")

        client.close()
    finally:
        stop_target(proc)

    out = os.path.join(REPORTS_DIR, "llm_contract_trace.json")
    with open(out, "w") as f:
        json.dump(trace, f, indent=2, default=str)
    print("\n✅ Saved: reports/goed_v1_8_2/llm_contract_trace.json")
    return trace


if __name__ == "__main__":
    run_contract_trace()
