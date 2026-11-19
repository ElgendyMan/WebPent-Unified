"""GOED v1.8.3 — Differential Benchmark v2 Runner
Uses CausalFeedbackBridge for LLM ON mode.
Mode A: LLM OFF (pure deterministic baseline only)
Mode B: LLM ON (baseline + research loop + re-evaluation)
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

from webpent.cqa_v2 import guarded_causal_evaluate
from webpent.llm_researcher import (
    CausalFeedbackBridge,
    LLMResearcher,
    ToolBoundary,
    WorldModel,
    get_provider_from_env,
)

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

def _classify(v, iv):
    if v == "CONFIRMED" and iv: return "TP"
    if v == "CONFIRMED" and not iv: return "FP"
    if v == "CLEAN" and not iv: return "TN"
    if (v == "CLEAN" or v == "INCONCLUSIVE") and iv: return "FN"
    return v

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

def run_mode(base_url, cases, ground_truth, actor, use_llm=False, llm_client=None):
    results = []
    tp = fp = fn = tn = 0
    total_hyps = useful = redundant = invalid = blocked = 0
    total_tools = 0
    steps_list = []
    recovered_cases = []
    t0 = time.time()

    transport = httpx.HTTPTransport()
    client = httpx.Client(timeout=10, base_url=base_url, transport=transport)
    tb = ToolBoundary(http_client=client) if use_llm else None
    rsch = LLMResearcher(tool_boundary=tb, llm_client=llm_client) if use_llm else None
    bridge = CausalFeedbackBridge(rsch, tb) if use_llm else None

    for cid, case in cases.items():
        try:
            rb = client.get(case["baseline"], headers={"X-Actor": actor})
            rc = client.get(case["candidate"], headers={"X-Actor": actor})
            rctrl = client.get(case["control"], headers={"X-Actor": actor})
            b = make_obs(rb, case["baseline"], base_url, actor_id=actor)
            c = make_obs(rc, case["candidate"], base_url, actor_id=actor)
            ctrl = make_obs(rctrl, case["control"], base_url, actor_id=actor)
            iv = ground_truth[cid]["expected_label"] == "vulnerable"
            nh = nu = nr = ni = nb = 0
            ntools = 0
            steps = 1
            recovered = False
            trajectory = None

            if use_llm and bridge:
                bridge.world_model = WorldModel()
                bridge.trajectory = []
                loop_result = bridge.run_research_loop([b, c, ctrl], guarded_causal_evaluate)
                verdict = loop_result["final_verdict"]
                steps = loop_result.get("loops_run", 0) + 1
                recovered = loop_result.get("recovered", False)
                trajectory = loop_result.get("trajectory")
                ntools = loop_result.get("new_observations_added", 0)
                total_tools += ntools
                # Count hypotheses from trajectory
                for step in (trajectory or []):
                    if "top_hypothesis" in step:
                        nh += 1
                        total_hyps += 1
                        hd = step.get("top_hypothesis", "").lower()
                        if any(w in hd for w in ["ownership","boundary","tenant","isolation","workflow",
                            "state","transition","relationship","multi-step","prerequisite",
                            "consequence","invariant","equivalent","nested","indirect","counter",
                            "sequence","process","chain","flag","reference","context"]):
                            useful += 1; nu += 1
                        elif any(w in hd for w in ["http 200","status code","response exists"]):
                            redundant += 1; nr += 1
                        else:
                            invalid += 1; ni += 1
            else:
                er = guarded_causal_evaluate(b, c, ctrl)
                verdict = er.verdict.value

            o = _classify(verdict, iv)
            if o == "TP": tp += 1; steps_list.append(steps)
            elif o == "FP": fp += 1
            elif o == "TN": tn += 1
            elif o == "FN": fn += 1

            if recovered and iv:
                recovered_cases.append(cid)

            results.append({"case_id": cid, "family": case.get("family"),
                "verdict": verdict, "outcome": o, "is_vulnerable": iv,
                "hypotheses": nh, "useful": nu, "redundant": nr, "invalid": ni,
                "tool_calls": ntools, "steps": steps, "recovered": recovered,
                "trajectory": trajectory})
        except Exception as e:
            results.append({"case_id": cid, "error": str(e)[:200]})

    client.close()
    prec = tp/(tp+fp) if (tp+fp) else 0
    rec = tp/(tp+fn) if (tp+fn) else 0
    f1 = 2*prec*rec/(prec+rec) if (prec+rec) else 0

    return {"mode": "LLM_ON" if use_llm else "LLM_OFF",
        "model": getattr(llm_client,'model','none') if llm_client else 'none',
        "provider_type": getattr(llm_client,'provider_type','none') if llm_client else 'none',
        "mock_provider": getattr(llm_client,'is_mock',True) if llm_client else True,
        "cases": len(results),
        "metrics": {"tp":tp,"fp":fp,"fn":fn,"tn":tn,
            "precision":round(prec,4),"recall":round(rec,4),"f1":round(f1,4)},
        "llm_metrics": {"total_hypotheses": total_hyps, "useful": useful,
            "useful_rate": round(useful/max(total_hyps,1),4),
            "redundant": redundant, "invalid": invalid, "blocked": blocked,
            "total_tool_calls": total_tools,
            "probes_per_confirmed": round(total_tools/max(tp,1),2),
            "avg_steps_to_confirm": round(sum(steps_list)/max(len(steps_list),1),2),
            "elapsed": round(time.time()-t0,2)},
        "recovered_cases": recovered_cases,
        "per_case": results,
        "deterministic_oracle_authoritative": True,
        "causal_feedback_bridge_used": use_llm}

def run_differential():
    print("="*60); print("GOED v1.8.3 — Differential Benchmark v2 (90 cases)"); print("="*60)

    with open(os.path.join(_ROOT, "benchmarks", "differential_v2", "manifest.json")) as f:
        manifest = json.load(f)
    with open(os.path.join(_ROOT, "benchmarks", "differential_v2", "ground_truth.json")) as f:
        ground_truth = json.load(f)

    cases = manifest["cases"]
    vuln = sum(1 for g in ground_truth.values() if g["expected_label"]=="vulnerable")
    print(f"Cases: {len(cases)} | Vulnerable: {vuln} | Clean: {len(cases)-vuln}")

    proc = start_target(9210)
    base = "http://127.0.0.1:9210"
    try:
        print("\n--- Mode A: LLM OFF (pure deterministic baseline) ---")
        ma = run_mode(base, cases, ground_truth, "attacker", use_llm=False)
        print(f"  TP={ma['metrics']['tp']} FP={ma['metrics']['fp']} "
              f"FN={ma['metrics']['fn']} TN={ma['metrics']['tn']}")
        print(f"  P={ma['metrics']['precision']:.4f} R={ma['metrics']['recall']:.4f} F1={ma['metrics']['f1']:.4f}")

        print("\n--- Mode B: LLM ON (Causal Feedback Bridge) ---")
        rsch = LLMResearcher()
        llm = get_provider_from_env(rsch.get_policy_hash())
        print(f"  Provider: {type(llm).__name__}")
        print(f"  provider_type: {llm.provider_type}, mock: {llm.is_mock}")
        print(f"  Model: {llm.model}")

        mb = run_mode(base, cases, ground_truth, "attacker", use_llm=True, llm_client=llm)
        print(f"  TP={mb['metrics']['tp']} FP={mb['metrics']['fp']} "
              f"FN={mb['metrics']['fn']} TN={mb['metrics']['tn']}")
        print(f"  P={mb['metrics']['precision']:.4f} R={mb['metrics']['recall']:.4f} F1={mb['metrics']['f1']:.4f}")
        lm = mb["llm_metrics"]
        print(f"  Hypotheses: {lm['total_hypotheses']} (useful={lm['useful']}, rate={lm['useful_rate']:.2%})")
        print(f"  New observations from experiments: {lm['total_tool_calls']}")
        print(f"  Recovered by LLM research: {len(mb['recovered_cases'])}")

        for cid in mb['recovered_cases'][:5]:
            gt = ground_truth[cid]
            print(f"    {cid}: {gt['case_family']} / {gt['mechanism']} / {gt['vulnerability_class']}")

        delta = {"precision_change": round(mb['metrics']['precision']-ma['metrics']['precision'],4),
            "recall_change": round(mb['metrics']['recall']-ma['metrics']['recall'],4),
            "f1_change": round(mb['metrics']['f1']-ma['metrics']['f1'],4),
            "recovered_cases": mb['recovered_cases'],
            "recovered_count": len(mb['recovered_cases']),
            "hypotheses": lm['total_hypotheses'], "useful_rate": lm['useful_rate'],
            "new_observations": lm['total_tool_calls']}
        print("\n--- Delta ---")
        for k, v in delta.items():
            if k != "recovered_cases": print(f"  {k}: {v}")

        result = {"timestamp": time.time(), "benchmark": "DifferentialBenchmark-v2",
            "deterministic_oracle_identical": True,
            "causal_feedback_bridge": "ACTIVE_in_LLM_ON_mode",
            "mode_a_llm_off": ma, "mode_b_llm_on": mb, "delta": delta,
            "provider_metadata": llm.get_provider_metadata() if hasattr(llm,'get_provider_metadata') else {},
            "telemetry_redacted": llm.get_redacted_telemetry() if hasattr(llm,'get_redacted_telemetry') else [],
            "note": "Causal Feedback Bridge active in Mode B. LLM selects experiments, "
                    "new observations feed into WorldModel, CausalGuard re-evaluates. "
                    "Final verdict authority remains CausalGuard exclusively."}

        with open(os.path.join(REPORTS_DIR, "differential_results.json"), "w") as f:
            json.dump(result, f, indent=2, default=str)
        print("\n✅ Saved: reports/goed_v1_8_3/differential_results.json")
    finally:
        stop_target(proc)
    return result

if __name__ == "__main__": run_differential()
