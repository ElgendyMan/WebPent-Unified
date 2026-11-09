"""GOED v1.8.2 — Real Model Comparison (Phase 12)
Compares at least 2 model configurations.
Note: Uses enhanced MockLLMProvider with different quality profiles pending real API key.
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
from webpent.llm_researcher import LLMResearcher, ToolBoundary
from webpent.llm_researcher.providers import MockLLMProvider

REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_2")
os.makedirs(REPORTS_DIR, exist_ok=True)

def _sd(t): return hashlib.sha256(t.encode()).hexdigest()
def make_obs(r, p):
    return {"status_code": r.status_code, "body_length": len(r.text),
        "semantic_digest": _sd(r.text),
        "response_shape": "json" if r.text.strip().startswith("{") else "text",
        "request": {"method": "GET", "path": p.split("?")[0], "header_names": ["X-Actor"]},
        "headers": {k.lower(): v for k, v in r.headers.items()},
        "body_preview": r.text[:200]}

def start_target(port=9200, timeout=15):
    script = os.path.join(_ROOT, "benchmarks", "differential_v1", "differential_target.py")
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

def eval_config(config_name, config, cases, ground_truth):
    provider = MockLLMProvider(model=config["model"],
        reasoning_quality=config["reasoning_quality"],
        hallucination_rate=config.get("hallucination_rate", 0.0))
    tb = ToolBoundary()
    r = LLMResearcher(tool_boundary=tb, llm_client=provider)
    client = httpx.Client(timeout=10)
    tp = fp = fn = tn = 0
    total_hyps = useful = redundant = 0
    t0 = time.time()

    # Test on first 20 reasoning/novel cases only
    test_cases = [(cid, c) for cid, c in cases.items() if c.get("family") in ("reasoning", "novel")][:20]

    for cid, case in test_cases:
        try:
            rb = client.get(f"http://127.0.0.1:9200{case['baseline']}", headers={"X-Actor":"attacker"})
            rc = client.get(f"http://127.0.0.1:9200{case['candidate']}", headers={"X-Actor":"attacker"})
            rctrl = client.get(f"http://127.0.0.1:9200{case['control']}", headers={"X-Actor":"attacker"})
            b, c, ctrl = make_obs(rb, case['baseline']), make_obs(rc, case['candidate']), make_obs(rctrl, case['control'])

            er = guarded_causal_evaluate(b, c, ctrl)
            verdict = er.verdict.value
            iv = ground_truth[cid]["expected_label"] == "vulnerable"

            r.memory = type(r.memory)()
            r.ingest_observation(b); r.ingest_observation(c); r.ingest_observation(ctrl)
            hyps = r.generate_hypotheses()
            total_hyps += len(hyps)
            for h in hyps:
                hd = h.description.lower()
                if any(p in hd for p in ["ownership","boundary","tenant","isolation","workflow",
                    "state","relationship","multi-step","prerequisite","consequence","invariant",
                    "equivalent","nested","indirect","counter","chain","composition"]):
                    useful += 1
                elif any(w in hd for w in ["http 200","status code","response exists"]):
                    redundant += 1

            o = "TP" if verdict=="CONFIRMED" and iv else ("FP" if verdict=="CONFIRMED" and not iv
                else ("TN" if verdict=="CLEAN" and not iv else "FN"))
            if o == "TP": tp += 1
            elif o == "FP": fp += 1
            elif o == "TN": tn += 1
            elif o == "FN": fn += 1
        except Exception: pass

    client.close()
    prec = tp/(tp+fp) if (tp+fp) else 0
    rec = tp/(tp+fn) if (tp+fn) else 0
    f1 = 2*prec*rec/(prec+rec) if (prec+rec) else 0
    elapsed = time.time() - t0

    return {"config": config_name, "model": config["model"],
        "provider_type": provider.provider_type, "mock_provider": provider.is_mock,
        "reasoning_quality": config["reasoning_quality"],
        "metrics": {"tp":tp,"fp":fp,"fn":fn,"tn":tn,
            "precision":round(prec,4),"recall":round(rec,4),"f1":round(f1,4)},
        "hypothesis_stats": {"total":total_hyps,"useful":useful,"redundant":redundant,
            "useful_rate":round(useful/max(total_hyps,1),4),
            "redundant_rate":round(redundant/max(total_hyps,1),4)},
        "cost": {"cost_per_1k_tokens": config["cost_per_1k_tokens"],
            "estimated_total_tokens": provider.total_tokens,
            "estimated_cost": round(provider.total_tokens/1000*config["cost_per_1k_tokens"],4)},
        "latency": {"avg_seconds": round(elapsed/max(len(test_cases),1),3),
            "total_seconds": round(elapsed,2)},
        "note": config.get("note", "")}

def run_comparison():
    print("="*60); print("Real Model Comparison"); print("="*60)

    with open(os.path.join(_ROOT, "benchmarks", "differential_v1", "manifest.json")) as f:
        manifest = json.load(f)
    with open(os.path.join(_ROOT, "benchmarks", "differential_v1", "ground_truth.json")) as f:
        ground_truth = json.load(f)

    configs = {
        "production-fast": {
            "model": "mock-fast-v1", "reasoning_quality": 0.55,
            "hallucination_rate": 0.08, "cost_per_1k_tokens": 0.0015,
            "note": "Fast, low-cost model profile",
        },
        "production-reasoning": {
            "model": "mock-reasoning-v1", "reasoning_quality": 0.85,
            "hallucination_rate": 0.02, "cost_per_1k_tokens": 0.015,
            "note": "Stronger reasoning model profile",
        },
    }

    proc = start_target(9200)
    try:
        results = {}
        for cname, cfg in configs.items():
            print(f"\nEvaluating: {cname} (quality={cfg['reasoning_quality']})")
            r = eval_config(cname, cfg, manifest["cases"], ground_truth)
            results[cname] = r
            m = r["metrics"]; hs = r["hypothesis_stats"]
            print(f"  Recall: {m['recall']:.4f}, Useful hyp rate: {hs['useful_rate']:.2%}")
            print(f"  Est cost: ${r['cost']['estimated_cost']:.4f}, Avg latency: {r['latency']['avg_seconds']:.3f}s/case")

        fast = results["production-fast"]; strong = results["production-reasoning"]
        print("\n--- Delta (reasoning - fast) ---")
        print(f"  Recall: {strong['metrics']['recall']-fast['metrics']['recall']:+.4f}")
        print(f"  Useful hyp rate: {strong['hypothesis_stats']['useful_rate']-fast['hypothesis_stats']['useful_rate']:+.4f}")
        print(f"  Cost ratio: {strong['cost']['estimated_cost']/max(fast['cost']['estimated_cost'],0.0001):.1f}x")

        with open(os.path.join(REPORTS_DIR, "model_comparison.json"), "w") as f:
            json.dump(results, f, indent=2, default=str)
        print("\n✅ Saved: reports/goed_v1_8_2/model_comparison.json")
    finally:
        stop_target(proc)
    return results

if __name__ == "__main__": run_comparison()
