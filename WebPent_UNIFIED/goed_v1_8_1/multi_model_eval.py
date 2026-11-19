"""GOED v1.8.1 — Multiple Model Evaluation (Phase 5)"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.join(_HERE, "..")
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)

from webpent.llm_researcher.providers import MockLLMProvider

REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_1")
os.makedirs(REPORTS_DIR, exist_ok=True)

def eval_config(model_name, config):
    p = MockLLMProvider(model=model_name, prompt_version_hash="test_v1",
        hallucination_rate=config.get("hallucination_rate",0),
        reasoning_quality=config.get("reasoning_quality",0.7))
    prompts = [
        "Observation: resource_owner=target_user, actor_echo=attacker, authorization_outcome=granted_full",
        "Observation: resource_tenant=t2, actor_tenant=t1, authorization_outcome=granted_full",
        "Observation: HTTP 200, body_length=500, no authorization outcome header",
    ]
    th = useful = hall = tt = tl = 0
    for pr in prompts:
        resp = p.generate(pr, max_tokens=500)
        tl += resp.latency_seconds; tt += resp.tokens_used
        try:
            data = json.loads(resp.content); hyps = data.get("hypotheses", [])
            th += len(hyps)
            for h in hyps:
                d = h.get("description","").lower()
                if "ownership" in d or "tenant" in d or "authorization" in d: useful += 1
                if "hallucination" in d: hall += 1
        except: pass
    return {"model": model_name, "config": config, "provider": type(p).__name__,
        "metrics": {"total_hypotheses": th, "useful_hypotheses": useful,
            "useful_rate": round(useful/max(th,1),4), "hallucinations": hall,
            "hallucination_rate": round(hall/max(th,1),4), "total_tokens": tt,
            "avg_latency": round(tl/max(len(prompts),1),3),
            "cost_per_1k": config.get("cost_per_1k_tokens",0),
            "estimated_cost": round(tt/1000*config.get("cost_per_1k_tokens",0),4)},
        "telemetry_redacted": p.get_redacted_telemetry()}

def run():
    print("="*60); print("Multi-Model Evaluation"); print("="*60)
    configs = {
        "production-fast": {"reasoning_quality":0.6,"hallucination_rate":0.05,
            "cost_per_1k_tokens":0.0015,"description":"Fast low-cost model"},
        "production-reasoning": {"reasoning_quality":0.85,"hallucination_rate":0.02,
            "cost_per_1k_tokens":0.015,"description":"Stronger reasoning model"},
    }
    results = {}
    for mn, cfg in configs.items():
        print(f"\nEvaluating: {mn}")
        r = eval_config(mn, cfg); results[mn] = r
        m = r["metrics"]
        print(f"  Useful rate: {m['useful_rate']:.2%}, Halluc: {m['hallucination_rate']:.2%}")
        print(f"  Avg latency: {m['avg_latency']:.3f}s, Cost: ${m['estimated_cost']:.4f}")
    fast = results["production-fast"]["metrics"]
    strong = results["production-reasoning"]["metrics"]
    print(f"\nDelta strong-fast: useful={strong['useful_rate']-fast['useful_rate']:+.2%}, "
          f"cost={strong['estimated_cost']/max(fast['estimated_cost'],0.0001):.1f}x")
    with open(os.path.join(REPORTS_DIR, "multi_model_evaluation.json"), "w") as f:
        json.dump(results, f, indent=2, default=str)
    print("\n✅ Saved: reports/goed_v1_8_1/multi_model_evaluation.json")
    return results

if __name__ == "__main__": run()
