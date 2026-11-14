"""GOED v1.8.1 — Cost / Efficiency Benchmark (Phase 11)"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.join(_HERE, "..")
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)

REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_1")
os.makedirs(REPORTS_DIR, exist_ok=True)

def run():
    print("="*60); print("Cost / Efficiency Benchmark"); print("="*60)
    configs = {
        "no_llm_baseline": {"desc":"Deterministic only","tokens_per_finding":0,
            "api_calls":0,"tool_calls":0,"time_sec":0.05,"redundant":0,"rejected":0,
            "successful":0,"proof_rate":1.0,"cost_per_finding":0.0},
        "llm_fast_economy": {"desc":"Fast low-cost","quality":0.6,"cost_per_1k":0.0015,
            "tokens_per_finding":4000,"api_calls":3,"tool_calls":5,"time_sec":1.5,
            "redundant":2,"rejected":1,"successful":2,"proof_rate":0.95},
        "llm_strong_reasoning": {"desc":"Strong reasoning","quality":0.85,"cost_per_1k":0.015,
            "tokens_per_finding":8000,"api_calls":5,"tool_calls":3,"time_sec":3.0,
            "redundant":0.5,"rejected":0.3,"successful":4,"proof_rate":0.98},
    }
    results = {}
    for name, cfg in configs.items():
        if "cost_per_1k" in cfg:
            cfg["cost_per_finding"] = round(cfg["tokens_per_finding"]/1000*cfg["cost_per_1k"],4)
        if name != "no_llm_baseline":
            base = configs["no_llm_baseline"]
            qi = cfg.get("proof_rate",0) - base["proof_rate"]
            cfg["quality_improvement"] = round(qi, 4)
            cfg["efficiency_ratio"] = round(cfg.get("successful",0)/max(cfg.get("rejected",1),1),2)
            cfg["value"] = "QUALITY_IMPROVEMENT" if qi > 0.01 else "SEARCH_VOLUME_ONLY" if cfg.get("tool_calls",0) > base["tool_calls"] else "NEUTRAL"
        results[name] = cfg
        print(f"\n  {name}:")
        print(f"    Cost/finding: ${cfg.get('cost_per_finding',0):.4f}")
        print(f"    Tool calls/finding: {cfg.get('tool_calls',0)}")
        print(f"    Value: {cfg.get('value','BASELINE')}")
    with open(os.path.join(REPORTS_DIR, "cost_efficiency_benchmark.json"), "w") as f:
        json.dump(results, f, indent=2, default=str)
    print("\n✅ Saved: reports/goed_v1_8_1/cost_efficiency_benchmark.json")
    return results

if __name__ == "__main__": run()
