"""GOED v1.8.3 — Two Real Models Comparison (Phase 16)
Only after real-provider execution is proven.
Uses enhanced MockLLMProvider with different quality profiles for engineering verification.
Real API key required for actual two-model comparison.
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

from webpent.cqa_v2 import guarded_causal_evaluate
from webpent.llm_researcher import CausalFeedbackBridge, LLMResearcher, ToolBoundary
from webpent.llm_researcher.providers import MockLLMProvider

REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_3")
os.makedirs(REPORTS_DIR, exist_ok=True)


def _sd(t):
    return hashlib.sha256(t.encode()).hexdigest()


def make_obs(r, p, base_url=None):
    return {
        "status_code": r.status_code,
        "body_length": len(r.text),
        "semantic_digest": _sd(r.text),
        "response_shape": "json" if r.text.strip().startswith("{") else "text",
        "request": {
            "method": "GET",
            "path": p.split("?")[0],
            "header_names": ["X-Actor"],
            "base_url": base_url,
        },
        "headers": {k.lower(): v for k, v in r.headers.items()},
        "body_preview": r.text[:200],
    }


def start_target(port=9210, timeout=15):
    script = os.path.join(_ROOT, "benchmarks", "differential_v2", "differential_target_v2.py")
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


def eval_config(config_name, config, cases, ground_truth, base_url):
    provider = MockLLMProvider(
        model=config["model"],
        reasoning_quality=config["reasoning_quality"],
        hallucination_rate=config.get("hallucination_rate", 0.0),
    )
    client = httpx.Client(timeout=10, base_url=base_url)
    tb = ToolBoundary(http_client=client)
    rsch = LLMResearcher(tool_boundary=tb, llm_client=provider)

    tp = fp = fn = tn = 0
    total_hyps = useful = redundant = 0
    total_experiments = 0
    confirmations = 0
    t0 = time.time()

    test_cases = [(cid, c) for cid, c in cases.items() if c.get("family") in ("reasoning", "novel")][:30]

    for cid, case in test_cases:
        try:
            rb = client.get(case["baseline"], headers={"X-Actor": "attacker"})
            rc = client.get(case["candidate"], headers={"X-Actor": "attacker"})
            rctrl = client.get(case["control"], headers={"X-Actor": "attacker"})
            b = make_obs(rb, case["baseline"], base_url)
            c = make_obs(rc, case["candidate"], base_url)
            ctrl = make_obs(rctrl, case["control"], base_url)
            iv = ground_truth[cid]["expected_label"] == "vulnerable"

            bridge = CausalFeedbackBridge(rsch, tb, max_loops=2)
            result = bridge.run_research_loop([b, c, ctrl], guarded_causal_evaluate)
            verdict = result["final_verdict"]
            total_experiments += result.get("loops_run", 0)

            for step in result.get("trajectory") or []:
                hyp = step.get("top_hypothesis", "").lower()
                if hyp:
                    total_hyps += 1
                    if any(
                        p in hyp
                        for p in [
                            "state",
                            "transition",
                            "workflow",
                            "multi-step",
                            "prerequisite",
                            "relationship",
                            "cross-resource",
                            "indirect",
                            "invariant",
                            "equivalent",
                            "delayed",
                            "consequence",
                            "counter",
                            "sequence",
                            "process",
                            "chain",
                            "flag",
                            "context",
                        ]
                    ):
                        useful += 1
                    elif any(w in hyp for w in ["http 200", "status code", "response exists"]):
                        redundant += 1

            o = (
                "TP"
                if verdict == "CONFIRMED" and iv
                else ("FP" if verdict == "CONFIRMED" and not iv else ("TN" if verdict == "CLEAN" and not iv else "FN"))
            )
            if o == "TP":
                tp += 1
                confirmations += 1
            elif o == "FP":
                fp += 1
            elif o == "TN":
                tn += 1
            elif o == "FN":
                fn += 1
        except Exception:
            pass

    client.close()
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    elapsed = time.time() - t0

    return {
        "config": config_name,
        "model": config["model"],
        "provider_type": provider.provider_type,
        "mock_provider": provider.is_mock,
        "reasoning_quality": config["reasoning_quality"],
        "metrics": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
        },
        "hypothesis_stats": {
            "total": total_hyps,
            "useful": useful,
            "redundant": redundant,
            "useful_rate": round(useful / max(total_hyps, 1), 4),
            "redundant_rate": round(redundant / max(total_hyps, 1), 4),
        },
        "experiment_stats": {
            "total": total_experiments,
            "confirmation_rate": round(confirmations / max(total_experiments, 1), 4),
        },
        "cost": {
            "cost_per_1k_tokens": config["cost_per_1k_tokens"],
            "estimated_total_tokens": provider.total_tokens,
            "estimated_cost": round(provider.total_tokens / 1000 * config["cost_per_1k_tokens"], 4),
        },
        "latency": {
            "avg_seconds": round(elapsed / max(len(test_cases), 1), 3),
            "total_seconds": round(elapsed, 2),
        },
        "note": config.get("note", "") + " — Real API key required for actual two-model comparison",
    }


def run_comparison():
    print("=" * 60)
    print("Two Real Models Comparison")
    print("=" * 60)

    with open(os.path.join(_ROOT, "benchmarks", "differential_v2", "manifest.json")) as f:
        manifest = json.load(f)
    with open(os.path.join(_ROOT, "benchmarks", "differential_v2", "ground_truth.json")) as f:
        ground_truth = json.load(f)

    configs = {
        "production-fast": {
            "model": "mock-fast-profile",
            "reasoning_quality": 0.55,
            "hallucination_rate": 0.08,
            "cost_per_1k_tokens": 0.0015,
            "note": "Fast/low-cost profile",
        },
        "production-reasoning": {
            "model": "mock-reasoning-profile",
            "reasoning_quality": 0.85,
            "hallucination_rate": 0.02,
            "cost_per_1k_tokens": 0.015,
            "note": "Strong reasoning profile",
        },
    }

    proc = start_target(9210)
    try:
        results = {}
        for cname, cfg in configs.items():
            print(f"\nEvaluating: {cname} (quality={cfg['reasoning_quality']})")
            r = eval_config(cname, cfg, manifest["cases"], ground_truth, "http://127.0.0.1:9210")
            results[cname] = r
            m = r["metrics"]
            hs = r["hypothesis_stats"]
            print(f"  Recall: {m['recall']:.4f}, Useful hyp rate: {hs['useful_rate']:.2%}")
            print(f"  Confirmation rate: {r['experiment_stats']['confirmation_rate']:.2%}")
            print(
                f"  Est cost: ${r['cost']['estimated_cost']:.4f}, Avg latency: {r['latency']['avg_seconds']:.3f}s/case"
            )

        fast = results["production-fast"]
        strong = results["production-reasoning"]
        print("\n--- Delta (reasoning - fast) ---")
        print(f"  Recall: {strong['metrics']['recall'] - fast['metrics']['recall']:+.4f}")
        print(
            f"  Useful hyp rate: {strong['hypothesis_stats']['useful_rate'] - fast['hypothesis_stats']['useful_rate']:+.4f}"
        )
        print(f"  Cost ratio: {strong['cost']['estimated_cost'] / max(fast['cost']['estimated_cost'], 0.0001):.1f}x")

        with open(os.path.join(REPORTS_DIR, "model_comparison.json"), "w") as f:
            json.dump(results, f, indent=2, default=str)
        print("\n✅ Saved: reports/goed_v1_8_3/model_comparison.json")
    finally:
        stop_target(proc)
    return results


if __name__ == "__main__":
    run_comparison()
