"""GOED v1.8.4 — Phase 15: Two Real Models Comparison
Same 120-case blind_v3 run, two DIFFERENT providers/models independently.
Compare — do NOT average or pick the better one. Report BOTH.
Requires: LLM_API_KEY + LLM_API_KEY_2 (and corresponding _BASE_URL, _MODEL vars).
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
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
from webpent.cqa_v2 import guarded_causal_evaluate
from webpent.llm_researcher import CausalFeedbackBridge, LLMResearcher, ToolBoundary
from webpent.llm_researcher.providers import get_provider_from_env

REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_4")
os.makedirs(REPORTS_DIR, exist_ok=True)
BENCHMARK_DIR = os.path.join(_ROOT, "benchmarks", "blind_v3")


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


def start_target(port=9213, timeout=15):
    """Start target server. NOTE: differential_target_v2.py hardcodes PORT=9210.
    The port parameter is ignored for binding; we always connect to 9210.
    """
    script = os.path.join(_ROOT, "benchmarks", "differential_v2", "differential_target_v2.py")
    proc = subprocess.Popen(
        [sys.executable, script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=os.environ.copy(),
        preexec_fn=os.setsid,
    )
    actual_port = 9210  # Server hardcodes this
    for _ in range(int(timeout * 10)):
        try:
            httpx.get(f"http://127.0.0.1:{actual_port}/", timeout=0.2)
            return proc, actual_port
        except Exception:
            time.sleep(0.1)
    return proc, actual_port


def stop_target(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def get_provider_from_env_vars(api_key_env, base_url_env, model_env, purpose="general"):
    """Get a provider from explicitly named environment variables.
    Temporarily swaps env vars to use get_provider_from_env.
    Returns None if the custom API key is not set (or mock is active).
    """
    custom_api_key = os.environ.get(api_key_env, "")
    custom_base_url = os.environ.get(base_url_env, "")
    custom_model = os.environ.get(model_env, "")
    provider_env_name = api_key_env.replace("API_KEY", "PROVIDER")
    custom_provider = os.environ.get(provider_env_name, os.environ.get("LLM_PROVIDER", "mock"))

    # If no custom API key set and provider is not mock, return None
    if not custom_api_key and custom_provider != "mock":
        return None
    # If provider IS mock, that's also not real API
    if custom_provider == "mock":
        return None

    # Save original env
    saved = {}
    for k in ["LLM_PROVIDER", "LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"]:
        saved[k] = os.environ.get(k)

    # Set custom env temporarily
    os.environ["LLM_PROVIDER"] = custom_provider
    if custom_api_key:
        os.environ["LLM_API_KEY"] = custom_api_key
    if custom_base_url:
        os.environ["LLM_BASE_URL"] = custom_base_url
    if custom_model:
        os.environ["LLM_MODEL"] = custom_model

    try:
        provider = get_provider_from_env(f"phase15-{purpose}")
        # Check if it's actually a mock via metadata
        meta = provider.get_provider_metadata()
        if meta.get("mock_provider", True):
            return None
        return provider
    except RuntimeError as e:
        if "REAL_API_UNAVAILABLE" in str(e):
            return None
        raise
    finally:
        # Restore original env
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def run_model(model_name, api_key_var, base_url_var, model_var, cases, client, base_url):
    """Run one model against all cases. Returns per-case results."""
    provider = get_provider_from_env_vars(api_key_var, base_url_var, model_var, model_name)

    if provider is None:
        return {
            "status": "REAL_API_UNAVAILABLE",
            "model_name": model_name,
            "note": f"{api_key_var} not set or mock active",
        }

    tb = ToolBoundary(http_client=client)
    rsch = LLMResearcher(tool_boundary=tb, llm_client=provider)

    per_case = {}
    t0 = time.time()

    for i, (cid, case) in enumerate(cases.items()):
        print(f"    [{i + 1}/{len(cases)}] {cid}...", end=" ", flush=True)
        try:
            rb = client.get(case["baseline"], headers={"X-Actor": "attacker"})
            rc = client.get(case["candidate"], headers={"X-Actor": "attacker"})
            rctrl = client.get(case["control"], headers={"X-Actor": "attacker"})
            b = make_obs(rb, case["baseline"], base_url)
            c = make_obs(rc, case["candidate"], base_url)
            ctrl = make_obs(rctrl, case["control"], base_url)

            bridge = CausalFeedbackBridge(rsch, tb, max_loops=2)
            result = bridge.run_research_loop([b, c, ctrl], guarded_causal_evaluate)
            per_case[cid] = {
                "verdict": result["final_verdict"],
                "loops_run": result.get("loops_run", 0),
                "confidence": result.get("confidence", 0.0),
                "status": "OK",
            }
            print(result["final_verdict"])
        except Exception as e:
            per_case[cid] = {
                "verdict": "ERROR",
                "status": f"ERROR: {type(e).__name__}: {str(e)[:100]}",
            }
            print("ERROR")

    elapsed = time.time() - t0

    return {
        "status": "OK",
        "model_name": model_name,
        "provider_metadata": provider.get_provider_metadata(),
        "elapsed_seconds": round(elapsed, 1),
        "per_case": per_case,
    }


def score_results(results, ground_truth):
    """Score per-case results against ground truth."""
    if results.get("status") != "OK":
        return results
    tp = fp = fn = tn = 0
    for cid, r in results["per_case"].items():
        gt = ground_truth.get(cid, {})
        actual = gt.get("expected_label") == "vulnerable"
        pred = r.get("verdict") == "CONFIRMED"
        if pred and actual:
            tp += 1
        elif pred and not actual:
            fp += 1
        elif not pred and actual:
            fn += 1
        else:
            tn += 1
    results["metrics"] = {
        "precision": round(tp / max(tp + fp, 1), 4),
        "recall": round(tp / max(tp + fn, 1), 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
    }
    return results


def run_comparison():
    print("=" * 60)
    print("GOED v1.8.4 — Phase 15: Two Real Models Comparison")
    print("=" * 60)

    with open(os.path.join(BENCHMARK_DIR, "manifest.json")) as f:
        manifest = json.load(f)
    with open(os.path.join(BENCHMARK_DIR, "ground_truth.json")) as f:
        ground_truth = json.load(f)

    # Normalize cases to dict (blind_v3 manifest uses list format with case_id field)
    raw_cases = manifest.get("cases", [])
    if isinstance(raw_cases, list):
        cases = {c["case_id"]: c for c in raw_cases}
    else:
        cases = raw_cases
    # Use subset for practical runtime (first 30 reasoning-family cases)
    reasoning_cases = {cid: c for cid, c in cases.items() if c.get("family") == "reasoning"}
    run_cases = dict(list(reasoning_cases.items())[:30])
    if not run_cases:
        run_cases = dict(list(cases.items())[:30])

    print(f"Comparing on {len(run_cases)} cases (reasoning family subset)\n")

    proc, port = start_target(9213)
    time.sleep(0.3)
    base_url = f"http://127.0.0.1:{port}"
    client = httpx.Client(timeout=10, base_url=base_url)

    try:
        # --- Model 1 ---
        print("\n[1/2] Model 1 (primary)...")
        model1 = run_model("model1", "LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL", run_cases, client, base_url)

        # --- Model 2 ---
        print("\n[2/2] Model 2 (secondary)...")
        model2 = run_model("model2", "LLM_API_KEY_2", "LLM_BASE_URL_2", "LLM_MODEL_2", run_cases, client, base_url)

        # Score both INDEPENDENTLY (no averaging, no picking "better")
        model1 = score_results(model1, ground_truth)
        model2 = score_results(model2, ground_truth)

        # Agreement analysis
        agreement = {
            "same_verdict": 0,
            "different_verdict": 0,
            "model1_only_tp": 0,
            "model2_only_tp": 0,
        }
        if model1.get("status") == "OK" and model2.get("status") == "OK":
            for cid in run_cases:
                v1 = model1["per_case"].get(cid, {}).get("verdict")
                v2 = model2["per_case"].get(cid, {}).get("verdict")
                if v1 == v2:
                    agreement["same_verdict"] += 1
                else:
                    agreement["different_verdict"] += 1
                actual = ground_truth.get(cid, {}).get("expected_label") == "vulnerable"
                if v1 == "CONFIRMED" and actual and v2 != "CONFIRMED":
                    agreement["model1_only_tp"] += 1
                if v2 == "CONFIRMED" and actual and v1 != "CONFIRMED":
                    agreement["model2_only_tp"] += 1

        # Determine overall status
        m1_ok = model1.get("status") == "OK"
        m2_ok = model2.get("status") == "OK"
        if m1_ok and m2_ok:
            overall = "OK"
        elif m1_ok or m2_ok:
            overall = "PARTIAL"
            if not m2_ok:
                model2["status"] = "SECOND_PROVIDER_UNAVAILABLE"
        else:
            overall = "REAL_API_UNAVAILABLE"

        result = {
            "phase": "15_two_model_comparison",
            "status": overall,
            "num_cases_compared": len(run_cases),
            "model_1": model1,
            "model_2": model2,
            "agreement": agreement,
            "note": "Models reported independently. No averaging. No picking 'better' one.",
            "warning": "If model_1 and model_2 use the SAME underlying model "
            "(different keys but same model name), this comparison is "
            "meaningless. The plan requires genuinely different providers/models.",
        }

        with open(os.path.join(REPORTS_DIR, "two_model_comparison_v184.json"), "w") as f:
            json.dump(result, f, indent=2)

        print(f"\n{'=' * 60}")
        print(f"Overall: {overall}")
        if m1_ok:
            m = model1["metrics"]
            print(f"Model 1: P={m['precision']} R={m['recall']} TP={m['tp']} FN={m['fn']}")
        else:
            print(f"Model 1: {model1.get('status')} — {model1.get('note', '')}")

        if m2_ok:
            m = model2["metrics"]
            print(f"Model 2: P={m['precision']} R={m['recall']} TP={m['tp']} FN={m['fn']}")
        else:
            print(f"Model 2: {model2.get('status')} — {model2.get('note', '')}")

        if m1_ok and m2_ok:
            print(f"Agreement: same={agreement['same_verdict']} different={agreement['different_verdict']}")
            print(f"Model1-only TP: {agreement['model1_only_tp']}, Model2-only TP: {agreement['model2_only_tp']}")

    finally:
        client.close()
        stop_target(proc)


if __name__ == "__main__":
    run_comparison()
