"""GOED v1.8.4 — Phase 11: LLM_OFF vs LLM_ON Differential
Same 120 blind_v3 cases, two modes:
  Mode A (LLM_OFF): deterministic CausalGuard only, no LLM researcher
  Mode B (LLM_ON):  full LLM-augmented pipeline
Delta = Mode B - Mode A. If DELTA_RECALL <= 0, report REAL_LLM_INTEGRATED_NO_MEASURED_GAIN.
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
from webpent.cqa_v2 import guarded_causal_evaluate
from webpent.llm_researcher import (
    CausalFeedbackBridge,
    LLMResearcher,
    ToolBoundary,
    get_provider_from_env,
)

REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_4")
os.makedirs(REPORTS_DIR, exist_ok=True)
BENCHMARK_DIR = os.path.join(_ROOT, "benchmarks", "blind_v3")
def _sd(t): return hashlib.sha256(t.encode()).hexdigest()
def make_obs(r, p, base_url=None):
    return {"status_code": r.status_code, "body_length": len(r.text),
        "semantic_digest": _sd(r.text),
        "response_shape": "json" if r.text.strip().startswith("{") else "text",
        "request": {"method": "GET", "path": p.split("?")[0],
                   "header_names": ["X-Actor"], "base_url": base_url},
        "headers": {k.lower(): v for k, v in r.headers.items()},
        "body_preview": r.text[:200]}
def start_target(port=9212, timeout=15):
    """Start target server. NOTE: differential_target_v2.py hardcodes PORT=9210.
    The port parameter is ignored for binding; we always connect to 9210.
    """
    script = os.path.join(_ROOT, "benchmarks", "differential_v2", "differential_target_v2.py")
    proc = subprocess.Popen([sys.executable, script], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, env=os.environ.copy(), preexec_fn=os.setsid)
    actual_port = 9210  # Server hardcodes this
    for _ in range(int(timeout*10)):
        try: httpx.get(f"http://127.0.0.1:{actual_port}/", timeout=0.2); return proc, actual_port
        except Exception: time.sleep(0.1)
    return proc, actual_port
def stop_target(proc):
    try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM); proc.wait(timeout=5)
    except Exception:
        try: proc.kill()
        except Exception: pass
def run_llm_off(case_id, case, client, base_url):
    """Mode A: Deterministic only — direct guarded_causal_evaluate on observations."""
    try:
        rb = client.get(case["baseline"], headers={"X-Actor":"attacker"})
        rc = client.get(case["candidate"], headers={"X-Actor":"attacker"})
        rctrl = client.get(case["control"], headers={"X-Actor":"attacker"})
        b = make_obs(rb, case["baseline"], base_url)
        c = make_obs(rc, case["candidate"], base_url)
        ctrl = make_obs(rctrl, case["control"], base_url)

        result = guarded_causal_evaluate(b, c, ctrl)
        verdict = result.verdict.value
        confidence = result.confidence
        return {"case_id": case_id, "verdict": verdict,
                "confidence": confidence, "status": "OK"}
    except Exception as e:
        return {"case_id": case_id, "verdict": "ERROR",
                "status": f"ERROR: {type(e).__name__}: {str(e)[:200]}"}
def run_llm_on(case_id, case, client, base_url, researcher, tool_boundary):
    """Mode B: Full LLM-augmented pipeline."""
    try:
        rb = client.get(case["baseline"], headers={"X-Actor":"attacker"})
        rc = client.get(case["candidate"], headers={"X-Actor":"attacker"})
        rctrl = client.get(case["control"], headers={"X-Actor":"attacker"})
        b = make_obs(rb, case["baseline"], base_url)
        c = make_obs(rc, case["candidate"], base_url)
        ctrl = make_obs(rctrl, case["control"], base_url)

        bridge = CausalFeedbackBridge(researcher, tool_boundary, max_loops=3)
        result = bridge.run_research_loop([b, c, ctrl], guarded_causal_evaluate)

        return {"case_id": case_id, "verdict": result["final_verdict"],
                "loops_run": result.get("loops_run", 0),
                "confidence": result.get("confidence", 0.0),
                "status": "OK"}
    except Exception as e:
        return {"case_id": case_id, "verdict": "ERROR",
                "status": f"ERROR: {type(e).__name__}: {str(e)[:200]}"}
def run_differential():
    print("=" * 60)
    print("GOED v1.8.4 — Phase 11: LLM_OFF vs LLM_ON Differential")
    print("=" * 60)

    with open(os.path.join(BENCHMARK_DIR, "manifest.json")) as f:
        manifest = json.load(f)

    # Normalize cases to dict (blind_v3 manifest uses list format with case_id field)
    raw_cases = manifest.get("cases", [])
    if isinstance(raw_cases, list):
        cases = {c["case_id"]: c for c in raw_cases}
    else:
        cases = raw_cases

    print(f"Cases: {len(cases)}")

    # Check real API gate
    provider = get_provider_from_env("differential-v184")
    if provider is None or getattr(provider, 'mock_provider', True):
        result = {"phase": "11_differential", "status": "REAL_API_UNAVAILABLE",
                  "note": "LLM_API_KEY not set or mock active. Requires real LLM for Mode B."}
        with open(os.path.join(REPORTS_DIR, "differential_v184.json"), "w") as f:
            json.dump(result, f, indent=2)
        print("REAL_API_UNAVAILABLE — report written.")
        return

    proc, port = start_target(9212)
    time.sleep(0.3)
    base_url = f"http://127.0.0.1:{port}"

    client = httpx.Client(timeout=10, base_url=base_url)
    tb = ToolBoundary(http_client=client)
    rsch = LLMResearcher(tool_boundary=tb, llm_client=provider)

    t0 = time.time()
    mode_a_results = {}  # LLM_OFF
    mode_b_results = {}  # LLM_ON

    # --- Mode A: LLM_OFF ---
    print("\n[1/2] Mode A — LLM_OFF (deterministic only)...")
    for i, (cid, case) in enumerate(cases.items()):
        print(f"  [{i+1}/{len(cases)}] {cid}...", end=" ", flush=True)
        r = run_llm_off(cid, case, client, base_url)
        mode_a_results[cid] = r
        print(r["verdict"])

    # --- Mode B: LLM_ON ---
    print("\n[2/2] Mode B — LLM_ON (full pipeline)...")
    for i, (cid, case) in enumerate(cases.items()):
        print(f"  [{i+1}/{len(cases)}] {cid}...", end=" ", flush=True)
        r = run_llm_on(cid, case, client, base_url, rsch, tb)
        mode_b_results[cid] = r
        print(r["verdict"])

    elapsed = time.time() - t0

    # --- Delta analysis (requires ground truth, loaded HERE for scoring only) ---
    with open(os.path.join(BENCHMARK_DIR, "ground_truth.json")) as f:
        ground_truth = json.load(f)

    def classify(results):
        tp = fp = fn = tn = 0
        for cid, r in results.items():
            gt = ground_truth.get(cid, {})
            actual = gt.get("expected_label") == "vulnerable"
            pred = r.get("verdict") == "CONFIRMED"
            if pred and actual: tp += 1
            elif pred and not actual: fp += 1
            elif not pred and actual: fn += 1
            else: tn += 1
        return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": round(tp/max(tp+fp,1),4),
                "recall": round(tp/max(tp+fn,1),4)}

    ma = classify(mode_a_results)
    mb = classify(mode_b_results)

    delta_recall = mb["recall"] - ma["recall"]
    delta_precision = mb["precision"] - ma["precision"]

    # Recovered cases: LLM_OFF=FN AND LLM_ON=TP
    recovered_cases = []
    for cid in cases:
        a_fn = mode_a_results[cid].get("verdict") != "CONFIRMED" and \
               ground_truth.get(cid, {}).get("expected_label") == "vulnerable"
        b_tp = mode_b_results[cid].get("verdict") == "CONFIRMED" and \
               ground_truth.get(cid, {}).get("expected_label") == "vulnerable"
        if a_fn and b_tp:
            recovered_cases.append(cid)

    # Lost cases: LLM_OFF=TP AND LLM_ON=FN (regression)
    lost_cases = []
    for cid in cases:
        a_tp = mode_a_results[cid].get("verdict") == "CONFIRMED" and \
               ground_truth.get(cid, {}).get("expected_label") == "vulnerable"
        b_fn = mode_b_results[cid].get("verdict") != "CONFIRMED" and \
               ground_truth.get(cid, {}).get("expected_label") == "vulnerable"
        if a_tp and b_fn:
            lost_cases.append(cid)

    if delta_recall <= 0:
        overall_note = "REAL_LLM_INTEGRATED_NO_MEASURED_GAIN — Principle #10 applies"
        overall_status = "NO_MEASURED_GAIN"
    else:
        overall_note = f"Measured recall gain: +{delta_recall:.4f}"
        overall_status = "MEASURED_GAIN"

    result = {
        "phase": "11_differential",
        "status": "OK",
        "classification": overall_status,
        "note": overall_note,
        "elapsed_seconds": round(elapsed, 1),
        "mode_a_llm_off": {"metrics": ma, "per_case": mode_a_results},
        "mode_b_llm_on": {"metrics": mb, "per_case": mode_b_results},
        "delta": {
            "recall": round(delta_recall, 4),
            "precision": round(delta_precision, 4),
            "recovered_cases": recovered_cases,
            "recovered_count": len(recovered_cases),
            "lost_cases": lost_cases,
            "lost_count": len(lost_cases),
        },
        "provider_metadata": provider.get_provider_metadata(),
    }

    with open(os.path.join(REPORTS_DIR, "differential_v184.json"), "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n{'='*60}")
    print(f"Mode A (LLM_OFF): P={ma['precision']} R={ma['recall']} TP={ma['tp']} FN={ma['fn']}")
    print(f"Mode B (LLM_ON):  P={mb['precision']} R={mb['recall']} TP={mb['tp']} FN={mb['fn']}")
    print(f"Delta Recall: {delta_recall:+.4f} — {overall_status}")
    print(f"Recovered: {len(recovered_cases)}, Lost: {len(lost_cases)}")

    client.close()
    stop_target(proc)
if __name__ == "__main__":
    run_differential()
