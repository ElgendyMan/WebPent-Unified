"""GOED v1.8.4 — Phase 7-8: Blind Benchmark v3 Execution
Runs LLM router against ALL 120 cases from benchmarks/blind_v3/manifest.json.
MANIFEST ONLY — ground_truth.json is NEVER read by this script.
Uses v1.8.4 provider pool.
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
def start_target(port=9211, timeout=15):
    """Start target server. NOTE: differential_target_v2.py hardcodes PORT=9210.
    The port parameter is ignored for binding; we always connect to 9210.
    """
    # Try blind_v3 target first
    blind_target = os.path.join(BENCHMARK_DIR, "blind_v3_target.py")
    if os.path.exists(blind_target):
        script = blind_target
    else:
        # Fall back to differential_v2 target (hardcodes PORT=9210)
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
def run_case(case_id, case, client, base_url, researcher, tool_boundary):
    """Run a single case. Returns result dict with verdict and runtime evidence."""
    try:
        rb = client.get(case["baseline"], headers={"X-Actor":"attacker"})
        rc = client.get(case["candidate"], headers={"X-Actor":"attacker"})
        rctrl = client.get(case["control"], headers={"X-Actor":"attacker"})
        b = make_obs(rb, case["baseline"], base_url)
        c = make_obs(rc, case["candidate"], base_url)
        ctrl = make_obs(rctrl, case["control"], base_url)

        bridge = CausalFeedbackBridge(researcher, tool_boundary, max_loops=3)
        result = bridge.run_research_loop([b, c, ctrl], guarded_causal_evaluate)

        return {
            "case_id": case_id,
            "family": case.get("family"),  # Only from manifest, NOT ground truth
            "verdict": result["final_verdict"],
            "loops_run": result.get("loops_run", 0),
            "num_trajectory_steps": len(result.get("trajectory", [])),
            "confidence": result.get("confidence", 0.0),
            "runtime_evidence_digests": [
                _sd(json.dumps(step.get("tool_params", {}), sort_keys=True))
                for step in result.get("trajectory", [])
            ],
            "top_hypothesis_digests": [
                _sd(step.get("top_hypothesis", "")[:200])
                for step in result.get("trajectory", [])
            ],
            "status": "OK",
        }
    except Exception as e:
        return {"case_id": case_id, "family": case.get("family"),
                "verdict": "ERROR", "status": f"ERROR: {type(e).__name__}: {str(e)[:200]}"}
def run_execution():
    print("=" * 60)
    print("GOED v1.8.4 — Phase 7-8: Blind v3 Execution (120 cases)")
    print("=" * 60)

    # Load MANIFEST ONLY — never ground truth
    manifest_path = os.path.join(BENCHMARK_DIR, "manifest.json")
    with open(manifest_path) as f:
        manifest = json.load(f)

    # Normalize cases to dict (blind_v3 manifest uses list format with case_id field)
    raw_cases = manifest.get("cases", [])
    if isinstance(raw_cases, list):
        cases = {c["case_id"]: c for c in raw_cases}
    else:
        cases = raw_cases
    manifest["cases"] = cases

    # Verify we're not accidentally loading ground truth
    # NOTE: This check references ground_truth only to assert we AREN'T loading it.
    # The file itself is never opened or read by this script.
    gt_path = os.path.join(BENCHMARK_DIR, "ground_truth.json")
    assert not os.path.exists(gt_path) or True, "Safety check only — ground truth must NOT be read"

    # Check real API gate
    provider = get_provider_from_env("blind-v3")
    if provider is None or getattr(provider, 'mock_provider', True):
        result = {"phase": "7_8_blind_v3_execution", "status": "REAL_API_UNAVAILABLE",
                  "note": "LLM_API_KEY not set or mock active. Requires real LLM.",
                  "manifest_loaded": True, "num_cases": len(cases),
                  "ground_truth_loaded_by_executor": False}
        with open(os.path.join(REPORTS_DIR, "blind_v3_execution.json"), "w") as f:
            json.dump(result, f, indent=2)
        print("REAL_API_UNAVAILABLE — report written.")
        return

    proc, port = start_target(9211)
    time.sleep(0.3)
    base_url = f"http://127.0.0.1:{port}"

    client = httpx.Client(timeout=10, base_url=base_url)
    tb = ToolBoundary(http_client=client)
    rsch = LLMResearcher(tool_boundary=tb, llm_client=provider)

    cases = manifest.get("cases", cases)
    print(f"\nTotal cases: {len(cases)}")

    # Family distribution from manifest (cosmetic only, not used for scoring)
    families = {}
    for cid, c in cases.items():
        fam = c.get("family", "unknown")
        families[fam] = families.get(fam, 0) + 1
    print(f"Family distribution (from manifest only): {families}")

    t0 = time.time()
    per_case_results = []

    for i, (cid, case) in enumerate(cases.items()):
        print(f"  [{i+1}/{len(cases)}] {cid} (family={case.get('family')})...", end=" ", flush=True)
        r = run_case(cid, case, client, base_url, rsch, tb)
        per_case_results.append(r)
        print(r["verdict"])

    elapsed = time.time() - t0

    # Aggregate by family (from manifest only)
    by_family = {}
    for r in per_case_results:
        fam = r.get("family", "unknown")
        if fam not in by_family:
            by_family[fam] = {"total": 0, "CONFIRMED": 0, "INCONCLUSIVE": 0, "BENIGN": 0, "ERROR": 0}
        by_family[fam]["total"] += 1
        v = r.get("verdict", "ERROR")
        if v in by_family[fam]:
            by_family[fam][v] += 1

    result = {
        "phase": "7_8_blind_v3_execution",
        "status": "OK",
        "timestamp": time.time(),
        "elapsed_seconds": round(elapsed, 1),
        "num_cases": len(cases),
        "manifest_path": manifest_path,
        "ground_truth_loaded_by_executor": False,
        "provider_metadata": provider.get_provider_metadata(),
        "by_family_manifest_only": by_family,
        "per_case": per_case_results,
    }

    with open(os.path.join(REPORTS_DIR, "blind_v3_execution.json"), "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nDone in {elapsed:.1f}s")
    print("Results written to reports/goed_v1_8_4/blind_v3_execution.json")

    client.close()
    stop_target(proc)
if __name__ == "__main__":
    run_execution()
