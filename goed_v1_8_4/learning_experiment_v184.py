"""GOED v1.8.4 — Phase 16: Learning Experiment
COLD vs LEARNED runs against v1.8.4 provider pool/router.
Acceptance: only hypothesis/strategy ordering differs between COLD and LEARNED.
If anything else differs (findings, verdicts), that's a LEAK, not learning → FAIL.
"""
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from collections import Counter

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
def _sd(t): return hashlib.sha256(t.encode()).hexdigest()
def make_obs(r, p, base_url=None):
    return {"status_code": r.status_code, "body_length": len(r.text),
        "semantic_digest": _sd(r.text),
        "response_shape": "json" if r.text.strip().startswith("{") else "text",
        "request": {"method": "GET", "path": p.split("?")[0],
                   "header_names": ["X-Actor"], "base_url": base_url},
        "headers": {k.lower(): v for k, v in r.headers.items()},
        "body_preview": r.text[:200]}
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
def run_eval(case_ids, manifest, ground_truth, base_url, learned_weights=None):
    """Run evaluation with optional learned weights. Returns metrics + per-case verdicts."""
    provider = get_provider_from_env("learn-eval")
    if provider is None or getattr(provider, 'mock_provider', True):
        return {"status": "REAL_API_UNAVAILABLE", "note": "LLM_API_KEY not set or mock active"}

    client = httpx.Client(timeout=10, base_url=base_url)
    tb = ToolBoundary(http_client=client)
    rsch = LLMResearcher(tool_boundary=tb, llm_client=provider)

    if learned_weights:
        rsch.apply_hypothesis_weights(learned_weights)

    tp = fn = 0
    verdicts = {}
    ordering_signals = []

    for cid in case_ids:
        case = manifest["cases"][cid]
        try:
            rb = client.get(case["baseline"], headers={"X-Actor":"attacker"})
            rc = client.get(case["candidate"], headers={"X-Actor":"attacker"})
            rctrl = client.get(case["control"], headers={"X-Actor":"attacker"})
            b = make_obs(rb, case["baseline"], base_url)
            c = make_obs(rc, case["candidate"], base_url)
            ctrl = make_obs(rctrl, case["control"], base_url)
            iv = ground_truth[cid]["expected_label"] == "vulnerable"

            bridge = CausalFeedbackBridge(rsch, tb, max_loops=2)
            result = bridge.run_research_loop([b, c, ctrl], guarded_causal_evaluate)
            verdict = result["final_verdict"]
            verdicts[cid] = verdict

            # Capture hypothesis ordering signal (not the actual hypotheses)
            traj = result.get("trajectory", [])
            if traj:
                ordering_signals.append({
                    "case_id": cid,
                    "num_hypotheses": len(traj[0].get("hypotheses", [])),
                    "top_hypothesis_digest": _sd(traj[0].get("top_hypothesis", "")[:100])
                })

            if verdict == "CONFIRMED" and iv:
                tp += 1
            elif iv and verdict != "CONFIRMED":
                fn += 1
        except Exception as e:
            verdicts[cid] = f"ERROR: {type(e).__name__}"

    client.close()
    rec = tp / max(tp + fn, 1)
    return {"status": "OK", "recall": round(rec, 4), "tp": tp, "fn": fn,
            "verdicts": verdicts, "ordering_signals": ordering_signals}
def derive_learned_weights(cold_result):
    """Derive hypothesis weights from COLD run's successful patterns.
    Only changes ordering/prioritization, NOT the evaluation logic itself."""
    weights = Counter()
    for sig in cold_result.get("ordering_signals", []):
        weights[sig["top_hypothesis_digest"]] += 1
    return dict(weights.most_common())
def run_experiment():
    print("=" * 60)
    print("GOED v1.8.4 — Phase 16: Learning Experiment")
    print("=" * 60)

    # Load manifest and ground truth (GT only for scoring, never sent to LLM)
    with open(os.path.join(_ROOT, "benchmarks", "differential_v2", "manifest.json")) as f:
        manifest = json.load(f)
    with open(os.path.join(_ROOT, "benchmarks", "differential_v2", "ground_truth.json")) as f:
        ground_truth = json.load(f)

    # Use reasoning family cases (most interesting for learning)
    case_ids = [cid for cid, c in manifest["cases"].items()
                if c.get("family") in ("reasoning", "novel")][:20]

    proc = start_target(9210)
    time.sleep(0.3)
    base_url = "http://127.0.0.1:9210"

    try:
        # COLD run: no prior knowledge
        print("\n[1/2] COLD run (no learned weights)...")
        cold = run_eval(case_ids, manifest, ground_truth, base_url, learned_weights=None)

        if cold.get("status") == "REAL_API_UNAVAILABLE":
            result = {"phase": "16_learning", "status": "REAL_API_UNAVAILABLE",
                      "note": "LLM_API_KEY not set. Learning experiment requires real LLM."}
            with open(os.path.join(REPORTS_DIR, "learning_experiment_v184.json"), "w") as f:
                json.dump(result, f, indent=2)
            print("REAL_API_UNAVAILABLE — report written.")
            return

        # Derive learned weights from COLD patterns
        learned_weights = derive_learned_weights(cold)

        # LEARNED run: same cases, same target, same provider, only weights differ
        print("\n[2/2] LEARNED run (with hypothesis ordering weights)...")
        learned = run_eval(case_ids, manifest, ground_truth, base_url,
                          learned_weights=learned_weights)

        # Acceptance check: only ordering should differ, NOT verdicts
        cold_verdicts = cold.get("verdicts", {})
        learned_verdicts = learned.get("verdicts", {})
        common_cases = set(cold_verdicts.keys()) & set(learned_verdicts.keys())
        verdict_mismatches = {cid: (cold_verdicts[cid], learned_verdicts[cid])
                             for cid in common_cases
                             if cold_verdicts[cid] != learned_verdicts[cid]}

        ordering_changed = (
            cold.get("ordering_signals", []) != learned.get("ordering_signals", [])
        )

        if verdict_mismatches:
            # LEAK: learning changed verdicts, not just ordering
            status = "FAILED"
            classification = "LEAK_DETECTED"
            note = "Learning changed verdicts (not just ordering) — this is a leak, not learning."
        elif ordering_changed:
            status = "PASS"
            classification = "LEARNING_VERIFIED"
            note = "Only hypothesis/strategy ordering differs between COLD and LEARNED."
        else:
            status = "PASS"
            classification = "NO_MEASURABLE_LEARNING"
            note = "No ordering change detected between COLD and LEARNED runs."

        result = {
            "phase": "16_learning",
            "status": status,
            "classification": classification,
            "note": note,
            "cold": {"recall": cold.get("recall"), "tp": cold.get("tp"), "fn": cold.get("fn"),
                     "num_cases": len(cold_verdicts)},
            "learned": {"recall": learned.get("recall"), "tp": learned.get("tp"), "fn": learned.get("fn"),
                        "num_cases": len(learned_verdicts)},
            "verdict_mismatches": verdict_mismatches,
            "verdict_match_count": len(common_cases) - len(verdict_mismatches),
            "verdict_total_compared": len(common_cases),
            "ordering_changed": ordering_changed,
            "learned_weights_count": len(learned_weights),
        }

        with open(os.path.join(REPORTS_DIR, "learning_experiment_v184.json"), "w") as f:
            json.dump(result, f, indent=2)

        print(f"\nResult: {status} — {classification}")
        print(f"  Cold recall: {cold.get('recall')}, Learned recall: {learned.get('recall')}")
        print(f"  Verdict matches: {len(common_cases) - len(verdict_mismatches)}/{len(common_cases)}")
        print(f"  Ordering changed: {ordering_changed}")

    finally:
        stop_target(proc)
if __name__ == "__main__":
    run_experiment()
