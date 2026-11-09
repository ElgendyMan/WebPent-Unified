"""GOED v1.8.2 — Differential Benchmark Runner
Runs 60 cases in LLM OFF and LLM ON modes.
Ground truth stored independently — runtime NEVER receives it.
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
from webpent.llm_researcher import LLMResearcher, ResearchLoop, ToolBoundary, get_provider_from_env

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


def _classify(v, iv):
    if v == "CONFIRMED" and iv:
        return "TP"
    if v == "CONFIRMED" and not iv:
        return "FP"
    if v == "CLEAN" and not iv:
        return "TN"
    if (v == "CLEAN" or v == "INCONCLUSIVE") and iv:
        return "FN"
    return v


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


def run_mode(base_url, cases, ground_truth, actor, use_llm=False, llm_client=None):
    """Run evaluation. ground_truth used ONLY for scoring — NEVER passed to detector/LLM."""
    results = []
    tp = fp = fn = tn = 0
    total_hyps = useful = redundant = invalid = blocked = 0
    total_tools = 0
    steps_list = []
    t0 = time.time()
    client = httpx.Client(timeout=10)
    tb = ToolBoundary(http_client=client) if use_llm else None
    rsch = LLMResearcher(tool_boundary=tb, llm_client=llm_client) if use_llm else None

    for cid, case in cases.items():
        try:
            rb = client.get(f"{base_url}{case['baseline']}", headers={"X-Actor": actor})
            rc = client.get(f"{base_url}{case['candidate']}", headers={"X-Actor": actor})
            rctrl = client.get(f"{base_url}{case['control']}", headers={"X-Actor": actor})
            b, c, ctrl = (
                make_obs(rb, case["baseline"]),
                make_obs(rc, case["candidate"]),
                make_obs(rctrl, case["control"]),
            )

            er = guarded_causal_evaluate(b, c, ctrl)
            verdict = er.verdict.value
            iv = ground_truth[cid]["expected_label"] == "vulnerable"
            steps = 1
            nh = nu = nr = ni = nb = 0
            ntools = 0

            if use_llm and rsch:
                rsch.memory = type(rsch.memory)()
                rsch.ingest_observation(b)
                rsch.ingest_observation(c)
                rsch.ingest_observation(ctrl)
                hyps = rsch.generate_hypotheses()
                nh = len(hyps)
                total_hyps += nh

                # Classify hypotheses
                family = case.get("family", "easy")
                for h in hyps:
                    hd = h.description.lower()
                    if any(w in hd for w in ["confirm", "bypass", "override", "authority", "shell", "exec"]):
                        blocked += 1
                        nb += 1
                        continue
                    useful_patterns = [
                        "ownership",
                        "boundary",
                        "tenant",
                        "isolation",
                        "workflow",
                        "state",
                        "relationship",
                        "multi-step",
                        "prerequisite",
                        "consequence",
                        "invariant",
                        "equivalent",
                        "nested",
                        "indirect",
                        "counter",
                        "chain",
                        "composition",
                        "side effect",
                        "transitive",
                        "conditional",
                    ]
                    if any(p in hd for p in useful_patterns):
                        useful += 1
                        nu += 1
                    elif any(w in hd for w in ["http 200", "status code", "response exists", "endpoint"]):
                        redundant += 1
                        nr += 1
                    else:
                        invalid += 1
                        ni += 1

                if verdict == "INCONCLUSIVE":
                    loop = ResearchLoop(rsch, tb, max_loops=3)
                    lr = loop.run([b, c, ctrl])
                    ntools = lr.tool_calls
                    total_tools += ntools
                    steps += lr.experiments_run

                    # Re-evaluate after LLM exploration (if new observations)
                    if lr.findings_for_deterministic_validation:
                        pass  # Final verdict still from original deterministic eval

            o = _classify(verdict, iv)
            if o == "TP":
                tp += 1
            elif o == "FP":
                fp += 1
            elif o == "TN":
                tn += 1
            elif o == "FN":
                fn += 1
            if verdict == "CONFIRMED":
                steps_list.append(steps)

            results.append(
                {
                    "case_id": cid,
                    "family": case.get("family"),
                    "verdict": verdict,
                    "outcome": o,
                    "confidence": round(er.confidence, 4),
                    "is_vulnerable": iv,
                    "hypotheses": nh,
                    "useful_hyp": nu,
                    "redundant_hyp": nr,
                    "invalid_hyp": ni,
                    "blocked_hyp": nb,
                    "tool_calls": ntools,
                    "steps": steps,
                }
            )
        except Exception as e:
            results.append({"case_id": cid, "error": str(e)})

    client.close()
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0

    return {
        "mode": "LLM_ON" if use_llm else "LLM_OFF",
        "model": getattr(llm_client, "model", "none") if llm_client else "none",
        "provider_type": getattr(llm_client, "provider_type", "none") if llm_client else "none",
        "mock_provider": getattr(llm_client, "is_mock", True) if llm_client else True,
        "cases": len(results),
        "metrics": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
        },
        "llm_metrics": {
            "total_hypotheses": total_hyps,
            "useful": useful,
            "useful_rate": round(useful / max(total_hyps, 1), 4),
            "redundant": redundant,
            "invalid": invalid,
            "blocked": blocked,
            "total_tool_calls": total_tools,
            "probes_per_confirmed": round(total_tools / max(tp, 1), 2),
            "avg_steps_to_confirm": round(sum(steps_list) / max(len(steps_list), 1), 2),
            "elapsed": round(time.time() - t0, 2),
        },
        "per_case": results,
        "deterministic_oracle_authoritative": True,
    }


def run_differential():
    print("=" * 60)
    print("GOED v1.8.2 — Differential Benchmark")
    print("=" * 60)

    with open(os.path.join(_ROOT, "benchmarks", "differential_v1", "manifest.json")) as f:
        manifest = json.load(f)
    with open(os.path.join(_ROOT, "benchmarks", "differential_v1", "ground_truth.json")) as f:
        ground_truth = json.load(f)

    cases = manifest["cases"]
    print(f"Cases: {len(cases)} (families: easy=20, reasoning=20, novel=20)")
    vuln = sum(1 for g in ground_truth.values() if g["expected_label"] == "vulnerable")
    print(f"Vulnerable: {vuln}, Clean: {len(cases) - vuln}")

    proc = start_target(9200)
    base = "http://127.0.0.1:9200"
    try:
        print("\n--- Mode A: LLM OFF (pure deterministic) ---")
        ma = run_mode(base, cases, ground_truth, "attacker", use_llm=False)
        print(f"  TP={ma['metrics']['tp']} FP={ma['metrics']['fp']} FN={ma['metrics']['fn']} TN={ma['metrics']['tn']}")
        print(f"  P={ma['metrics']['precision']:.4f} R={ma['metrics']['recall']:.4f} F1={ma['metrics']['f1']:.4f}")

        # Family breakdown for LLM OFF
        by_family_off = {}
        for r in ma["per_case"]:
            fam = r.get("family", "unknown")
            by_family_off.setdefault(fam, {"tp": 0, "fn": 0})
            if r.get("outcome") == "TP":
                by_family_off[fam]["tp"] += 1
            elif r.get("outcome") == "FN":
                by_family_off[fam]["fn"] += 1
        print("  LLM OFF Recall by family:")
        for fam, counts in by_family_off.items():
            total = counts["tp"] + counts["fn"]
            rec = counts["tp"] / max(total, 1)
            print(f"    {fam}: TP={counts['tp']} FN={counts['fn']} recall={rec:.2%}")

        print("\n--- Mode B: LLM ON ---")
        rsch = LLMResearcher()
        llm = get_provider_from_env(rsch.get_policy_hash())
        print(f"  Provider: {type(llm).__name__}")
        print(f"  provider_type: {llm.provider_type}, mock: {llm.is_mock}")
        print(f"  Model: {llm.model}")

        mb = run_mode(base, cases, ground_truth, "attacker", use_llm=True, llm_client=llm)
        print(f"  TP={mb['metrics']['tp']} FP={mb['metrics']['fp']} FN={mb['metrics']['fn']} TN={mb['metrics']['tn']}")
        print(f"  P={mb['metrics']['precision']:.4f} R={mb['metrics']['recall']:.4f} F1={mb['metrics']['f1']:.4f}")
        lm = mb["llm_metrics"]
        print(f"  Hypotheses: {lm['total_hypotheses']} (useful={lm['useful']}, rate={lm['useful_rate']:.2%})")
        print(f"  Redundant={lm['redundant']} Invalid={lm['invalid']} Blocked={lm['blocked']}")

        # Family breakdown for LLM ON
        by_family_on = {}
        for r in mb["per_case"]:
            fam = r.get("family", "unknown")
            by_family_on.setdefault(fam, {"tp": 0, "fn": 0})
            if r.get("outcome") == "TP":
                by_family_on[fam]["tp"] += 1
            elif r.get("outcome") == "FN":
                by_family_on[fam]["fn"] += 1
        print("  LLM ON Recall by family:")
        for fam, counts in by_family_on.items():
            total = counts["tp"] + counts["fn"]
            rec = counts["tp"] / max(total, 1)
            print(f"    {fam}: TP={counts['tp']} FN={counts['fn']} recall={rec:.2%}")

        # Identify recovered cases
        off_verdicts = {r["case_id"]: r["outcome"] for r in ma["per_case"]}
        on_verdicts = {r["case_id"]: r["outcome"] for r in mb["per_case"]}
        recovered = [cid for cid in off_verdicts if off_verdicts[cid] == "FN" and on_verdicts.get(cid) == "TP"]
        print(f"\n--- LLM-Recovered Cases: {len(recovered)} ---")
        for cid in recovered[:10]:
            gt = ground_truth[cid]
            print(f"  {cid}: family={gt['case_family']}, mechanism={gt['mechanism']}")

        delta = {
            "precision_change": round(mb["metrics"]["precision"] - ma["metrics"]["precision"], 4),
            "recall_change": round(mb["metrics"]["recall"] - ma["metrics"]["recall"], 4),
            "f1_change": round(mb["metrics"]["f1"] - ma["metrics"]["f1"], 4),
            "recovered_cases": recovered,
            "recovered_count": len(recovered),
            "hypotheses": lm["total_hypotheses"],
            "useful_rate": lm["useful_rate"],
            "tool_calls": lm["total_tool_calls"],
        }
        print("\n--- Delta ---")
        for k, v in delta.items():
            if k != "recovered_cases":
                print(f"  {k}: {v}")

        result = {
            "timestamp": time.time(),
            "benchmark": "DifferentialBenchmark-v1",
            "deterministic_oracle_identical": True,
            "mode_a_llm_off": ma,
            "mode_b_llm_on": mb,
            "delta": delta,
            "provider_metadata": llm.get_provider_metadata() if hasattr(llm, "get_provider_metadata") else {},
            "telemetry_redacted": llm.get_redacted_telemetry() if hasattr(llm, "get_redacted_telemetry") else [],
            "note": "Mock provider used for engineering verification. "
            "Real API key required for REAL_API classification.",
        }

        out = os.path.join(REPORTS_DIR, "differential_results.json")
        with open(out, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print("\n✅ Saved: reports/goed_v1_8_2/differential_results.json")
    finally:
        stop_target(proc)
    return result


if __name__ == "__main__":
    run_differential()
