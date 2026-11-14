"""GOED v1.8.1 — LLM ON/OFF Comparison (Phase 4)"""

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

REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_1")
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


def start_target(script, port, timeout=15):
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


def run_mode(base_url, cases, actor, use_llm=False, llm_client=None):
    results = []
    tp = fp = fn = tn = 0
    total_hyps = useful = total_tools = 0
    steps_list = []
    t0 = time.time()
    client = httpx.Client(timeout=10)
    tb = ToolBoundary(http_client=client) if use_llm else None
    rsch = LLMResearcher(tool_boundary=tb, llm_client=llm_client) if use_llm else None

    for case in cases:
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
            iv = case.get("is_vulnerable", False)
            steps = 1
            nh = ntools = 0
            hu = False

            if use_llm and rsch:
                rsch.memory = type(rsch.memory)()
                rsch.ingest_observation(b)
                rsch.ingest_observation(c)
                rsch.ingest_observation(ctrl)
                hyps = rsch.generate_hypotheses()
                nh = len(hyps)
                total_hyps += nh
                if iv and any(
                    (
                        "ownership" in h.description.lower()
                        or "boundary" in h.description.lower()
                        or "tenant" in h.description.lower()
                    )
                    for h in hyps
                ):
                    useful += 1
                    hu = True
                if verdict == "INCONCLUSIVE":
                    loop = ResearchLoop(rsch, tb, max_loops=3)
                    lr = loop.run([b, c, ctrl])
                    ntools = lr.tool_calls
                    total_tools += ntools
                    steps += lr.experiments_run

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
                    "case_id": case.get("case_id", "?"),
                    "verdict": verdict,
                    "outcome": o,
                    "confidence": round(er.confidence, 4),
                    "is_vulnerable": iv,
                    "class": case.get("class", "?"),
                    "hypotheses": nh,
                    "tool_calls": ntools,
                    "hypothesis_useful": hu,
                    "steps": steps,
                }
            )
        except Exception as e:
            results.append({"case_id": case.get("case_id", "?"), "error": str(e)})
    client.close()
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    return {
        "mode": "LLM_ON" if use_llm else "LLM_OFF",
        "model": getattr(llm_client, "model", "none") if llm_client else "none",
        "provider": type(llm_client).__name__ if llm_client else "none",
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
            "useful_hypotheses": useful,
            "useful_rate": round(useful / max(total_hyps, 1), 4),
            "total_tool_calls": total_tools,
            "probes_per_confirmed": round(total_tools / max(tp, 1), 2),
            "avg_steps_to_confirm": round(sum(steps_list) / max(len(steps_list), 1), 2),
            "elapsed": round(time.time() - t0, 2),
        },
        "per_case": results,
        "deterministic_oracle_authoritative": True,
    }


def run_comparison():
    print("=" * 60)
    print("GOED v1.8.1 — LLM ON/OFF Comparison")
    print("=" * 60)
    ADV3 = os.path.join(_ROOT, "benchmarks", "goed_v1_7_adversarial_v3")
    with open(os.path.join(ADV3, "manifest.json")) as f:
        mf = json.load(f)
    cases = []
    for cid, c in mf.get("vulnerable", {}).items():
        cases.append({"case_id": cid, **c})
    for cid, c in mf.get("clean", {}).items():
        cases.append({"case_id": cid, **c})
    print(f"Cases: {len(cases)}")

    proc = start_target(os.path.join(ADV3, "adversarial_v3_target.py"), 9150)
    base = "http://127.0.0.1:9150"
    try:
        print("\n--- Mode A: LLM OFF ---")
        ma = run_mode(base, cases, "attacker", use_llm=False)
        print(f"  TP={ma['metrics']['tp']} FP={ma['metrics']['fp']} FN={ma['metrics']['fn']} TN={ma['metrics']['tn']}")
        print(f"  P={ma['metrics']['precision']:.4f} R={ma['metrics']['recall']:.4f} F1={ma['metrics']['f1']:.4f}")

        print("\n--- Mode B: LLM ON ---")
        rsch = LLMResearcher()
        llm = get_provider_from_env(rsch.get_policy_hash())
        print(f"  Provider: {type(llm).__name__}, Model: {llm.model}")
        mb = run_mode(base, cases, "attacker", use_llm=True, llm_client=llm)
        print(f"  TP={mb['metrics']['tp']} FP={mb['metrics']['fp']} FN={mb['metrics']['fn']} TN={mb['metrics']['tn']}")
        print(f"  P={mb['metrics']['precision']:.4f} R={mb['metrics']['recall']:.4f} F1={mb['metrics']['f1']:.4f}")
        lm = mb["llm_metrics"]
        print(
            f"  Hypotheses: {lm['total_hypotheses']} (useful: {lm['useful_hypotheses']}, rate: {lm['useful_rate']:.2%})"
        )
        print(f"  Tool calls: {lm['total_tool_calls']}")

        delta = {
            "precision_change": round(mb["metrics"]["precision"] - ma["metrics"]["precision"], 4),
            "recall_change": round(mb["metrics"]["recall"] - ma["metrics"]["recall"], 4),
            "f1_change": round(mb["metrics"]["f1"] - ma["metrics"]["f1"], 4),
            "hypotheses": lm["total_hypotheses"],
            "useful_rate": lm["useful_rate"],
            "tool_calls": lm["total_tool_calls"],
            "steps_change": round(lm["avg_steps_to_confirm"] - ma["llm_metrics"]["avg_steps_to_confirm"], 2),
        }
        print("\n--- Delta ---")
        for k, v in delta.items():
            print(f"  {k}: {v}")

        comp = {
            "timestamp": time.time(),
            "target": "adversarial_v3",
            "deterministic_oracle_identical": True,
            "mode_a_llm_off": ma,
            "mode_b_llm_on": mb,
            "delta": delta,
            "telemetry_redacted": llm.get_redacted_telemetry() if hasattr(llm, "get_redacted_telemetry") else [],
            "usage": llm.get_usage_stats() if hasattr(llm, "get_usage_stats") else {},
        }
        with open(os.path.join(REPORTS_DIR, "llm_comparison.json"), "w") as f:
            json.dump(comp, f, indent=2, default=str)
        print("\n✅ Saved: reports/goed_v1_8_1/llm_comparison.json")
    finally:
        stop_target(proc)
    return comp


if __name__ == "__main__":
    run_comparison()
