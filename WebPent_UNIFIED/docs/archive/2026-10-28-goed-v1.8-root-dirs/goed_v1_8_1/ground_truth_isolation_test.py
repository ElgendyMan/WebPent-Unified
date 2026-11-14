"""GOED v1.8.1 — Ground-Truth Isolation Test (Phase 6)"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.join(_HERE, "..")
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)

from webpent.llm_researcher import LLMResearcher, ToolBoundary
from webpent.llm_researcher.tool_boundary import ToolCall

REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_1")
os.makedirs(REPORTS_DIR, exist_ok=True)

PROHIBITED_FIELDS = ["ground_truth","expected_label","vulnerability_class","case_id",
    "benchmark_id","mechanism","is_vulnerable","expected_verdict","oracle_answer","label","class"]

def test_sanitization():
    r = LLMResearcher()
    obs = {"status_code": 200, "headers": {"x-actor-echo": "a"}, "request": {"path": "/t"},
           **{f: f"INJECTED_{f}" for f in PROHIBITED_FIELDS}}
    r.ingest_observation(obs)
    s = r.memory.observations[-1]
    stripped = all(f not in s for f in PROHIBITED_FIELDS)
    return {"all_prohibited_fields_stripped": stripped,
            "legitimate_preserved": s.get("status_code")==200,
            "policy_unchanged": r.get_policy_hash()==r.system_prompt_hash}

def test_tool_boundary_blocks():
    b = ToolBoundary()
    attempts = [("shell_exec",{"command":"cat x"}),("file_write",{}),
                ("modify_detector",{}),("set_confirmed",{}),("bypass_causal_guard",{}),
                ("override_verdict",{}),("mutate_evidence",{})]
    r = {}
    all_blocked = True
    for tn, p in attempts:
        tc = ToolCall(tool_name=tn, parameters=p, hypothesis="x")
        res = b.execute(tc)
        blocked = res.get("authorized") is False and "FORBIDDEN_TOOL" in str(res.get("error",""))
        r[f"blocked_{tn}"] = blocked
        if not blocked: all_blocked = False
    r["all_prohibited_tools_blocked"] = all_blocked
    return r

def test_llm_no_authority():
    r = LLMResearcher()
    forbidden = ["confirm_vulnerability","mark_confirmed","set_confirmed",
        "bypass_causal_guard","override_verdict","mutate_evidence","modify_proof_bundle"]
    r2 = {f"no_{m}": not hasattr(r, m) for m in forbidden}
    r2["all_forbidden_methods_absent"] = all(r2.values())
    return r2

def run_isolation_tests():
    print("="*60); print("Ground-Truth Isolation Tests"); print("="*60)
    results = {"observation_sanitization": test_sanitization(),
               "tool_boundary_blocks": test_tool_boundary_blocks(),
               "llm_no_verdict_authority": test_llm_no_authority()}
    overall = all(v.get(list(v.keys())[-1], False) for v in results.values())
    results["overall"] = "PASS" if overall else "FAIL"
    print(f"\nOverall: {results['overall']}")
    for tn, checks in results.items():
        if tn == "overall": continue
        print(f"\n  {tn}:")
        for k, v in checks.items():
            if isinstance(v, bool): print(f"    {'✅' if v else '❌'} {k}")
    with open(os.path.join(REPORTS_DIR, "ground_truth_isolation.json"), "w") as f:
        json.dump(results, f, indent=2, default=str)
    print("\n✅ Saved: reports/goed_v1_8_1/ground_truth_isolation.json")
    return results

if __name__ == "__main__":
    run_isolation_tests()
