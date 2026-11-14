"""GOED v1.8.1 — Autonomous Strategy Selection (Phase 9)"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.join(_HERE, "..")
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)

from webpent.llm_researcher import ToolBoundary
from webpent.llm_researcher.tool_boundary import ALLOWED_TOOLS, ToolCall

REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_1")
os.makedirs(REPORTS_DIR, exist_ok=True)

STRATEGIES = {
    "authorization_differential": {"tool":"compare","params":{"s":"auth_diff"}},
    "object_substitution": {"tool":"request","params":{"s":"obj_sub"}},
    "semantic_comparison": {"tool":"compare","params":{"s":"sem_diff"}},
    "state_transition_testing": {"tool":"inspect_state","params":{"s":"pre_post"}},
    "workflow_manipulation": {"tool":"run_workflow_step","params":{"s":"step_reorder"}},
    "replay_testing": {"tool":"replay","params":{"s":"cond_replay"}},
    "invariant_probing": {"tool":"request","params":{"s":"inv_edge"}},
    "relationship_testing": {"tool":"enumerate_entity","params":{"s":"rel_chain"}},
    "mass_assignment_testing": {"tool":"request","params":{"s":"extra_fields"}},
    "race_condition_probing": {"tool":"run_workflow_step","params":{"s":"timing"}},
}

def run():
    print("="*60); print("Strategy Selection Test"); print("="*60)
    b = ToolBoundary(); results = {"strategies":{}, "all_pass": True}
    for name, s in STRATEGIES.items():
        tc = ToolCall(tool_name=s["tool"], parameters=s["params"], hypothesis=f"Testing {name}")
        r = b.execute(tc)
        auth = r.get("authorized", False); in_allowed = s["tool"] in ALLOWED_TOOLS
        results["strategies"][name] = {"tool":s["tool"],"in_allowed":in_allowed,"passes_boundary":auth}
        if not auth: results["all_pass"] = False
    total = len(STRATEGIES); passed = sum(1 for s in results["strategies"].values() if s["passes_boundary"])
    print(f"\n{passed}/{total} strategies pass ToolBoundary")
    for n, r in results["strategies"].items():
        print(f"  {'✅' if r['passes_boundary'] else '❌'} {n} (tool={r['tool']})")
    bad = ToolCall(tool_name="invent_new_unrestricted_tool", parameters={}, hypothesis="x")
    br = b.execute(bad)
    results["invented_rejected"] = br.get("authorized") is False
    print(f"\n  {'✅' if results['invented_rejected'] else '❌'} Invented tool rejected")
    with open(os.path.join(REPORTS_DIR, "strategy_selection.json"), "w") as f:
        json.dump(results, f, indent=2, default=str)
    print("\n✅ Saved: reports/goed_v1_8_1/strategy_selection.json")
    return results

if __name__ == "__main__": run()
