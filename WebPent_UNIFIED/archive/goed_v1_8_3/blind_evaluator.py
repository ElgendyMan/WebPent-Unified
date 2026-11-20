"""GOED v1.8.3 — Blind Ground Truth Evaluator (Phase 9)
Ground truth loaded INDEPENDENTLY. Compares runtime evidence against ground truth
ONLY AFTER execution completes. Runtime NEVER receives ground truth fields.
"""

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.join(_HERE, "..")
REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_3")


def evaluate():
    print("=" * 60)
    print("Blind Ground Truth Evaluator")
    print("=" * 60)

    with open(os.path.join(_ROOT, "benchmarks", "differential_v2", "ground_truth.json")) as f:
        gt = json.load(f)
    with open(os.path.join(REPORTS_DIR, "differential_results.json")) as f:
        results = json.load(f)

    mb = results.get("mode_b_llm_on", {})
    ma = results.get("mode_a_llm_off", {})
    delta = results.get("delta", {})

    # Verify independence: runtime results contain NO ground truth fields
    per_case = mb.get("per_case", [])
    leakage = False
    for r in per_case:
        for field in [
            "mechanism",
            "difficulty",
            "case_family",
            "vulnerability_class",
            "expected_label",
        ]:
            if field in r and field != "family":
                leakage = True
                print(f"  ⚠️ LEAKAGE: {field} found in runtime result for {r.get('case_id')}")

    print(f"\nRuntime-ground-truth independence: {'✅ VERIFIED' if not leakage else '⚠️ LEAKAGE DETECTED'}")

    # Classify recovered cases
    recovered = delta.get("recovered_cases", [])
    non_idor = []
    stateful = []
    compositional = []
    for cid in recovered:
        g = gt.get(cid, {})
        vc = g.get("vulnerability_class", "")
        mech = g.get("mechanism", "")
        if vc not in ("direct_auth_mismatch",):
            non_idor.append(cid)
        if any(w in vc for w in ["stateful", "business_logic", "compositional", "relational"]) or any(
            w in mech for w in ["state", "transition", "process", "sequence", "multi_step", "counter", "flag"]
        ):
            stateful.append(cid)
        if any(w in vc for w in ["compositional"]) or any(w in mech for w in ["plus", "combination", "chain"]):
            compositional.append(cid)

    print("\nRecovered cases analysis:")
    print(f"  Total recovered: {len(recovered)}")
    print(f"  Non-IDOR: {len(non_idor)}")
    print(f"  Stateful/business-logic: {len(stateful)}")
    print(f"  Compositional/multi-step: {len(compositional)}")

    # Check minimum capability gain criteria
    criteria = {
        ">=3_recovered": len(recovered) >= 3,
        ">=1_non_idor": len(non_idor) >= 1,
        ">=1_stateful": len(stateful) >= 1,
        ">=1_compositional": len(compositional) >= 1,
        "no_fp_increase": mb.get("metrics", {}).get("fp", 0) <= ma.get("metrics", {}).get("fp", 0),
    }
    print("\nMinimum capability gain criteria:")
    for k, v in criteria.items():
        print(f"  {'✅' if v else '⚠️'} {k}: {v}")

    all_pass = all(criteria.values())
    print(f"\nOverall: {'✅ MINIMUM CAPABILITY GAIN DEMONSTRATED' if all_pass else '⚠️ INSUFFICIENT CAPABILITY GAIN'}")

    result = {
        "runtime_independence_verified": not leakage,
        "recovered_analysis": {
            "total": len(recovered),
            "non_idor": len(non_idor),
            "stateful_business_logic": len(stateful),
            "compositional_multi_step": len(compositional),
            "recovered_cases": recovered,
            "non_idor_cases": non_idor,
            "stateful_cases": stateful,
            "compositional_cases": compositional,
        },
        "minimum_gain_criteria": criteria,
        "all_criteria_pass": all_pass,
        "per_case_ground_truth": gt,
    }

    with open(os.path.join(REPORTS_DIR, "blind_evaluation.json"), "w") as f:
        json.dump(result, f, indent=2, default=str)
    print("\n✅ Saved: reports/goed_v1_8_3/blind_evaluation.json")
    return result


if __name__ == "__main__":
    evaluate()
