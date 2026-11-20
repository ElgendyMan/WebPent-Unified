"""GOED v1.8.4 — Phase 9: Blind v3 Scorer & Leakage Audit
SEPARATE script — ONLY this one reads ground_truth.json.
Scores execution results against ground truth AFTER the fact.
Audits for leakage: checks that runtime transcripts contain NO ground truth fields.
"""
import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_4")
BENCHMARK_DIR = os.path.join(_ROOT, "benchmarks", "blind_v3")
def _sd(t): return hashlib.sha256(t.encode()).hexdigest()
def score():
    print("=" * 60)
    print("GOED v1.8.4 — Phase 9: Blind v3 Scoring & Leakage Audit")
    print("=" * 60)

    # Load execution results
    exec_path = os.path.join(REPORTS_DIR, "blind_v3_execution.json")
    if not os.path.exists(exec_path):
        print("ERROR: blind_v3_execution.json not found. Run blind_v3_executor.py first.")
        sys.exit(1)

    with open(exec_path) as f:
        exec_result = json.load(f)

    if exec_result.get("status") == "REAL_API_UNAVAILABLE":
        result = {"phase": "9_blind_v3_scoring", "status": "REAL_API_UNAVAILABLE",
                  "note": "Execution phase was REAL_API_UNAVAILABLE; nothing to score."}
        with open(os.path.join(REPORTS_DIR, "blind_v3_score.json"), "w") as f:
            json.dump(result, f, indent=2)
        print("REAL_API_UNAVAILABLE — report written.")
        return

    # NOW load ground truth (separate step, after execution)
    with open(os.path.join(BENCHMARK_DIR, "ground_truth.json")) as f:
        ground_truth = json.load(f)

    per_case = exec_result.get("per_case", [])

    # --- LEAKAGE AUDIT ---
    # Grep all runtime evidence for ground truth sensitive fields
    leakage_findings = []
    sensitive_terms = set()
    for cid, gt in ground_truth.items():
        for field in ["expected_label", "mechanism", "difficulty", "vulnerability_class", "case_family"]:
            val = gt.get(field)
            if val and isinstance(val, str) and len(val) > 3:
                sensitive_terms.add(val.lower())

    # Serialize all runtime output for searching
    runtime_text = json.dumps(per_case).lower()

    for term in sorted(sensitive_terms):
        if term in runtime_text:
            leakage_findings.append({"term": term, "field_source": "ground_truth"})

    leakage_detected = len(leakage_findings) > 0

    # --- SCORING ---
    tp = fp = fn = tn = 0
    by_family = {}  # keyed by actual ground truth family

    for r in per_case:
        cid = r["case_id"]
        gt = ground_truth.get(cid, {})
        actual_vulnerable = gt.get("expected_label") == "vulnerable"
        predicted_vulnerable = r.get("verdict") == "CONFIRMED"
        family = gt.get("case_family", gt.get("family", "unknown"))

        if family not in by_family:
            by_family[family] = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "total": 0}
        by_family[family]["total"] += 1

        if predicted_vulnerable and actual_vulnerable:
            tp += 1; by_family[family]["tp"] += 1
        elif predicted_vulnerable and not actual_vulnerable:
            fp += 1; by_family[family]["fp"] += 1
        elif not predicted_vulnerable and actual_vulnerable:
            fn += 1; by_family[family]["fn"] += 1
        else:
            tn += 1; by_family[family]["tn"] += 1

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 0.0001)
    accuracy = (tp + tn) / max(tp + fp + fn + tn, 1)

    # Family-specific metrics
    for fam, m in by_family.items():
        m["precision"] = round(m["tp"] / max(m["tp"] + m["fp"], 1), 4)
        m["recall"] = round(m["tp"] / max(m["tp"] + m["fn"], 1), 4)

    # Note: plan text says "simple/stateful/compositional" but actual family names
    # in ground truth are "simple/reasoning/compositional". Reconciled here.
    family_name_note = (
        "Plan text says simple/stateful/compositional; actual ground truth families are "
        "simple/reasoning/compositional. This is cosmetic and documented here."
    )

    overall_status = "FAILED" if leakage_detected else "OK"

    result = {
        "phase": "9_blind_v3_scoring",
        "status": overall_status,
        "leakage_detected": leakage_detected,
        "leakage_findings": leakage_findings[:20],  # Cap for readability
        "leakage_total_count": len(leakage_findings),
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        },
        "by_family_ground_truth": by_family,
        "family_name_reconciliation": family_name_note,
        "num_cases_scored": len(per_case),
    }

    with open(os.path.join(REPORTS_DIR, "blind_v3_score.json"), "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nLeakage audit: {'FAILED — sensitive terms found' if leakage_detected else 'PASSED — no leakage'}")
    print("\nOverall metrics:")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1:        {f1:.4f}")
    print(f"  TP={tp} FP={fp} FN={fn} TN={tn}")
    print("\nBy family (ground truth):")
    for fam, m in sorted(by_family.items()):
        print(f"  {fam}: P={m['precision']} R={m['recall']} (n={m['total']})")
if __name__ == "__main__":
    score()
