"""GOED v1.8.3 — Tool Intelligence Measurement (Phase 14)
For every LLM-selected experiment record: hypothesis, predicted information gain,
tool, parameters, result, next decision.
Measure: redundant probes, repeated identical probes, dead-end loops,
unnecessary experiments, experiments leading to new evidence,
experiments leading to causal confirmation.
"""

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.join(_HERE, "..")
REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_3")


def analyze():
    print("=" * 60)
    print("Tool Intelligence Analysis")
    print("=" * 60)

    with open(os.path.join(REPORTS_DIR, "differential_results.json")) as f:
        results = json.load(f)

    mb = results.get("mode_b_llm_on", {})
    per_case = mb.get("per_case", [])

    total_experiments = 0
    new_evidence = 0
    causal_confirmations = 0
    redundant = 0
    dead_ends = 0
    experiment_records = []

    for case in per_case:
        traj = case.get("trajectory") or []
        for step in traj:
            if "experiment" not in step:
                continue
            total_experiments += 1
            rec = {
                "case_id": case.get("case_id"),
                "family": case.get("family"),
                "hypothesis": step.get("top_hypothesis", "")[:100],
                "hypothesis_confidence": step.get("hypothesis_confidence"),
                "tool": step.get("experiment", {}).get("tool"),
                "purpose": step.get("experiment", {}).get("purpose"),
                "method": step.get("experiment", {}).get("method"),
                "http_executed": step.get("http_executed"),
                "http_status": step.get("http_status"),
                "new_observation_added": step.get("new_observation_added", False),
                "re_evaluation_verdict": step.get("re_evaluation", {}).get("verdict"),
            }
            experiment_records.append(rec)

            if step.get("new_observation_added"):
                new_evidence += 1
            if step.get("re_evaluation", {}).get("verdict") == "CONFIRMED":
                causal_confirmations += 1
            if step.get("http_executed") and not step.get("new_observation_added"):
                redundant += 1
            if step.get("http_status") and step.get("http_status") >= 400:
                dead_ends += 1

    useful_rate = new_evidence / max(total_experiments, 1)
    confirmation_yield = causal_confirmations / max(total_experiments, 1)
    evidence_yield = new_evidence / max(total_experiments, 1)

    print(f"  Total LLM-selected experiments: {total_experiments}")
    print(f"  Experiments producing new evidence: {new_evidence} ({useful_rate:.1%})")
    print(f"  Experiments leading to causal confirmation: {causal_confirmations} ({confirmation_yield:.1%})")
    print(f"  Redundant/unproductive experiments: {redundant}")
    print(f"  Dead-end probes (HTTP error): {dead_ends}")
    print(f"\n  useful_experiment_rate: {useful_rate:.4f}")
    print(f"  evidence_yield: {evidence_yield:.4f}")
    print(f"  confirmation_yield: {confirmation_yield:.4f}")

    result = {
        "total_experiments": total_experiments,
        "new_evidence_experiments": new_evidence,
        "causal_confirmation_experiments": causal_confirmations,
        "redundant_experiments": redundant,
        "dead_end_probes": dead_ends,
        "useful_experiment_rate": round(useful_rate, 4),
        "evidence_yield": round(evidence_yield, 4),
        "confirmation_yield": round(confirmation_yield, 4),
        "experiment_records_sample": experiment_records[:20],
    }

    with open(os.path.join(REPORTS_DIR, "tool_intelligence.json"), "w") as f:
        json.dump(result, f, indent=2, default=str)
    print("\n✅ Saved: reports/goed_v1_8_3/tool_intelligence.json")
    return result


if __name__ == "__main__":
    analyze()
