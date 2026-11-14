"""GOED v1.8.4 — Phase 13: Generative vs Pattern-Recognition Split
Uses Phase 12's confirmed genuine recoveries as candidate set.
Classifies each recovery as:
  - GENERATIVE: LLM constructed a novel experiment not in the deterministic strategy set
  - PATTERN_RECOGNITION: LLM recognized a known pattern and applied existing strategy
"""

import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_4")
BENCHMARK_DIR = os.path.join(_ROOT, "benchmarks", "blind_v3")


def _sd(t):
    return hashlib.sha256(t.encode()).hexdigest()


def classify_split():
    print("=" * 60)
    print("GOED v1.8.4 — Phase 13: Generative vs Pattern-Recognition Split")
    print("=" * 60)

    rec_path = os.path.join(REPORTS_DIR, "recovery_rule_v184.json")
    if not os.path.exists(rec_path):
        print("ERROR: recovery_rule_v184.json not found. Run Phase 12 first.")
        sys.exit(1)

    with open(rec_path) as f:
        rec = json.load(f)

    if rec.get("status") == "REAL_API_UNAVAILABLE":
        result = {
            "phase": "13_generative_split",
            "status": "REAL_API_UNAVAILABLE",
            "note": "Phase 12 was REAL_API_UNAVAILABLE.",
        }
        with open(os.path.join(REPORTS_DIR, "generative_split_v184.json"), "w") as f:
            json.dump(result, f, indent=2)
        print("REAL_API_UNAVAILABLE — report written.")
        return

    with open(os.path.join(BENCHMARK_DIR, "ground_truth.json")) as f:
        ground_truth = json.load(f)

    genuine_case_ids = rec.get("genuine_case_ids", [])

    # Known deterministic strategy patterns (from v1.6 deterministic core)
    # These are the patterns the deterministic engine already knows
    known_patterns = {
        "direct_auth_mismatch",
        "idor_basic",
        "missing_auth_check",
        "weak_access_control",
        "horizontal_privilege",
    }

    generative_cases = []
    pattern_recognition_cases = []

    for cid in genuine_case_ids:
        gt = ground_truth.get(cid, {})
        vc = gt.get("vulnerability_class", "")
        mech = gt.get("mechanism", "")

        # Heuristic: if the vulnerability class is in known_patterns,
        # the LLM likely just recognized it. Otherwise, it may be generative.
        # A stronger test would compare the actual experiment chosen, but we
        # only have digests in the current report structure.
        is_known_pattern = any(p in vc.lower() or p in mech.lower() for p in known_patterns)

        classification = "PATTERN_RECOGNITION" if is_known_pattern else "GENERATIVE"

        entry = {
            "case_id": cid,
            "vulnerability_class": vc,
            "mechanism_digest": _sd(mech),
            "classification": classification,
            "heuristic_used": "known_pattern_match",
        }

        if classification == "GENERATIVE":
            generative_cases.append(entry)
        else:
            pattern_recognition_cases.append(entry)

    result = {
        "phase": "13_generative_split",
        "status": "OK",
        "candidate_set_size": len(genuine_case_ids),
        "generative_count": len(generative_cases),
        "pattern_recognition_count": len(pattern_recognition_cases),
        "generative_cases": generative_cases,
        "pattern_recognition_cases": pattern_recognition_cases,
        "note": "Classification uses heuristic based on known deterministic patterns. "
        "A more rigorous classification would compare LLM-selected experiment "
        "parameters against the deterministic strategy space directly.",
    }

    with open(os.path.join(REPORTS_DIR, "generative_split_v184.json"), "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nCandidate set: {len(genuine_case_ids)}")
    print(f"Generative: {len(generative_cases)}")
    print(f"Pattern recognition: {len(pattern_recognition_cases)}")
    for g in generative_cases:
        print(f"  GEN  {g['case_id']}")
    for p in pattern_recognition_cases:
        print(f"  PAT  {p['case_id']}")


if __name__ == "__main__":
    classify_split()
