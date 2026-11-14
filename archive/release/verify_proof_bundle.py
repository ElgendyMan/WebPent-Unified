#!/usr/bin/env python3.12
"""WebPent Release Candidate — ProofBundle Verification Tool
Cross-environment: verifies a ProofBundle exported from another environment.
No ground truth or benchmark metadata required.
"""

import argparse
import json
import os
import sys

# Ensure src/ is in path
_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(_HERE, "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from webpent.models.proof_bundle import ProofBundle, validate_proof_bundle


def main():
    parser = argparse.ArgumentParser(description="Verify exported ProofBundle")
    parser.add_argument("bundle", help="Path to ProofBundle JSON file")
    parser.add_argument("--require-replay", action="store_true", help="Also check replay artifact presence")
    args = parser.parse_args()

    with open(args.bundle) as f:
        data = json.load(f)

    bundle = ProofBundle.from_dict(data)
    native = bundle.to_native_proof_bundle()

    print(f"Bundle: {bundle.bundle_id}")
    print(f"Target: {bundle.target_identity}")
    print(f"Case: {bundle.case_identity}")
    print(f"Verdict: {bundle.causal_verdict}")
    print(f"Confidence: {bundle.causal_confidence:.4f}")
    print(f"Custody events: {len(bundle.custody_chain)}")

    valid = validate_proof_bundle(native, require_negative_control=False)
    print(f"\nStructural validity: {'✅ PASS' if valid else '❌ FAIL'}")

    if bundle.replay_artifact:
        print("Replay artifact present: ✅")
        print(f"Replay verified: {'✅' if bundle.replay_verified else '⚠️ not marked'}")
    else:
        print("Replay artifact: ⚠️ not present")

    if bundle.deterministic_seal:
        print(f"Deterministic seal: ✅ {bundle.deterministic_seal[:16]}...")

    if bundle.semantic_evidence:
        print(f"Semantic evidence fields: {list(bundle.semantic_evidence.keys())}")

    sys.exit(0 if valid else 1)


if __name__ == "__main__":
    main()
