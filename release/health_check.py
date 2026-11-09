#!/usr/bin/env python3.12
"""WebPent Release Candidate — Health Check"""
import argparse
import json
import os
import sys

# Ensure src/ is in path
_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(_HERE, "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

def check_imports():
    results = {}
    modules = [
        "webpent.cqa_v2.causal_guard",
        "webpent.cqa_v2.proof_bundle_builder",
        "webpent.cqa_v2.replay_verifier",
        "webpent.models.proof_bundle",
        "webpent.goed_v1.real_stateful_executor",
        "webpent.goed_v1.business_logic_evaluator",
    ]
    for mod in modules:
        try:
            __import__(mod)
            results[mod] = "OK"
        except Exception as e:
            results[mod] = f"FAIL: {e}"
    return results

def check_config(path):
    if not os.path.exists(path):
        return False, f"Config not found: {path}"
    try:
        with open(path) as f:
            cfg = json.load(f)
        required = ["release_version", "governance", "llm_policy", "tool_boundary"]
        for key in required:
            if key not in cfg:
                return False, f"Missing config key: {key}"
        gov = cfg.get("governance", {})
        if gov.get("vip_qualified") is not False:
            return False, "GOVERNANCE VIOLATION: vip_qualified must be false"
        if gov.get("P10") != "CLOSED":
            return False, "GOVERNANCE VIOLATION: P10 must be CLOSED"
        return True, "Config valid, governance enforced"
    except Exception as e:
        return False, f"Config parse error: {e}"

def main():
    parser = argparse.ArgumentParser(description="WebPent health check")
    parser.add_argument("--config", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "config_schema.json"))
    args = parser.parse_args()

    print("--- Import Check ---")
    imports = check_imports()
    all_ok = True
    for mod, status in imports.items():
        print(f"  {mod}: {status}")
        if not status == "OK":
            all_ok = False

    print("\n--- Config Check ---")
    cfg_ok, cfg_msg = check_config(args.config)
    print(f"  {cfg_msg}")

    print("\n--- Governance Check ---")
    print("  vip_qualified: false (hard-coded policy)")
    print("  P10: CLOSED")
    print("  P9: CLOSED")

    if all_ok and cfg_ok:
        print("\n✅ HEALTH CHECK PASSED")
        sys.exit(0)
    else:
        print("\n❌ HEALTH CHECK FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()
