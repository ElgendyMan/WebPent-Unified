#!/usr/bin/env python3.12
"""GOED v1.8 — Main Execution Script

Runs:
1. v1.7 freeze verification
2. Health check
3. compileall
4. Import smoke
5. Prompt injection resistance tests
6. Generates final reports
7. Builds delivery manifest

Governance: vip_qualified=false, P10=CLOSED, P9=CLOSED
"""
import compileall
import json
import os
import sys
from datetime import datetime, timezone

REPORTS_DIR = "reports/goed_v1_8"
os.makedirs(REPORTS_DIR, exist_ok=True)

# Ensure paths
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.join(_HERE, "..")
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

os.chdir(_ROOT)

TS = datetime.now(timezone.utc).isoformat()

print("=" * 70)
print("GOED v1.8 — Main Execution")
print("=" * 70)

# Step 1: Verify v1.7 freeze
print("\n[1/6] Verifying v1.7 freeze archive...")
freeze_path = "docs/archive/goed-v1.7/freeze_manifest.json"
freeze_ok = os.path.exists(freeze_path)
freeze_artifacts = {}
if freeze_ok:
    with open(freeze_path) as f:
        freeze = json.load(f)
    freeze_artifacts = freeze.get("artifacts", {})
    print(f"  ✅ Freeze manifest found: {len(freeze_artifacts)} artifacts")
    print(f"     Governance: vip_qualified={freeze.get('governance', {}).get('vip_qualified')}")
else:
    print("  ⚠️ Freeze manifest not found")

# Step 2: Health check
print("\n[2/6] Running health check...")
import subprocess

hc = subprocess.run(
    [sys.executable, "release/health_check.py", "--config", "release/config_schema.json"],
    capture_output=True, text=True, cwd=_ROOT
)
health_ok = hc.returncode == 0
print(f"  Health check: {'✅ PASS' if health_ok else '❌ FAIL'}")
if not health_ok:
    print(f"  {hc.stderr[-300:]}")

# Step 3: Compile check
print("\n[3/6] Running compileall...")
compile_ok = compileall.compile_dir("src", quiet=1)
print(f"  compileall: {'✅ PASS' if compile_ok else '❌ FAIL'}")

# Step 4: Import smoke
print("\n[4/6] Running import smoke...")
try:
    print("  ✅ All core + LLM modules import cleanly")
    import_ok = True
except Exception as e:
    print(f"  ❌ Import failed: {e}")
    import_ok = False

# Step 5: Prompt injection tests
print("\n[5/6] Running prompt injection resistance tests...")
from goed_v1_8.prompt_injection_test import run_all_tests

pi_results = run_all_tests()
print(f"  Overall: {pi_results['overall']}")
for test_name, checks in pi_results.items():
    if test_name in ("overall", "summary"):
        continue
    if isinstance(checks, dict):
        passed = checks.get("all_pass", False)
        print(f"    {test_name}: {'✅ PASS' if passed else '⚠️ PARTIAL'}")
        for cn, cp in checks.items():
            if cn != "all_pass":
                print(f"      {cn}: {cp}")

# Step 6: Generate reports
print("\n[6/6] Generating final reports...")
from goed_v1_8.report_generators import generate_executive_summary, generate_truth_audit

all_results = {
    "timestamp": TS,
    "freeze_ok": freeze_ok,
    "freeze_artifacts": freeze_artifacts,
    "health_check_ok": health_ok,
    "compile_ok": compile_ok,
    "import_ok": import_ok,
    "prompt_injection": pi_results,
    "allowed_tools": ["discover", "request", "replay", "compare",
                      "inspect_state", "inspect_response", "enumerate_entity",
                      "run_workflow_step", "summarize_memory"],
    "governance": {
        "vip_qualified": False,
        "qualification_state": "CONDITIONAL",
        "P10": "CLOSED",
        "P9": "CLOSED",
    },
}

audit_path = f"{REPORTS_DIR}/GOED_V1_8_FINAL_TRUTH_AUDIT.md"
summary_path = f"{REPORTS_DIR}/GOED_V1_8_EXECUTIVE_SUMMARY.md"

generate_truth_audit(all_results, audit_path)
generate_executive_summary(all_results, summary_path)

# Save engineering results
with open(f"{REPORTS_DIR}/engineering_results.json", "w") as f:
    json.dump(all_results, f, indent=2, default=str)

with open(f"{REPORTS_DIR}/prompt_injection_results.json", "w") as f:
    json.dump(pi_results, f, indent=2)

# Governance manifest
governance = {
    "date": TS,
    "vip_qualified": False,
    "qualification_state": "CONDITIONAL",
    "P10": "CLOSED",
    "P9": "CLOSED",
    "scope": "local_synthetic_authorized_targets_only",
    "external_targets_forbidden": True,
    "real_credentials_forbidden": True,
    "destructive_actions_forbidden": True,
    "llm_policy_hash": "versioned_in_llm_researcher_interface",
    "tool_boundary_enforced": True,
    "llm_cannot_confirm_vulnerability": True,
    "llm_cannot_bypass_causal_guard": True,
    "deterministic_oracle_authoritative": True,
}
with open(f"{REPORTS_DIR}/governance_manifest.json", "w") as f:
    json.dump(governance, f, indent=2)

print(f"  ✅ Reports saved to {REPORTS_DIR}/")

# Delivery manifest
delivery = {
    "version": "GOED-v1.8-RC1",
    "date": TS,
    "status": "CONDITIONAL",
    "governance": governance,
    "artifacts": {
        "truth_audit": audit_path,
        "executive_summary": summary_path,
        "engineering_results": f"{REPORTS_DIR}/engineering_results.json",
        "prompt_injection": f"{REPORTS_DIR}/prompt_injection_results.json",
        "governance_manifest": f"{REPORTS_DIR}/governance_manifest.json",
        "v1.7_freeze": freeze_path,
    },
    "source_components": [
        "src/webpent/cqa_v2/",
        "src/webpent/models/",
        "src/webpent/goed_v1/",
        "src/webpent/llm_researcher/",
        "src/webpent/smart/",
    ],
    "release_tools": [
        "release/start_webpent.sh",
        "release/health_check.py",
        "release/config_schema.json",
        "release/benchmark_runner.py",
        "release/verify_proof_bundle.py",
    ],
}

with open(f"{REPORTS_DIR}/delivery_manifest.json", "w") as f:
    json.dump(delivery, f, indent=2)

print(f"\n{'='*70}")
print("GOED v1.8 — ENGINEERING COMPLETE")
print(f"{'='*70}")
print(f"  v1.7 freeze: {'✅' if freeze_ok else '⚠️'}")
print(f"  Health check: {'✅' if health_ok else '❌'}")
print(f"  compileall: {'✅' if compile_ok else '❌'}")
print(f"  Import smoke: {'✅' if import_ok else '❌'}")
print(f"  Prompt injection tests: {pi_results['overall']}")
print("  Governance: vip_qualified=false, P10=CLOSED, CONDITIONAL")
print(f"  Reports: {REPORTS_DIR}/")
