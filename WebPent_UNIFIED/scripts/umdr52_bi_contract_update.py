#!/usr/bin/env python3
"""UM-DR-52 — the BUILD_INFO version-identity contract update (0.50.0).

The honesty gate (scripts/check_build_info_honesty.py) binds BUILD_INFO
to the LATEST window's durable release evidence. This script performs
the window's identity update, the umdr51 pattern exactly:

  1. version_identity_contract.package_version: 0.49.0 -> 0.50.0
  2. previous_release <- the old current_release (the 0.49.0 UM-DR-51
     release entry, verbatim);
  3. current_release <- the 0.50.0 UM-DR-52 entry, source_revision =
     the battery commit 3e3ff17 (tree_clean=TRUE);
  4. provenance.manifest_digest <- the CURRENT sha256 of the re-bound
     frozen_modules.sha256.

Run AFTER scripts/umdr52_refreeze_manifest.py (the manifest digest must
reflect the final manifest). Idempotent.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BI = ROOT / "BUILD_INFO.json"
MANIFEST = ROOT / "frozen_modules.sha256"

BATTERY_COMMIT = "3e3ff17452cde5f39a1de4d6d67417113fae679f"
OLD_VERSION = "0.49.0"
NEW_VERSION = "0.50.0"

bi = json.loads(BI.read_text())
contract = bi["version_identity_contract"]

# 1 — the contract version
assert contract["package_version"] in (OLD_VERSION, NEW_VERSION), \
    contract["package_version"]
contract["package_version"] = NEW_VERSION

# 2 + 3 — previous_release <- old current_release; new current_release
# (idempotent: a rerun keeps the already-updated contract intact)
old_current = contract["current_release"]
if old_current["package_version"] == OLD_VERSION:
    contract["previous_release"] = old_current
if contract["current_release"]["package_version"] != NEW_VERSION:
    contract["current_release"] = {
    "package_version": NEW_VERSION,
    "window": (
        "0.50.0 release line: UM-DR-52 the behavioral & adaptive window "
        "— the brain changes decisions MEASURED (ORDER changed on "
        "Juice Shop 3 deterministic runs/arm + TWO decision flips on "
        "the approved fixture via the priority decision map; pool-only "
        "never claimed), the adaptive experimentation engine (the "
        "eight-state lifecycle VIEW after the actual reducer, the "
        "fail-closed experiment ledger with the repeat-guard QC, "
        "identity-safe parallelism, measured per-family economics; "
        "W1->W2 integration VERIFIED), six real lessons extracted "
        "(the zero-lessons verdict dies), the field honesty record "
        "(the auth wall BLOCKED by the owner's declared GET-only "
        "constraint, DVWA BLOCKED on the recorded environment attempt, "
        "Juice Shop 0 confirmed in standard mode — recorded, never "
        "claimed). The honest verdict: gaps declared by number and "
        "item (deliverables/umdr52/FINAL_ACCEPTANCE_MATRIX.json)"),
    "source_revision": BATTERY_COMMIT,
    "python_floor": ">=3.11 (pyproject.toml)",
    "python_tested": "3.12.16",
    "provenance_note": (
        "UM-DR-52 re-freeze: the battery on a clean tree at 3e3ff17 "
        "(9990/9990/9969/5 — four are the re-bind gates satisfied by "
        "the 90d1890 re-bind commit, one is a recorded load flake "
        "5/5-green standalone); current release identity is this "
        "re-freeze revision line"),
}

# 4 — the manifest digest (reflects the re-bound manifest)
digest = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
prov = bi["provenance"]
prov["manifest_digest"] = digest

# 5 — provenance.test_accounting must EQUAL the durable release
# evidence's accounting verbatim (the honesty gate compares them for
# the same evidence_revision). Copied from the record, never typed.
EV = (ROOT.parent / "deliverables" / "umdr52_closure"
      / "FULL_SUITE_EVIDENCE.json")
ev = json.loads(EV.read_text())
assert str(ev.get("source_commit", "")).startswith(BATTERY_COMMIT[:12]), \
    ev.get("source_commit")
prov["test_accounting"] = dict(ev["accounting"])

BI.write_text(json.dumps(bi, indent=2) + "\n")
print("BUILD_INFO contract updated: 0.49.0 -> 0.50.0; battery="
      + BATTERY_COMMIT[:12] + "; manifest_digest=" + digest[:12]
      + "; test_accounting copied from the durable evidence ("
      + str(ev["accounting"]["collected"]) + " collected / "
      + str(ev["accounting"]["executed"]) + " executed)")
