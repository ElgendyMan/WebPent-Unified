"""GOED v1.8.4 — Phase 18: FULL REGRESSION.
Verifies v1.8.3 freeze (docs/archive/goed-v1.8.3/freeze_manifest.json) unchanged,
CausalGuard/ProofBundle unchanged, governance unchanged.

This is the check that actually matters for v1.8.4 (the v1.8.3 freeze is the one whose
policy string says 'IMMUTABLE - v1.8.4 must NOT modify these artifacts'). The existing
goed_v1_8_3/regression_audit.py only ever checked the older v1.8.1/v1.8.2 manifests and
had its own path-construction bug (fixed separately) — this script checks the freeze
that governs *this* version, with per-file hashes (the v1.8.3 manifest nests them as
{category: {path: {sha256, size_bytes}}}, unlike v1.8.1/v1.8.2's flatter shape).

--- 2026-09-06 UPDATE (per docs/decisions/DECISION-2026-09-06-phase18-freeze-contradiction.md) ---
Mohamed's decision was RE-FREEZE (DOCUMENTED), option (a) of Part A.1: the v1.8.3 manifest
stays historical/immutable (this script now also verifies ITS OWN hash hasn't drifted, so
"immutable" is checked, not assumed). A NEW v1.8.4 manifest
(docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_MANIFEST.json) documents exactly the 4 paths that
were allowed to evolve, each with a one-line reason. A v1.8.3-vs-current mismatch is now only a
PASS-with-note ("superseded_documented") if the current hash matches what the v1.8.4 manifest
recorded; if it drifts even one more byte past that, it is still a hard FAIL. This does not
loosen the check for anything not explicitly re-frozen — see Part 0 Rule 7.
"""
import compileall
import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_4")
os.makedirs(REPORTS_DIR, exist_ok=True)

V183_MANIFEST_EXPECTED_SELF_HASH = "9b2a7ea29e4938bd86fef13e63293a4c19c98b8bc2e2341703b6c2ac4d070d06"
V184_FREEZE_PATH = os.path.join(_ROOT, "docs", "archive", "goed-v1.8.4", "GOED_V1_8_4_FREEZE_MANIFEST.json")


def load_v184_supersessions():
    """Flatten the v1.8.4 freeze manifest's nested {category:{path:{...}}} into {path: info}."""
    if not os.path.exists(V184_FREEZE_PATH):
        return {}
    with open(V184_FREEZE_PATH) as f:
        v184 = json.load(f)
    flat = {}
    for _category, entries in v184.get("artifacts", {}).items():
        for rel_path, info in entries.items():
            flat[rel_path] = info
    return flat


def file_hash(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def audit():
    print("=" * 60)
    print("Phase 18 — Full Regression vs v1.8.3 Freeze")
    print("=" * 60)

    findings = []
    cok = compileall.compile_dir(os.path.join(_ROOT, "src"), quiet=1)
    print(f"  compileall: {'✅ PASS' if cok else '❌ FAIL'}")

    fz_path = os.path.join(_ROOT, "docs", "archive", "goed-v1.8.3", "freeze_manifest.json")
    with open(fz_path) as f:
        fz = json.load(f)

    if fz.get("freeze_policy", "") != "IMMUTABLE - v1.8.4 must NOT modify these artifacts":
        findings.append({"issue": "freeze_policy string changed unexpectedly", "value": fz.get("freeze_policy")})

    v183_manifest_self_hash = file_hash(fz_path)
    v183_manifest_untouched = (v183_manifest_self_hash == V183_MANIFEST_EXPECTED_SELF_HASH)
    print(f"  v1.8.3 manifest file itself untouched: {'✅ PASS' if v183_manifest_untouched else '❌ SOMEONE EDITED THE HISTORICAL FREEZE FILE'}")
    if not v183_manifest_untouched:
        findings.append({
            "issue": "docs/archive/goed-v1.8.3/freeze_manifest.json itself has been modified — "
                     "this is the one file that must NEVER change, regardless of any re-freeze decision",
            "expected_self_sha256": V183_MANIFEST_EXPECTED_SELF_HASH,
            "actual_self_sha256": v183_manifest_self_hash,
        })

    v184_supersessions = load_v184_supersessions()

    per_file = {}
    changed, missing, unchanged = [], [], []
    superseded_documented, unresolved_changed = [], []
    for category, entries in fz["artifacts"].items():
        for rel_path, info in entries.items():
            abs_path = os.path.join(_ROOT, rel_path)
            if not os.path.exists(abs_path):
                missing.append({"category": category, "path": rel_path})
                continue
            current_hash = file_hash(abs_path)
            expected_hash = info.get("sha256")
            rec = {
                "category": category, "path": rel_path,
                "frozen_sha256": expected_hash, "current_sha256": current_hash,
                "frozen_size": info.get("size_bytes"), "current_size": os.path.getsize(abs_path),
            }
            per_file[rel_path] = rec
            if current_hash == expected_hash:
                unchanged.append(rel_path)
            else:
                changed.append(rec)
                v184_info = v184_supersessions.get(rel_path)
                if v184_info and current_hash == v184_info.get("sha256"):
                    superseded_documented.append({**rec, "v184_reason": v184_info.get("reason")})
                else:
                    unresolved_changed.append(rec)

    total = len(unchanged) + len(changed) + len(missing)
    print(f"  Total frozen artifacts checked: {total} (expected 26)")
    print(f"  Unchanged: {len(unchanged)}")
    print(f"  Changed, total: {len(changed)}  (superseded+documented: {len(superseded_documented)}, unresolved: {len(unresolved_changed)})")
    for c in superseded_documented:
        print(f"      [SUPERSEDED, documented] [{c['category']}] {c['path']}")
        print(f"        v1.8.3 frozen: {c['frozen_sha256']}  ({c['frozen_size']} bytes)")
        print(f"        v1.8.4 current: {c['current_sha256']}  ({c['current_size']} bytes)")
        print(f"        reason: {c['v184_reason']}")
        findings.append({
            "issue": "FROZEN ARTIFACT MODIFIED vs v1.8.3 — but re-frozen and documented in "
                     "docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_MANIFEST.json per Mohamed's "
                     "RE-FREEZE (DOCUMENTED) decision. Not a violation.",
            "severity": "documented_not_a_violation",
            **c,
        })
    for c in unresolved_changed:
        print(f"      ❌ [UNRESOLVED VIOLATION] [{c['category']}] {c['path']}")
        print(f"        frozen : {c['frozen_sha256']}  ({c['frozen_size']} bytes)")
        print(f"        current: {c['current_sha256']}  ({c['current_size']} bytes)")
        findings.append({
            "issue": "FROZEN ARTIFACT MODIFIED — violates NON-NEGOTIABLE #4 "
                     "(Historical artifacts IMMUTABLE - v1.8.3 freeze is read-only) "
                     "AND not covered by any documented v1.8.4 re-freeze",
            "severity": "violation",
            **c,
        })
    if missing:
        print(f"  ⚠️ Missing (could not verify): {len(missing)}")
        for m in missing:
            print(f"      [{m['category']}] {m['path']}")
        findings.append({"issue": "frozen artifact missing from tree", "files": missing})

    # CausalGuard / ProofBundle explicit check (Principle #5)
    cg_ok = "src/webpent/cqa_v2/causal_guard.py" not in [c["path"] for c in changed]
    pb_ok = "src/webpent/models/proof_bundle.py" not in [c["path"] for c in changed]
    print(f"  CausalGuard unchanged (Principle #5): {'✅ PASS' if cg_ok else '❌ VIOLATED'}")
    print(f"  ProofBundle unchanged: {'✅ PASS' if pb_ok else '❌ VIOLATED'}")

    # Governance unchanged
    gov_expected = {"vip_qualified": False, "qualification_state": "CONDITIONAL", "P10": "CLOSED", "P9": "CLOSED"}
    gov_actual = fz.get("governance_embedded", {})
    gov_ok = gov_actual == gov_expected
    print(f"  Governance unchanged: {'✅ PASS' if gov_ok else '❌ CHANGED'} {gov_actual}")
    if not gov_ok:
        findings.append({"issue": "governance_embedded mismatch", "expected": gov_expected, "actual": gov_actual})

    overall_pass = cok and not unresolved_changed and not missing and gov_ok and v183_manifest_untouched
    result = {
        "phase": "18_full_regression",
        "compileall_pass": cok,
        "v183_historical_manifest_untouched": v183_manifest_untouched,
        "total_frozen_artifacts": total,
        "unchanged_count": len(unchanged),
        "changed_count": len(changed),
        "superseded_documented_count": len(superseded_documented),
        "unresolved_violation_count": len(unresolved_changed),
        "missing_count": len(missing),
        "changed_files": changed,
        "superseded_documented_files": superseded_documented,
        "unresolved_violation_files": unresolved_changed,
        "missing_files": missing,
        "causalguard_unchanged": cg_ok,
        "proofbundle_unchanged": pb_ok,
        "governance_unchanged": gov_ok,
        "findings": findings,
        "audit_pass": overall_pass,
        "note": (
            "audit_pass reflects ONLY the freeze-integrity gate (v1.8.3 historical freeze intact, "
            "and the 4 superseded files match their documented v1.8.4 re-freeze). It does NOT mean "
            "'missing_count' is ignored -- a non-zero missing_count still fails this gate, see "
            "missing_files for what still needs a decision."
        ) if missing else None,
    }

    print(f"\nOverall (freeze-integrity gate): {'✅ PASS' if overall_pass else '❌ FAIL'}")

    out = os.path.join(REPORTS_DIR, "full_regression_v184.json")
    with open(out, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"\nSaved: {out}")
    return result


if __name__ == "__main__":
    r = audit()
    sys.exit(0 if r["audit_pass"] else 1)
