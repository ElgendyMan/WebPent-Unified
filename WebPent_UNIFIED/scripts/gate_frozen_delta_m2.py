#!/usr/bin/env python3
"""M2-IMPL MID-WINDOW FROZEN GATE — DELTA MODE (Dispatch #009, C2 / rider R4).

Replaces the standard byte-identity frozen gate for the M2-impl unfreeze
window WITHOUT weakening it. Fail-closed assertions:

  (1) the frozen manifest has NOT been regenerated mid-window (sha256 must
      equal the v7 anchor 33885034… from the sidecar-verified delivery);
  (2) manifest scope unchanged: exactly 695 entries, every path exists;
  (3) every manifest-pinned file NOT on the Dispatch #009 thaw list is
      byte-identical to its pin (standard gate, restricted);
  (4) the git-visible changed set (baseline commit .. worktree) maps
      EXCLUSIVELY to Dispatch #009-authorized items — any src/ path outside
      the thaw list, or any unmapped path, is a WINDOW ABORT.

Usage:
  python scripts/gate_frozen_delta_m2.py --baseline <v7-pristine-commit-sha>

Exit 0 = delta-mode green. Any violation = exit 1 + loud ABORT banner.
Run after EVERY window commit (charter G4). Never disable or bypass.

REOPENED PHASE (Dispatch #009-A, Amendment A1 — P0 escalation intake):
  --phase reopened re-anchors the SAME four assertions to the v8 re-freeze
  state (the last delivered state) for the reopened window:
    [1] manifest sha256 == v8 anchor 0facc0f3… (regeneration only at the
        v9 re-freeze at reopened-window exit);
    [2] manifest scope == 708 entries;
    [3] thaw set = M2 thaw union + AMENDMENT conditional grant:
        cli/commands.py and workers/pentest_worker.py are SCOPED to
        EXIT-CODE-HONESTY changes ONLY (WP-I(c)); any other diff in them
        is an abort, verified by dossier review (WP-H precedent);
    [4] changed set (HEAD=c61519a .. worktree) maps to the Dispatch #009
        authorization map + Amendment #009-A additions.
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "frozen_modules.sha256"

# v7 delivery anchor (sidecar-verified WebPent_FINAL_v7_20261005.zip).
ANCHOR_MANIFEST_SHA256 = (
    "33885034a9da3d945c66ff67c00fcec23d8aaede778414dd74281adda32b2a33"
)

# v8 re-freeze anchor (G5, commit 9f987b6; scripts/m2_anchor_record.json).
# v9 re-freeze anchor (reopened-window exit, Dispatch #009-A) is read from
# scripts/m2a_anchor_record.json — single source of truth for the reopen.
# Used ONLY by --phase reopened (Dispatch #009-A window reopen).
ANCHOR_MANIFEST_SHA256_V8 = (
    "0facc0f39f8880684cc8701a314dc9b362282818e73bf61d5e2fba52d7f4365d"
)
MANIFEST_SCOPE_V8 = 708


def _reopened_anchor() -> str:
    """Read the reopened-window anchor from the record (v8 pre-refreeze,
    v9 post-refreeze — whichever the record currently designates)."""
    import json as _json

    record = _json.loads(
        (ROOT / "scripts" / "m2a_anchor_record.json").read_text(encoding="utf-8")
    )
    v9 = record.get("v9_refreeze_manifest_sha256")
    if v9 and hashlib.sha256(MANIFEST.read_bytes()).hexdigest() == v9:
        return v9
    return record.get("manifest_sha256", ANCHOR_MANIFEST_SHA256_V8)

# Dispatch #009-A WP-I(c) CONDITIONAL THAW GRANT (effective now, expires at
# reopened-window close): cli/commands.py and workers/pentest_worker.py join
# the thaw list FOR EXIT-CODE-HONESTY CHANGES ONLY. All other edits to them
# remain prohibited (verified by dossier review, WP-H scoped-file precedent).
CONDITIONAL_THAW_009A_SCOPED = {
    "src/webpent/cli/commands.py": (
        "WP-I CONDITIONAL (exit-code honesty ONLY — #009-A WP-I(c)); scoped"
    ),
    "src/webpent/workers/pentest_worker.py": (
        "WP-I CONDITIONAL (exit-code honesty ONLY — #009-A WP-I(c)); scoped"
    ),
}

# Amendment #009-A authorization additions (reopened phase, item [4]).
AUTHORIZED_NON_SRC_CLASSES_009A: list[tuple[str, str]] = [
    ("scripts/gate_frozen_delta_m2.py", "R4 reopened-phase gate mechanics"),
    ("scripts/m2a_anchor_record.json", "R3 reopened-window anchor record"),
    ("scripts/fix_gate_order.py", "NF-009A-02 repair script (dossier D3-A)"),
    ("scripts/regen_direct_io_inventory_m2a_20261006.py", "g02 linedrift regen (reopened-window exit, v4 linedrift lineage)"),
    ("scripts/m2a_p7_repro/", "WP-J reproduction harness (outside-tree mirror)"),
    ("credentials_template.json", "WP-K (template-side compliance fix)"),
    ("scope_template.yaml", "WP-K(b) sweep (only if a mismatch is found)"),
    ("docs/templates/", "WP-K(b) sweep (only if a mismatch is found)"),
    ("deliverables/", "D-J + D1-D7 amendments (WP-J/WP-I/WP-K evidence)"),
    ("scripts/build_delivery_v9.py", "D7 (v9 delivery build with enforcement)"),
    ("scripts/m2a_corrected_census_addendum.json", "D2 amendment (if needed)"),
]

# Dispatch #009 §4 thaw list — the ONLY src/ paths this window may change.
# modern_spine.py is SCOPED: _TEST_ESCAPE_ENV containment ONLY (any other
# diff in that file is an abort, verified by dossier review per WP-H).
THAW_SRC_M2 = {
    "src/webpent/state/state.py": "WP-B (declarations per corrected census + design keys)",
    "src/webpent/graph/builder.py": "WP-B/WP-D/WP-E/WP-G (campaign acquisition, skip marker, canonical dispatch, honest test support)",
    "src/webpent/production/modern_spine_integration.py": "WP-A/WP-B/WP-C/WP-F (seam: factory re-derivation helper, audit-chain producer, flag wiring, CampaignState write)",
    "src/webpent/production/advisory_registration.py": "WP-A/WP-D (audit API fix, guard hardening, durable dedupe, canonical enforcement, GAP-R2 helper)",
    "src/webpent/production/campaign_state.py": "WP-C (rehydration integration: registered-candidate record + versioned schema)",
    "src/webpent/production/modern_spine.py": "WP-H SCOPED (_TEST_ESCAPE_ENV containment ONLY)",
}

# Ruling-authorized NON-src surfaces (riders / deliverables / new files).
# src/ paths outside THAW_SRC_M2 abort unconditionally; these classes map.
AUTHORIZED_NON_SRC_CLASSES: list[tuple[str, str]] = [
    ("scripts/test_count_floor.json", "R1 (floor re-pin, documented --update)"),
    ("scripts/m2_standing_gates.py", "R3 (manifest-vs-HEAD standing gate)"),
    ("frozen_modules.sha256", "R3 (force-tracked anchor; regeneration only at G5 re-freeze)"),
    ("scripts/gate_frozen_delta_m2.py", "R4 (this gate)"),
    ("hunt_artifacts/", "R2 residue disposition (R3 classification carried: purge — see r3_residue_classification.json m2_impl_addendum)"),
    ("scripts/m2_anchor_record.json", "R3 (anchor record; written at G5 re-freeze)"),
    ("scripts/build_delivery_v8.py", "D7 (v8 delivery build with enforcement)"),
    ("scripts/m2_corrected_census.json", "D2 (corrected state-key census artifact)"),
    ("src/webpent/production/spine_flag_gates.py", "WP-F (NEW flag-consumer module — thaw item 7 'new files')"),
    ("tests/team1_acceptance/test_m2_graph_chain_gate.py", "WP-G (NEW graph-level chain test — the window exit gate)"),
    ("tests/team1_acceptance/test_m2_transport_contract.py", "WP-B/WP-C/WP-D/WP-F (NEW transport/rehydration/type/flag contract tests)"),
    ("docs/audit/", "R2 (canonical A1-A10) + D3/D4 (dossiers, closure table)"),
    ("deliverables/", "D1-D6 (evidence pack / dossiers / battery)"),
    ("docs/", "C9 (operator-visible doc updates)"),
    ("CAMPAIGN_GUIDE.md", "C9"),
    ("WORKLOG.md", "in-tree worklog"),
    ("EVIDENCE_REPORT_", "D7 (evidence report v8 prefix class)"),
    ("tests/", "C5 (tests grow only; modifications listed + justified)"),
]


def _fail(msg: str) -> None:
    print("\n" + "=" * 72)
    print("WINDOW ABORT — M2 DELTA GATE RED")
    print("=" * 72)
    print(msg)
    sys.exit(1)


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout


def _mapped(relpath: str) -> str | None:
    for prefix, why in AUTHORIZED_NON_SRC_CLASSES:
        if relpath == prefix or relpath.startswith(prefix):
            return why
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", required=True,
                    help="git sha of the pristine baseline commit")
    ap.add_argument("--phase", choices=("initial", "reopened"), default="initial",
                    help="initial = Dispatch #009 v7-anchored window; "
                         "reopened = Dispatch #009-A v8-anchored reopen")
    args = ap.parse_args()
    reopened = args.phase == "reopened"

    anchor = _reopened_anchor() if reopened else ANCHOR_MANIFEST_SHA256
    expected_scope = MANIFEST_SCOPE_V8 if reopened else 695

    # (1) manifest not regenerated mid-window
    manifest_sha = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    print(f"[1] frozen manifest sha256 = {manifest_sha[:16]}… ", end="")
    if manifest_sha != anchor:
        _fail(f"[1] frozen_modules.sha256 does not match the "
              f"{'v8 reopen' if reopened else 'v7'} anchor "
              f"({anchor[:16]}…). Regeneration happens only at "
              "window-exit re-freeze.")
    print(f"OK ({'v8 reopen' if reopened else 'v7'} anchor)")

    # (2) scope unchanged
    entries = [ln for ln in MANIFEST.read_text().splitlines() if ln.strip()]
    print(f"[2] manifest scope = {len(entries)} entries ", end="")
    if len(entries) != expected_scope:
        _fail(f"[2] manifest scope changed: {len(entries)} != {expected_scope}")
    missing = [ln.split("  ", 1)[1] for ln in entries
               if not (ROOT / ln.split("  ", 1)[1].strip()).exists()]
    if missing:
        _fail(f"[2] {len(missing)} pinned paths missing on disk (first 5: {missing[:5]})")
    print("OK, all paths exist")

    # (3) non-thawed pinned files byte-identical
    thawed_paths = set(THAW_SRC_M2)
    if reopened:
        thawed_paths |= set(CONDITIONAL_THAW_009A_SCOPED)
    drifted = []
    for ln in entries:
        sha, _, relpath = ln.partition("  ")
        relpath = relpath.strip()
        if relpath in thawed_paths:
            continue
        p = ROOT / relpath
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != sha:
            drifted.append(relpath)
    print(f"[3] non-thaw frozen files byte-identical ", end="")
    if drifted:
        _fail(f"[3] {len(drifted)} NON-THAWED files drifted from their pin "
              f"(first 5: {drifted[:5]}) — out-of-window modification")
    print(f"OK ({len(entries)} checked, thawed {len(thawed_paths)} skipped)")

    # (4) changed set maps exclusively to authorized items
    changed = [ln for ln in _git("diff", "--name-only", args.baseline).splitlines() if ln.strip()]
    uncommitted = [ln for ln in _git("status", "--porcelain").splitlines() if ln.strip()]
    status_paths = []
    for ln in uncommitted:
        relpath = ln[3:].strip().strip('"')
        status_paths.append(relpath)
    all_changes = sorted(set(changed) | set(status_paths))
    print(f"[4] changed set (committed + uncommitted) = {len(all_changes)} paths")
    problems = []
    auth_map = AUTHORIZED_NON_SRC_CLASSES + (
        AUTHORIZED_NON_SRC_CLASSES_009A if reopened else [])

    def _mapped_reopened(relpath: str) -> str | None:
        for prefix, why in auth_map:
            if relpath == prefix or relpath.startswith(prefix):
                return why
        return None

    for relpath in all_changes:
        if relpath in THAW_SRC_M2:
            continue
        if reopened and relpath in CONDITIONAL_THAW_009A_SCOPED:
            continue
        # Dispatch #009 thaw item 7: NEW files are authorized by nature
        # (flag-consumer module, graph-level chain test, census artifact,
        # window gates) — they are mapped explicitly in the auth map, so
        # check the map BEFORE the src/-outside-thaw abort.
        if _mapped_reopened(relpath) is not None:
            continue
        if relpath.startswith("src/"):
            problems.append(f"SRC PATH OUTSIDE THAW LIST: {relpath}")
            continue
        problems.append(f"UNMAPPED PATH: {relpath}")
    if problems:
        _fail("[4] authorization-map violations:\n  " + "\n  ".join(problems[:20]))
    print("    all mapped OK")
    print("\nM2 DELTA GATE GREEN — window scope holds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
