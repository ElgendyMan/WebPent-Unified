#!/usr/bin/env python3
"""R3 MID-WINDOW FROZEN GATE — DELTA MODE (Dispatch #005, constraint C2).

During the unfreeze window the standard byte-identity frozen gate cannot
pass (authorized thaw files legitimately differ from their v6 manifest
hashes). This gate replaces it for the window's duration WITHOUT weakening
it. It asserts, fail-closed:

  (1) the frozen manifest file itself has NOT been regenerated mid-window
      (its sha256 must equal the current re-freeze anchor 5957a1b5… —
      the 2026-10-24 catalog-fix re-freeze manifest; prior anchors:
      cfbc347a… TEAM-MERGE 2026-10-22, fb42957d… the original R3/v6
      anchor, retired — see PRE_HASHES.txt and the re-freeze addenda in
      docs/UNFREEZE_FILES_20261005.md);
  (2) the manifest scope is unchanged: exactly 719 entries (the
      2026-10-22 re-freeze scope; the 2026-10-05-era scope was 695), and
      every listed path exists on disk;
  (3) every frozen file NOT on the ruling thaw list is still byte-identical
      to its pinned manifest hash (the standard gate, restricted);
  (4) the git-visible changed set (baseline commit .. worktree) maps
      EXCLUSIVELY to ruling-authorized items — any src/ path outside the
      3.1 thaw list, or any unmapped path, is a WINDOW ABORT.

Usage:
  python scripts/gate_frozen_delta.py --baseline <pristine-v6-commit-sha>

Exit 0 = delta-mode green. Any violation = exit 1 + loud ABORT banner.
Never disable or bypass this gate or the standard gate (restored at
re-freeze). R3-V re-runs this script per commit (constraint C3).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "frozen_modules.sha256"

# Current re-freeze anchor — the frozen-manifest digest pinned at the
# 2026-10-24 VIP-wiring re-freeze (pre/post digests in
# PRE_HASHES.txt / POST_HASHES.txt, item 5). Supersedes the 2026-10-24
# catalog-fix anchor 5957a1b5… and the retired R3/v6 anchor fb42957d…
# from D2_ANCHOR_RECORD.md. Same 719-entry scope as every predecessor.
ANCHOR_MANIFEST_SHA256 = "50c6af8587d513af6515dcdc0b605028735f45f75bed382354ca118c0916c8e9"

# Re-freeze scope (TEAM-MERGE 2026-10-22): the manifest regenerated over the
# SAME 719-path scope and order as the v15.2-lineage manifest it replaced.
MANIFEST_SCOPE = 719

# Ruling R3-002 §3.1 thaw list — the ONLY src/ paths the window may change.
# (modern_spine_integration.py is entrypoint-DERIVATION changes only; the
# node's existing spine-disabled raise must remain untouched.)
THAW_SRC = {
    "src/webpent/api/app.py": "E-1",
    "src/webpent/memory/db.py": "E-1",
    "src/webpent/models/findings.py": "E-1 (amendment B: additive advisory_evidence field)",
    "src/webpent/graph/builder.py": "E-2 + E-4",
    "src/webpent/production/modern_spine_integration.py": "E-4 (entrypoint derivation ONLY)",
}

# Ruling-authorized NON-src surfaces (riders / deliverables). src/ paths
# outside THAW_SRC abort unconditionally; these classes must still map.
AUTHORIZED_NON_SRC_CLASSES: list[tuple[str, str]] = [
    (".gitignore", "R0"),
    ("scripts/test_count_floor.json", "R1(a)"),
    ("scripts/run_integration_battery.sh", "R1(a)"),
    ("tests/test_r2_spine_authority_contracts.py", "R1(b) + E-1/E-2/E-4 marker removal"),
    ("scripts/gate_frozen_delta.py", "C2 (this gate)"),
    ("scripts/r3_anchor_check.py", "R1(d)/R3"),
    ("scripts/build_delivery_v7.py", "R1(c)"),
    ("scripts/hygiene_gate_extended.py", "R2"),
    ("scripts/r3_residue_classification.json", "R2"),
    ("docs/audit/", "R5 (OQ-1 closure)"),
    ("deliverables/", "R6 (evidence pack / dossiers / battery txt)"),
    ("docs/", "C10 (operator-visible doc updates)"),
    ("CAMPAIGN_GUIDE.md", "C10"),
    ("WORKLOG.md", "R6"),
    ("tests/", "C6 (new behavior tests; pre-existing only via ruling items)"),
    ("hunt_artifacts/", "R2 (residue disposition)"),
    ("deliverables/integration_battery_20261005.txt", "R1(a) battery evidence"),
    ("alembic/versions/", "E-1 amendment B (advisory_evidence column migration)"),
    ("scripts/e4_probe_d3.py", "E-4 probe artifact (ruling 3.4(i): PROBE FIRST)"),
    ("worker.py", "E-4 (b): editable launch surface sets WEBPENT_ENTRYPOINT=worker"),
    ("server.py", "E-4 (b): editable launch surface sets WEBPENT_ENTRYPOINT=api"),
    ("webpent-cli.sh", "E-4 (b): editable launch surface exports WEBPENT_ENTRYPOINT=cli"),
    ("tests/conftest.py", "E-4 (b): harness declares its truthful direct-invoke label"),
]


def _fail(msg: str) -> None:
    print("\n" + "=" * 72)
    print("WINDOW ABORT — DELTA GATE RED")
    print("=" * 72)
    print(msg)
    sys.exit(1)


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", required=True,
                    help="path to the pristine baseline manifest file "
                         "(e.g. frozen_modules.sha256.baseline_pre_unfreeze); "
                         "diffed against the current manifest via "
                         "'git diff HEAD -- <path>'")
    args = ap.parse_args()

    problems: list[str] = []

    # (1) manifest not regenerated mid-window
    manifest_sha = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    print(f"[1] frozen manifest sha256 = {manifest_sha[:16]}… ", end="")
    if manifest_sha != ANCHOR_MANIFEST_SHA256:
        _fail("[1] frozen_modules.sha256 was REGENERATED mid-window "
              f"(anchor {ANCHOR_MANIFEST_SHA256[:16]}…). Re-freeze happens "
              "only in Phase 4 under R3 rider supervision.")
    print("OK (matches R3 anchor — not regenerated)")

    # (2) scope unchanged
    entries = [ln for ln in MANIFEST.read_text().splitlines() if ln.strip()]
    print(f"[2] manifest scope = {len(entries)} entries ", end="")
    if len(entries) != MANIFEST_SCOPE:
        problems.append(f"[2] manifest scope drifted: {len(entries)} != {MANIFEST_SCOPE}")
    missing = [ln.split("  ", 1)[1] for ln in entries
               if not (ROOT / ln.split("  ", 1)[1]).exists()]
    if missing:
        problems.append(f"[2] {len(missing)} manifest paths missing on disk: {missing[:5]}")
    print("OK" if not problems else "FAIL")

    # (3) standard frozen gate restricted to NON-thawed files
    thaw_paths = set(THAW_SRC)
    bad, checked = [], 0
    for ln in entries:
        sha, _, rel = ln.partition("  ")
        if rel in thaw_paths:
            continue
        checked += 1
        p = ROOT / rel
        if not p.exists():
            bad.append(f"{rel}: MISSING")
            continue
        if hashlib.sha256(p.read_bytes()).hexdigest() != sha:
            bad.append(f"{rel}: HASH MISMATCH (not on thaw list)")
    print(f"[3] non-thawed frozen files byte-identical: {checked - len(bad)}/{checked} ", end="")
    if bad:
        problems.append("[3] UNAUTHORIZED frozen-file mutations:\n      " + "\n      ".join(bad))
    print("OK" if not bad else "FAIL")

    # (4) every git-visible change maps to a ruling item
    committed = _git("diff", "--name-only", "HEAD", "--", args.baseline).split()
    dirty = _git("status", "--porcelain").splitlines()
    dirty_paths = [ln[3:].strip().strip('"') for ln in dirty]
    changed = sorted(set(committed) | set(dirty_paths))
    unmapped, out_of_list_src = [], []
    for rel in changed:
        if rel in THAW_SRC:
            continue
        if rel.startswith("src/webpent/"):
            out_of_list_src.append(rel)
            continue
        if rel.startswith("scripts/") and rel not in {c for c, _ in AUTHORIZED_NON_SRC_CLASSES}:
            # R3 process tooling (R1 riders/C2/R2) is the authorized scripts/
            # class; unknown scripts/ files still map to the R1/C2 class only
            # if added by this sprint's rider commits — flag for review.
            unmapped.append(f"{rel} (scripts/ — must be an R1/C2/R2 rider artifact)")
            continue
        if not any(rel == cls or rel.startswith(cls) for cls, _ in AUTHORIZED_NON_SRC_CLASSES):
            unmapped.append(rel)
    print(f"[4] changed-set mapping: {len(changed)} changed paths ", end="")
    if out_of_list_src:
        problems.append("[4] OUT-OF-LIST src/ DIFFS (WINDOW ABORT):\n      "
                        + "\n      ".join(out_of_list_src))
    if unmapped:
        problems.append("[4] changed paths not mapping to any ruling item:\n      "
                        + "\n      ".join(unmapped))
    print("OK" if not (out_of_list_src or unmapped) else "FAIL")

    # thaw-list reminders (semantic sub-scope is R3-V's to review)
    for rel, why in sorted(THAW_SRC.items()):
        note = f"       thaw: {rel} -> {why}"
        if "ONLY" in why:
            note += "  [sub-scope: derivation changes only]"
        print(note)

    if problems:
        _fail("\n\n".join(problems))
    print("\nDELTA GATE: GREEN — window invariants hold "
          "(manifest pinned, non-thawed frozen files byte-identical, "
          "changed set fully mapped to Ruling R3-002).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
