#!/usr/bin/env python3
"""M2-IMPL REOPENED-WINDOW DELIVERY BUILD (Dispatch #009-A, D7 amendment —
adapted from the v8 builder).

Builds WebPent_FINAL_v9_<date>.zip from this tree with HARD deliverable-
completeness enforcement (RF-06 lineage): the build REFUSES (exit 2) to
produce a ZIP missing any required deliverable class, and runs the
extended hygiene gate first.

Required additions for the reopened window (WP-J/WP-I/WP-K):
  - EVIDENCE_REPORT v9 (D7 amendment)
  - deliverables/DJ_P7_ROOT_CAUSE_20261006.md (D-J)
  - deliverables/m2a_dossiers/ (D3-A scoped-diff review)
  - deliverables/m2a_evidence_index.md
  - scripts/m2a_p7_repro/ (reproduction harness)
  - scripts/m2a_anchor_record.json (v9 anchor record)
  - tests/team1_acceptance/test_m2a_exit_code_honesty.py (20 tests)
  - tests/team1_acceptance/test_template_contracts.py (10 tests)
  - frozen_modules.sha256 (v9 manifest, 708 entries)

Usage:
  python scripts/build_delivery_v9.py --out-dir /path/to/download
"""
from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent

REQUIRED_CLASSES: list[tuple[str, str]] = [
    ("WORKLOG.md", "worklog ships in-package"),
    ("EVIDENCE_REPORT_20261006_v9.md", "EVIDENCE_REPORT v9 (D7 amendment)"),
    ("deliverables/DJ_P7_ROOT_CAUSE_20261006.md", "D-J root-cause report (WP-J)"),
    ("deliverables/m2a_dossiers", "reopened-window dossiers (D3-A)"),
    ("deliverables/m2a_evidence_index.md", "m2a evidence index"),
    ("deliverables/m2a_evidence/p7", "P7 reproduction evidence (WP-J)"),
    ("scripts/m2a_p7_repro", "P7 reproduction harness"),
    ("scripts/m2a_anchor_record.json", "reopened-window anchor record (v9)"),
    ("scripts/m2_anchor_record.json", "v8 anchor record (carried)"),
    ("deliverables/integration_battery_20261006_v9.txt", "battery evidence v9 (D1)"),
    ("deliverables/full_suite_v9_20261006.txt", "full-suite evidence v9"),
    ("deliverables/m2_dossiers", "initial-window WP dossiers (carried)"),
    ("scripts/m2_corrected_census.json", "corrected state-key census artifact (carried, D2)"),
    ("docs/audit/DISPATCH002_ACCEPTANCE_CRITERIA_CANONICAL.md", "R2 canonical A1-A10 (carried)"),
    ("frozen_modules.sha256", "frozen manifest (v9, 708 entries)"),
    ("tests/team1_acceptance/test_m2a_exit_code_honesty.py", "WP-I contract tests (A12)"),
    ("tests/team1_acceptance/test_template_contracts.py", "WP-K contract suite (A13)"),
    ("docs/credentials_template_README.md", "WP-K template guidance"),
]

TIMESTAMP = "2026-10-06 17:30"  # normalized build timestamp (UTC) for v9
DATE = "20261006"


def fail(msg: str, code: int = 2) -> int:
    print("\nBUILD REFUSED — " + msg, file=sys.stderr)
    return code


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--allow-list", default=str(HERE / "r3_residue_classification.json"),
                    help="residue classification/allowlist JSON (R2)")
    args = ap.parse_args()

    print("== deliverable-completeness enforcement (RF-06 lineage) ==")
    missing = []
    for rel, why in REQUIRED_CLASSES:
        p = ROOT / rel
        ok = p.is_dir() if rel.endswith(("m2a_dossiers", "m2_dossiers", "m2a_evidence/p7",
                                         "m2a_p7_repro")) else p.is_file()
        if not ok:
            missing.append(f"  MISSING {rel}  ({why})")
        else:
            print(f"  present: {rel}")
    if missing:
        return fail("deliverable classes missing — refusing to build:\n" + "\n".join(missing))

    # manifest scope assertion (v9: 708)
    entries = [ln for ln in (ROOT / "frozen_modules.sha256").read_text().splitlines() if ln.strip()]
    if len(entries) != 708:
        return fail(f"frozen manifest scope {len(entries)} != 708")
    print(f"  frozen manifest: {len(entries)} entries (v9 re-freeze)")

    # hygiene gate
    print("== extended hygiene gate (R2) ==")
    hyg = subprocess.run(
        [sys.executable, str(HERE / "hygiene_gate_extended.py"),
         "--allow-list", args.allow_list],
        cwd=ROOT, capture_output=True, text=True)
    print(hyg.stdout)
    if hyg.returncode != 0:
        print(hyg.stderr)
        return fail("hygiene gate FAILED — refusing to build")

    # normalize timestamps
    print("== timestamp normalization ==")
    stamp = datetime.strptime(TIMESTAMP, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc).timestamp()
    n = 0
    for p in ROOT.rglob("*"):
        if ".git" in p.parts:
            continue
        if p.is_file():
            os.utime(p, (stamp, stamp))
            n += 1
    print(f"  normalized {n} files to {TIMESTAMP} UTC")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"WebPent_FINAL_v9_{DATE}.zip"
    print(f"== building {zip_path.name} ==")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(ROOT.rglob("*")):
            if ".git" in p.parts or p.is_dir():
                continue
            z.write(p, p.relative_to(ROOT))
    sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    side = Path(str(zip_path) + ".sha256")
    side.write_text(f"{sha}  {zip_path}\n")
    print(f"== built: {zip_path}")
    print(f"== sha256: {sha}")
    print(f"== sidecar: {side.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
