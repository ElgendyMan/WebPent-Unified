#!/usr/bin/env python3
"""M2-IMPL DELIVERY BUILD (Dispatch #009, D7 — adapted from the v7 builder).

Builds WebPent_FINAL_v8_<date>.zip from this tree with HARD deliverable-
completeness enforcement (same RF-06 lineage as the v7 build): the build
REFUSES (exit 2) to produce a ZIP missing any required deliverable class,
and runs the extended hygiene gate first.

Required classes (Dispatch #009 D1-D7):
  - WORKLOG.md / EVIDENCE_REPORT v8
  - deliverables/m2_dossiers/ (per-WP dossiers D3 + NF-R2 closure table D4)
  - deliverables/m2_manifest_delta_v7_v8.json (D5)
  - scripts/m2_corrected_census.json (D2)
  - docs/audit/ (R2 canonical criteria) + deliverables/ core files
  - frozen_modules.sha256 (v8 manifest, 708 entries)

Usage:
  python scripts/build_delivery_v8.py --out-dir /path/to/download
"""
from __future__ import annotations

import argparse
import hashlib
import json
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
    ("EVIDENCE_REPORT_20261006_v8.md", "EVIDENCE_REPORT v8 (D7)"),
    ("deliverables/m2_dossiers", "per-WP dossiers (D3) + NF-R2 closure table (D4)"),
    ("deliverables/m2_manifest_delta_v7_v8.json", "manifest-delta record v7->v8 (D5)"),
    ("scripts/m2_corrected_census.json", "corrected state-key census artifact (D2)"),
    ("scripts/m2_anchor_record.json", "v8 anchor record (R3 standing gates)"),
    ("deliverables/integration_battery_20261006.txt", "battery evidence (D1)"),
    ("docs/audit/DISPATCH002_ACCEPTANCE_CRITERIA_CANONICAL.md", "R2 canonical A1-A10 (OQ-1 closure)"),
    ("deliverables/requirements_closure.txt", "closure C artifact"),
    ("deliverables/requirements_freeze_final.txt", "environment freeze artifact"),
    ("frozen_modules.sha256", "frozen manifest (v8, 708 entries)"),
]

TIMESTAMP = "2026-10-06 14:00"  # normalized build timestamp (UTC) for v8
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
        ok = p.is_dir() if rel in ("deliverables/m2_dossiers", "docs/audit",
                                   "deliverables/r2_dossiers", "deliverables/r3_dossiers") else p.is_file()
        if not ok:
            missing.append(f"  MISSING {rel}  ({why})")
        else:
            print(f"  present: {rel}")
    if missing:
        return fail("deliverable classes missing — refusing to build:\n" + "\n".join(missing))
    m2 = sorted((ROOT / "deliverables" / "m2_dossiers").glob("*.md"))
    if len(m2) < 9:
        return fail("deliverables/m2_dossiers incomplete (need 8 WP dossiers + closure table)")
    print(f"  m2_dossiers: {len(m2)} files")

    # manifest scope assertion (v8: 708)
    entries = [ln for ln in (ROOT / "frozen_modules.sha256").read_text().splitlines() if ln.strip()]
    if len(entries) != 708:
        return fail(f"frozen manifest scope {len(entries)} != 708 (v8 scope completion)")
    print(f"  frozen manifest: {len(entries)} entries (scope complete)")

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
    zip_path = out_dir / f"WebPent_FINAL_v8_{DATE}.zip"
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
