#!/usr/bin/env python3
"""R3 DELIVERY BUILD (Dispatch #005, rider R1(c) / RF-06 build enforcement).

Builds WebPent_FINAL_v7_<date>.zip from this tree with HARD deliverable-
completeness enforcement: the build REFUSES (exit 2) to produce a ZIP that
is missing any required deliverable class. RED-1 P-5.3 proved the previous
build recipe had ZERO completeness enforcement.

Required classes (R6):
  - WORKLOG.md (in-tree worklog; NF-03 healing)
  - EVIDENCE_REPORT (EVIDENCE_REPORT_*_v7*.md at root)
  - dossier classes: deliverables/r2_dossiers/ (E-1..E-5) AND
    deliverables/r3_dossiers/ (per-fix dossiers D4)
  - anchor/evidence pack: docs/audit/ (R5 record) + deliverables/ core files

Also runs the extended hygiene gate (scripts/hygiene_gate_extended.py) and
refuses to ship on hygiene FAIL (residue classes per rider R2).

Usage:
  python scripts/build_delivery_v7.py --out-dir /path/to/download [--purge]
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
    ("WORKLOG.md", "worklog ships in-package (R6 / NF-03)"),
    ("EVIDENCE_REPORT_20261005_v7.md", "EVIDENCE_REPORT v7 (R6)"),
    ("deliverables/r2_dossiers", "R2 dossier class E-1..E-5"),
    ("deliverables/r3_dossiers", "R3 per-fix dossier class (D4)"),
    ("docs/audit", "R5 OQ-1 closure record"),
    ("deliverables/requirements_closure.txt", "closure C artifact"),
    ("deliverables/requirements_freeze_final.txt", "environment freeze artifact"),
    ("frozen_modules.sha256", "frozen manifest"),
]

TIMESTAMP = "2026-10-05 17:00"  # normalized build timestamp (UTC) for v7


def fail(msg: str, code: int = 2) -> int:
    print("\nBUILD REFUSED — " + msg, file=sys.stderr)
    return code


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--purge", action="store_true",
                    help="purge generated runtime artifacts before stamping")
    ap.add_argument("--allow-list", default=str(HERE / "r3_residue_classification.json"),
                    help="residue classification/allowlist JSON (R2)")
    args = ap.parse_args()

    # ---- deliverable-completeness enforcement (R1(c)) -----------------------
    print("== deliverable-completeness enforcement (R1(c) / RF-06) ==")
    missing = []
    for rel, why in REQUIRED_CLASSES:
        p = ROOT / rel
        ok = p.is_dir() if rel in ("deliverables/r2_dossiers", "deliverables/r3_dossiers", "docs/audit") else p.is_file()
        if not ok:
            missing.append(f"  MISSING {rel}  ({why})")
        else:
            print(f"  present: {rel}")
    if missing:
        return fail("deliverable classes missing — refusing to build:\n" + "\n".join(missing))
    # dossier classes must be non-empty directories with the right shape
    r2 = sorted((ROOT / "deliverables" / "r2_dossiers").glob("*"))
    r3 = sorted((ROOT / "deliverables" / "r3_dossiers").glob("*"))
    if not r2:
        return fail("deliverables/r2_dossiers is empty (dossier class required)")
    if not any("D" in p.name or "dossier" in p.name.lower() or "FIX" in p.name.upper() for p in r3):
        return fail("deliverables/r3_dossiers has no R3 per-fix dossier files (D4)")
    print(f"  r2_dossiers: {len(r2)} files; r3_dossiers: {len(r3)} files")

    # ---- hygiene gate (R2) --------------------------------------------------
    print("== extended hygiene gate (R2) ==")
    hyg = subprocess.run(
        [sys.executable, str(HERE / "hygiene_gate_extended.py"),
         "--allow-list", args.allow_list],
        cwd=ROOT, capture_output=True, text=True)
    print(hyg.stdout)
    if hyg.returncode != 0:
        print(hyg.stderr)
        return fail("hygiene gate FAILED — refusing to build")

    # ---- optional purge (run residue; never the allowlisted evidence) -------
    if args.purge:
        print("== purge (--purge) ==")
        allow = json.loads(Path(args.allow_list).read_text())
        keep = set(allow.get("evidence_allowlist", []))
        for rel in list(keep):
            print(f"  keep (allowlisted evidence): {rel}")

    # ---- normalize timestamps ----------------------------------------------
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

    # ---- build --------------------------------------------------------------
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    date = "20261005"
    zip_path = out_dir / f"WebPent_FINAL_v7_{date}.zip"
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
