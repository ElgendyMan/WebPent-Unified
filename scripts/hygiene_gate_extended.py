#!/usr/bin/env python3
"""R3 EXTENDED HYGIENE GATE (Dispatch #005, rider R2 / RED-1 RF-07, P-5.2).

The v6-era gate covered a narrower class set; RED-1 enumerated the gaps
(.env* variants, sqlite WAL/SHM sidecars, stray .jsonl/.log, runtime dirs).
This gate scans the delivery tree for residue classes and FAILS when any
non-allowlisted file is present:

  C1 hunt_artifacts/**           (minus evidence allowlist)
  C2 memory/global/**            (derived runtime state)
  C3 output/**                   (runtime outputs)
  C4 .env*                       (any variant; .env.example template exempt)
  C5 *.sqlite3-wal / *-shm       (live-DB sidecars)
  C6 stray *.jsonl / *.log       (runtime audit/log streams; allowlist may
                                  exempt deliberately authored evidence)

Classification rule (rider R2): runtime-generated run residue = purged;
deliberately authored evidence artifacts referenced by the evidence report
= kept and enumerated in scripts/r3_residue_classification.json
(evidence_allowlist). Exit 0 = clean; exit 1 = residue present.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CLASSES = {
    "C1_hunt_artifacts": "hunt_artifacts",
    "C2_memory_global": "memory/global",
    "C3_output": "output",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--allow-list", default=str(Path(__file__).parent / "r3_residue_classification.json"))
    args = ap.parse_args()

    allow = json.loads(Path(args.allow_list).read_text())
    allowlist: set[str] = set(allow.get("evidence_allowlist", []))

    findings: list[str] = []

    # directory classes
    for cls, rel in CLASSES.items():
        base = ROOT / rel
        if not base.exists():
            continue
        for p in sorted(base.rglob("*")):
            if p.is_file():
                rp = str(p.relative_to(ROOT))
                if rp not in allowlist:
                    findings.append(f"[{cls}] {rp}")

    # .env* variants (.env.example template exempt by design)
    for p in sorted(ROOT.rglob(".env*")):
        if ".git" in p.parts:
            continue
        rp = str(p.relative_to(ROOT))
        if p.name != ".env.example" and rp not in allowlist:
            findings.append(f"[C4_env_variants] {rp}")

    # sqlite WAL/SHM sidecars
    for pat in ("*-wal", "*-shm", "*.sqlite3-wal", "*.sqlite3-shm", "*.db-wal", "*.db-shm"):
        for p in sorted(ROOT.rglob(pat)):
            if ".git" in p.parts:
                continue
            rp = str(p.relative_to(ROOT))
            if rp not in allowlist:
                findings.append(f"[C5_wal_shm] {rp}")

    # stray jsonl/log (allowlist may exempt authored evidence)
    for pat in ("*.jsonl", "*.log"):
        for p in sorted(ROOT.rglob(pat)):
            if ".git" in p.parts or "node_modules" in p.parts:
                continue
            rp = str(p.relative_to(ROOT))
            if rp not in allowlist:
                findings.append(f"[C6_jsonl_log] {rp}")

    if findings:
        print("HYGIENE GATE: FAIL — non-allowlisted residue present:")
        for f in findings:
            print("  " + f)
        print(f"\n{len(findings)} finding(s). Classify per rider R2: purge run "
              "residue, or record as evidence allowlist (with report reference).")
        return 1

    print("HYGIENE GATE: PASS — all residue classes clean "
          "(allowlist: " + (", ".join(sorted(allowlist)) or "empty") + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
