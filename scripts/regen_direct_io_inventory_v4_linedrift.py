#!/usr/bin/env python3
"""v4 direct-I/O inventory regeneration — LINE-DRIFT ONLY (TEAM-RED v4).

Background: the v3 FINAL PREP SPRINT adjudicated the poc_recorder.py
transport identities via ``regen_direct_io_inventory_reviewed_20261005_v2.py``.
That script's gates are written for a ONE-SHOT adjudication (it requires the
adjudicated identities to appear in the ADDED set), so it cannot re-run for
a pure line-number shift after those identities are already recorded.

The v4 remediation (R-05 route handler rewrite) shifted two recorded line
numbers inside ``poc_recorder.py`` WITHOUT adding or removing any identity.
This script re-generates the artifact under HARDER gates than v3:

  1. The (file, kind, normalized_symbol) identity SEQUENCE of the fresh scan
     must be EXACTLY equal to the recorded artifact — no additions, no
     removals, no reorder.  Anything else REFUSES with human-review
     instructions (use the v2 adjudication script for genuine identity
     changes).
  2. Only ``line`` / ``column`` fields may differ; any other field change
     (symbol, transport family, classification, approval status) REFUSES.

Refuses (exit 1) without writing anything unless every gate passes, then
rewrites ``docs/direct_io_inventory.json`` with the fresh records and prints
the reviewable line-number diff.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from webpent.shared.direct_io_inventory import scan_direct_io  # noqa: E402

ARTIFACT = REPO_ROOT / "docs" / "direct_io_inventory.json"
SRC_ROOT = REPO_ROOT / "src"


def _identity(r: dict) -> tuple[str, str, str]:
    return (r["file"], r["kind"], r["normalized_symbol"])


def main() -> int:
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    old_records = artifact["records"]
    new_records = scan_direct_io(SRC_ROOT)

    old_ids = [_identity(r) for r in old_records]
    new_ids = [_identity(r) for r in new_records]

    # Gate 1: identity sequence EXACTLY preserved.
    if old_ids != new_ids:
        removed = sorted(set(old_ids) - set(new_ids))
        added = sorted(set(new_ids) - set(old_ids))
        print("REFUSING: identity set changed — this requires the v2")
        print("  adjudication script (human review), not a line-drift regen.")
        if removed:
            print("  removed identities:", removed[:10])
        if added:
            print("  added identities  :", added[:10])
        if removed == [] and added == []:
            print("  (order changed without set change — refusing as well)")
        return 1

    # Gate 2: only line/column may differ on each paired record.
    bad = []
    for o, n in zip(old_records, new_records, strict=True):
        strip_o = {k: v for k, v in o.items() if k not in ("line", "column")}
        strip_n = {k: v for k, v in n.items() if k not in ("line", "column")}
        if strip_o != strip_n:
            bad.append((_identity(o), {k: strip_o.get(k) for k in strip_n if strip_o.get(k) != strip_n.get(k)}))
    if bad:
        print("REFUSING: non-positional field changes present (human review):")
        for ident, fields in bad[:10]:
            print("  ", ident, fields)
        return 1

    moved = [
        (o["file"], o["line"], n["line"])
        for o, n in zip(old_records, new_records, strict=True)
        if (o["line"], o["column"]) != (n["line"], n["column"])
    ]
    artifact["records"] = new_records
    ARTIFACT.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(f"OK: regenerated {ARTIFACT.relative_to(REPO_ROOT)} "
          f"({len(new_records)} records, identities unchanged)")
    print("line-number moves (reviewable):")
    for file, old_line, new_line in moved:
        print(f"  {file}: {old_line} -> {new_line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
