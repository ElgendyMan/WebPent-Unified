#!/usr/bin/env python3
"""UMDR42 direct-I/O inventory regeneration — LINE-DRIFT ONLY.

The D1 logging conversion (commits 22f0f4a + c57f765) inserted
`import logging` + module logger lines into 23 frozen files. The G-02
scan counts those logger call sites as transport records with new line
numbers; no (file, kind, symbol) identity was added or removed
(verified: added=0, removed=0; only `line` differs on 22 records and
`column` on 1).

Gates (harder than a blind regen, mirroring
regen_direct_io_inventory_v4_linedrift.py):

  1. The (file, kind, normalized_symbol) identity SET of the fresh scan
     must be a superset of the recorded artifact with ONLY these two
     documented additions from the UMDR41 window (277b1a5 modified
     principal_provisioning.py without regenerating the artifact — G-02
     shipped red):
       + ('src/webpent/recon/principal_provisioning.py',
          'dynamic_resolution', 'getattr') x2 (lines ~314/316)
     No removals are allowed; anything else REFUSES.
  2. Only `line` / `column` fields may differ on pre-existing records;
     any other field change REFUSES (identities carry their own fields).

Refuses (exit 1) without writing anything unless every gate passes,
then rewrites docs/direct_io_inventory.json with the fresh records and
prints the reviewable diff.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from webpent.shared.direct_io_inventory import scan_direct_io  # noqa: E402

ARTIFACT = REPO / "docs" / "direct_io_inventory.json"
SRC_ROOT = REPO / "src"

UMDR41_RESIDUAL_ADDITIONS = Counter({
    ("src/webpent/recon/principal_provisioning.py",
     "dynamic_resolution", "getattr", "getattr(detection, ... )"): 2,
})


def identity(rec: dict) -> tuple:
    return (rec.get("file"), rec.get("kind"), rec.get("symbol", ""),
            rec.get("normalized_symbol"))


def main() -> int:
    art = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    old_records = art["records"]
    new_records = scan_direct_io(SRC_ROOT)

    old_ids = Counter(identity(r) for r in old_records)
    new_ids = Counter(identity(r) for r in new_records)
    additions = new_ids - old_ids
    removals = old_ids - new_ids
    if removals:
        print("[regen-umdr42] REFUSED: identities were removed:")
        for k, v in removals.items():
            print(f"  -{v}x {k}")
        return 1
    if additions != UMDR41_RESIDUAL_ADDITIONS:
        print("[regen-umdr42] REFUSED: identity additions beyond the "
              "documented UMDR41 residual set:")
        for k, v in (additions - UMDR41_RESIDUAL_ADDITIONS).items():
            print(f"  +{v}x {k}")
        for k, v in (UMDR41_RESIDUAL_ADDITIONS - additions).items():
            print(f"  expected-but-missing +{v}x {k}")
        return 1

    old_buckets: dict[tuple, list[dict]] = {}
    for r in old_records:
        old_buckets.setdefault(identity(r), []).append(r)
    diffs: list[tuple] = []
    for rec in new_records:
        grp = old_buckets.get(identity(rec))
        if not grp:
            continue  # the two documented UMDR41 additions
        old = min(grp, key=lambda g: abs(g.get("line", 0)
                                         - rec.get("line", 0)))
        for field in rec:
            if rec[field] != old.get(field):
                if field not in ("line", "column"):
                    print(f"[regen-umdr42] REFUSED: non-position field "
                          f"'{field}' changed for {identity(rec)}.")
                    return 1
                diffs.append((rec["file"], old.get("line"),
                              rec["line"]))
    art["records"] = new_records
    ARTIFACT.write_text(json.dumps(art, indent=2, sort_keys=False)
                        + "\n", encoding="utf-8")
    print(f"[regen-umdr42] artifact updated: {len(diffs)} line-number "
          f"shift(s) from the D1 logger insertions + 2 documented "
          f"UMDR41-residual getattr records:")
    for f, old_l, new_l in sorted(set(diffs)):
        print(f"  {f}: {old_l} -> {new_l}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
