"""M2-impl REOPENED-window regeneration of docs/direct_io_inventory.json
(2026-10-06, Dispatch #009-A window exit).

Lineage: regen_direct_io_inventory_reviewed_20261005{,_v2}.py (v1/v2
reviewed sets), regen_direct_io_inventory_v4_linedrift.py (the linedrift
precedent), regen_direct_io_inventory_m2_20261006.py (the M2-impl
adjudicated set). This regen covers the REOPENED window (WP-J/WP-I/WP-K).

Reopened-window adjudication (encoded — any other delta refuses):

  * ZERO new sites and ZERO removed sites at the IDENTITY level
    (file, transport, normalized_symbol). The WP-I scoped edits
    (cli/commands.py, workers/pentest_worker.py — exit-code honesty ONLY)
    and the NF-009A-02 fix (graph/builder.py gate reorder) shifted LINE
    NUMBERS only: 14 records moved, all byte-identical modulo the line
    field. This is exactly the v4 linedrift class (reviewable, never
    silent — the drift test forced this deliberate regen).
  * the g02 no-drift test must pass immediately after this regen.
"""
from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webpent.shared.direct_io_inventory import scan_direct_io

ARTIFACT = ROOT / "docs" / "direct_io_inventory.json"
SRC = ROOT / "src"


def _key(r: dict) -> tuple:
    return (r.get("file"), r.get("transport"), r.get("normalized_symbol"))


def main() -> int:
    records = scan_direct_io(SRC)
    data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    old_records = data["records"]
    old_keys = {_key(r) for r in old_records}
    new_keys = {_key(r) for r in records}

    added = {k for k in new_keys if k not in old_keys}
    removed = {k for k in old_keys if k not in new_keys}

    if added or removed:
        print("REFUSING: identity-level delta non-empty (not a linedrift):")
        print("  added:", sorted(added))
        print("  removed:", sorted(removed))
        return 1

    moved = sum(
        1
        for old in old_records
        if any(
            _key(new) == _key(old) and new.get("line") != old.get("line")
            for new in records
        )
    )
    data["records"] = records
    coverage = data.get("coverage") or {}
    for field in ("record_count", "total_records", "count"):
        if field in coverage:
            coverage[field] = len(records)
    if "generated_at" in coverage:
        coverage["generated_at"] = (
            date.today().isoformat() + " (M2-impl reopened-window linedrift regen, Dispatch #009-A)"
        )
    data.setdefault("regen_history", []).append({
        "date": date.today().isoformat(),
        "window": "M2-impl reopened (Dispatch #009-A)",
        "added": [],
        "removed": [],
        "note": (
            f"pure linedrift regen: {moved} records shifted by the WP-I scoped "
            "edits (cli/commands.py, workers/pentest_worker.py — exit-code "
            "honesty only) and the NF-009A-02 builder.py gate reorder; zero "
            "identity-level sites added or removed"
        ),
    })
    ARTIFACT.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"linedrift regen OK: {len(old_records)} -> {len(records)} records "
          f"({moved} lines moved, 0 sites added, 0 removed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
