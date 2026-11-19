"""M2-impl regeneration of docs/direct_io_inventory.json (2026-10-06).

Follows the exact documented lineage of this artifact's regeneration
procedure (v1/v2 scripts; docs/HOSTILE_AUDIT_REMEDIATION_20261003.md §2.4):
records are regenerated from the canonical AST scanner (scan_direct_io);
every non-records artifact section is preserved verbatim; coverage counts
are recomputed. It does NOT hand-edit the artifact.

M2-impl window adjudication (Dispatch #009 — R3-era adjudicated set is
stale for this window; the delta below IS the adjudication, encoded):

  removed set MUST be empty;

  added set MUST be exactly these 3 dynamic_resolution getattr identities,
  all non-transport / not_applicable / non_transport family (precedent: the
  identical pinned getattr pattern from the v1-reviewed set):

    1. src/webpent/graph/builder.py — getattr(orch.research_loop, ... ):
       WP-C rehydration reads the fresh research-loop candidate map size
       for the operator-visible evidence counters (research_loop_active_candidates).
    2. src/webpent/production/modern_spine_integration.py — getattr(target_obj, ... ):
       WP-B declared-state target derivation ladder reads Target.url
       (declared `target` model) with an AttributeError guard.
    3. src/webpent/production/spine_flag_gates.py — getattr(config, ... ):
       WP-F flag snapshot reads the factory-resolved ProductionSpineConfig
       fields (fail-closed `_flag` helper reads with default None).

  any other addition, or any removal, still refuses.
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

M2_ADJUDICATED_ADDITIONS = {
    ("src/webpent/graph/builder.py", "dynamic_resolution", "getattr(orch.research_loop, ... )"),
    ("src/webpent/production/modern_spine_integration.py", "dynamic_resolution", "getattr(target_obj, ... )"),
    ("src/webpent/production/spine_flag_gates.py", "dynamic_resolution", "getattr(config, ... )"),
}


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

    if removed:
        print("REFUSING: removed set non-empty:", sorted(removed))
        return 1
    if added != M2_ADJUDICATED_ADDITIONS:
        # idempotent no-op: the artifact already reflects this window's scan
        # (regen already applied) — verify and exit green.
        if not added and not removed and len(records) == len(old_records) == 658:
            print("already regenerated for this window — no-op (658 records)")
            return 0
        print("REFUSING: added set != M2 adjudicated set.")
        print("  unexpected additions:", sorted(added - M2_ADJUDICATED_ADDITIONS))
        print("  adjudicated but absent:", sorted(M2_ADJUDICATED_ADDITIONS - added))
        return 1

    # The artifact records must equal the CURRENT scan verbatim (including
    # refreshed line numbers in thawed files) — the v1/v2 precedent replaces
    # the records wholesale from scan_direct_io output; non-records sections
    # are preserved verbatim below.
    merged = records

    data["records"] = merged
    coverage = data.get("coverage") or {}
    for field in ("record_count", "total_records", "count"):
        if field in coverage:
            coverage[field] = len(merged)
    if "generated_at" in coverage:
        coverage["generated_at"] = date.today().isoformat() + " (M2-impl window regen, Dispatch #009)"
    data.setdefault("regen_history", []).append({
        "date": date.today().isoformat(),
        "window": "M2-impl (Dispatch #009)",
        "added": sorted(added),
        "removed": [],
        "note": "3 adjudicated dynamic_resolution getattr identities (non-transport); see script docstring",
    })
    ARTIFACT.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"regenerated: {len(old_records)} -> {len(merged)} records "
          f"(+{len(added)} adjudicated, -0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
