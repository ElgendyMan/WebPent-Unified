#!/usr/bin/env python3
"""UM-DR-40 — regenerate docs/direct_io_inventory.json (declared).

Follows the declared-regeneration convention
(scripts/regen_direct_io_inventory_umdr31.py precedent):
nothing is written unless every gate passes.

Window UM-DR-40 (2026-11-18) declared additions — the window's NEW
non-frozen production modules carry function-local imports (the
project's standard lazy-import pattern; NO new raw-transport sites):

  src/webpent/production/hypothesis_dedup.py
    1. `from webpent.agents.hypothesis_analyzer.agent import
       hypothesis_node` inside deduplicated_hypothesis_node (the
       RC-5 registered wrapper — deferred import keeps the frozen
       generator module out of the import graph until the node
       actually runs).

  src/webpent/production/identity_activation.py
    2. `from webpent.config.settings import get_settings` inside
       _effective_flags (live flag reads for the activation
       snapshot).
    3. `from webpent.config.settings import get_settings` inside
       _clear_settings_cache (cache clear after env changes).

Gates (fail-closed; nothing written unless ALL pass):
  1. NO removed unique identities;
  2. added identities occur ONLY in the declared new modules;
  3. every non-records artifact section is preserved;
  4. coverage and generated_from recomputed; a regen_history entry
     appended.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webpent.shared.direct_io_inventory import scan_direct_io  # noqa: E402

ARTIFACT = ROOT / "docs" / "direct_io_inventory.json"

DECLARED_NEW_MODULES = {
    "src/webpent/production/hypothesis_dedup.py",
    "src/webpent/production/identity_activation.py",
    # UM-DR-40b: the window's declared-thawed strategist carries the
    # same lazy-import pattern (the decision-ledger wiring inside the
    # ranking loop).
    "src/webpent/agents/strategist/agent.py",
    # UM-DR-40b: the new pure measurement module itself carries one
    # dynamic-resolution site (the dual-shape candidate read).
    "src/webpent/production/decision_ledger.py",
}


def _identity(record: dict) -> tuple[str, str, str, str]:
    """A line-shift-stable identity: (file, kind, normalized symbol,
    column). The window's authorized delta file (builder.py) may
    shift LINES (comments added by the RC-4/RC-5 wiring); the sites
    themselves are identical when their file, kind, normalized
    symbol and column match. A real addition/removal still differs."""
    return (str(record.get("file")),
            str(record.get("kind") or record.get("name") or ""),
            str(record.get("normalized_symbol") or ""),
            str(record.get("column")))


def main() -> int:
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    old_records = artifact["records"]
    fresh_records = scan_direct_io(ROOT / "src")

    from collections import Counter
    old_counts = Counter(_identity(r) for r in old_records)
    fresh_counts = Counter(_identity(r) for r in fresh_records)
    removed = old_counts - fresh_counts
    added = fresh_counts - old_counts
    if removed:
        print(f"ABORT: removed identities: {sorted(removed)[:5]}")
        return 1  # Counter difference: sites truly removed
    bad_adds = {i for i in added
                if i[0] not in DECLARED_NEW_MODULES}
    if bad_adds:
        print(f"ABORT: additions outside the declared modules: "
              f"{sorted(bad_adds)[:5]}")
        return 1
    print(f"declared additions: {len(added)} (all inside the "
          f"window's new modules)")

    artifact["records"] = fresh_records
    if "coverage" in artifact:
        artifact["coverage"] = {
            "files_scanned": len({
                str(r.get("file")) for r in fresh_records}),
            "total_sites": len(fresh_records),
        }
    artifact["generated_from"] = (
        "scripts/regen_direct_io_inventory_umdr40.py (declared "
        "UM-DR-40 window regeneration)")
    history = artifact.setdefault("regen_history", [])
    history.append({
        "window": "UM-DR-40",
        "regenerated_at_utc":
            datetime.now(timezone.utc).isoformat(),
        "added": len(added),
        "removed": 0,
        "declared_modules": sorted(DECLARED_NEW_MODULES),
        "reason": "the window's new production modules "
                  "(hypothesis_dedup, identity_activation) carry "
                  "function-local imports per the lazy-import "
                  "convention",
    })
    ARTIFACT.write_text(
        json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(f"OK: direct_io_inventory.json regenerated — "
          f"{len(fresh_records)} records "
          f"(was {len(old_records)}, +{len(added)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
