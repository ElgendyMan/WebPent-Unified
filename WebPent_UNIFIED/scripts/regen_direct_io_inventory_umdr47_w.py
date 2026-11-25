#!/usr/bin/env python3
"""UM-DR-47 — the declared direct-I/O inventory regeneration.

Window delta versus the 46 artifact (1242 records): the Phase W wiring
added deterministic file-I/O in the three new production modules
(brain_engine / brain_watchdog / research_memory_store — the W6 memory
store and the W7 snapshot writer) plus advisory dynamic-resolution
sites, and the 46+47 lineage merge carries the tree's live state.

Gates (fail-closed, nothing written unless ALL pass):
  1. no REMOVED unique identities versus the recorded artifact;
  2. raw-transport site set (httpx/raw_http/subprocess/dynamic_import)
     UNCHANGED — the wiring adds no raw transport;
  3. every added identity is printed for the reviewable diff.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
ARTIFACT = REPO_ROOT / "docs" / "direct_io_inventory.json"

from webpent.shared.direct_io_inventory import scan_direct_io  # noqa: E402


def identity(record: dict) -> str:
    return json.dumps({
        "file": record.get("file"),
        "kind": record.get("kind"),
        "normalized_symbol": record.get("normalized_symbol"),
    }, sort_keys=True)


def main() -> int:
    artifact = json.loads(ARTIFACT.read_text())
    recorded = artifact["records"]
    current = scan_direct_io(SRC)

    recorded_ids = {identity(r) for r in recorded}
    current_ids = {identity(r) for r in current}

    removed = recorded_ids - current_ids
    assert not removed, (
        f"REMOVED unique identities (fail-closed): {sorted(removed)}")

    raw_kinds = {"httpx", "raw_http", "subprocess", "dynamic_import"}
    recorded_raw = sorted(
        identity(r) for r in recorded if r.get("transport") in raw_kinds)
    current_raw = sorted(
        identity(r) for r in current if r.get("transport") in raw_kinds)
    assert recorded_raw == current_raw, (
        "raw-transport site set changed — NOT declared by this window")

    added = current_ids - recorded_ids
    print(f"UM-DR-47 declared added identities ({len(added)}):")
    for ident in sorted(added):
        print(f"  + {ident}")

    artifact["records"] = current
    ARTIFACT.write_text(json.dumps(artifact, indent=1, sort_keys=False) + "\n")
    print(f"regenerated: {len(current)} records (was {len(recorded)}); "
          f"removed 0; raw-transport set unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
