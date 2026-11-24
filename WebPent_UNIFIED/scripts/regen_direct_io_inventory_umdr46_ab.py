#!/usr/bin/env python3
"""UM-DR-46 Phase A+B — the declared direct-I/O inventory regeneration.

Window: Phase A (Security Knowledge Graph) + Phase B (Researcher
Brain). Declared delta versus the pre-window artifact (1226 records):

  ADDED unique identities (2): appmodel/skg.py AND
    production/researcher_brain.py —
    getattr(state, ...) dynamic_resolution: the two windows' `_get`
    channel accessors (the same read-only pattern builder.py's own
    `_get` has used since UM-DR-17; no transport, no I/O — the sites
    are dynamic-RESOLUTION observations only).

  LINE-SHIFTED identities: builder.py / appmodel_nodes.py /
    state.py records whose (file, kind, normalized_symbol) identity is
    unchanged but whose line numbers moved with the window's edits.
    Identity comparison below ignores line/column (per the r5 /
    umdr36_2_37 regen convention), so shifts are not deltas.

  REMOVED unique identities: NONE.
  New raw-transport (httpx/__import__/importlib) sites: NONE — the
  unapproved-site pin set is byte-identical.

Gates (fail-closed, nothing written unless ALL pass):
  1. NO removed unique identities;
  2. every added identity ∈ declared set;
  3. the unapproved-site pin count and set unchanged.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
ARTIFACT = REPO_ROOT / "docs" / "direct_io_inventory.json"

sys.path.insert(0, str(REPO_ROOT / "src"))

from webpent.shared.direct_io_inventory import scan_direct_io  # noqa: E402

DECLARED_ADDED = {
    json.dumps({
        "file": "src/webpent/appmodel/skg.py",
        "kind": "dynamic_resolution",
        "normalized_symbol": "getattr(state, ... )",
    }, sort_keys=True),
    json.dumps({
        "file": "src/webpent/production/researcher_brain.py",
        "kind": "dynamic_resolution",
        "normalized_symbol": "getattr(state, ... )",
    }, sort_keys=True),
    # Phase C status-inspection accessors (deterministic, read-only)
    json.dumps({
        "file": "src/webpent/researcher/evolution.py",
        "kind": "dynamic_resolution",
        "normalized_symbol": "getattr(h, ... )",
    }, sort_keys=True),
    json.dumps({
        "file": "src/webpent/researcher/evolution.py",
        "kind": "dynamic_resolution",
        "normalized_symbol": "getattr(hyp, ... )",
    }, sort_keys=True),
    json.dumps({
        "file": "src/webpent/researcher/evolution.py",
        "kind": "dynamic_resolution",
        "normalized_symbol": "getattr(hypothesis, ... )",
    }, sort_keys=True),
    json.dumps({
        "file": "src/webpent/production/hypothesis_evolution.py",
        "kind": "dynamic_resolution",
        "normalized_symbol": "getattr(hyp, ... )",
    }, sort_keys=True),
    # Phase D: the attack-chain node's state accessor (read-only)
    json.dumps({
        "file": "src/webpent/production/attack_chains_node.py",
        "kind": "dynamic_resolution",
        "normalized_symbol": "getattr(state, ... )",
    }, sort_keys=True),
    # Phase H: the memory module's status-inspection accessor
    json.dumps({
        "file": "src/webpent/researcher/memory.py",
        "kind": "dynamic_resolution",
        "normalized_symbol": "getattr(hyp, ... )",
    }, sort_keys=True),
}


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

    added = current_ids - recorded_ids
    undeclared = added - DECLARED_ADDED
    assert not undeclared, (
        f"UNDECLARED added identities (fail-closed): {sorted(undeclared)}")

    # unapproved-site pin: raw transport sites unchanged
    raw_kinds = {"httpx", "raw_http", "subprocess", "dynamic_import"}
    recorded_raw = sorted(
        identity(r) for r in recorded if r.get("transport") in raw_kinds)
    current_raw = sorted(
        identity(r) for r in current if r.get("transport") in raw_kinds)
    assert recorded_raw == current_raw, (
        "raw-transport site set changed — NOT declared by this window")

    artifact["records"] = [json.loads(json.dumps(r)) if False else r for r in current]
    ARTIFACT.write_text(json.dumps(artifact, indent=1, sort_keys=False) + "\n")
    print(f"regenerated: {len(current)} records; "
          f"added identities {sorted(added)}; removed 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
