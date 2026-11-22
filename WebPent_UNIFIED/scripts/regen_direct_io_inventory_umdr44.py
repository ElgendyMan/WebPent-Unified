#!/usr/bin/env python3
"""UM-DR-44 window regen for the direct-I/O inventory artifact.

Reviewed closure delta (this script's own gate):
  * The B6(b) TLS settings gate added a `getattr(get_settings(), ...)`
    read in src/webpent/shared/h2_race.py (fail-closed double-gate —
    any settings failure keeps STRICT TLS), and the B2 identity-thread
    state work carried `getattr(record, ...)` reads in
    src/webpent/state/reducers.py (checkpoint record field access).
  * Both additions are dynamic_resolution (getattr) records ONLY —
    classification 'not_applicable' (no transport signal), the exact
    identity class the G-02 gate describes as non-transport.
  * ZERO removals (fail-closed gate holds; the unapproved-site pin is
    unchanged; no approved transport record was touched).
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webpent.shared.direct_io_inventory import scan_direct_io  # noqa: E402 — deliberate import order (P2-203 triage)

ARTIFACT = ROOT / "docs" / "direct_io_inventory.json"
SRC = ROOT / "src"

# The reviewed additive identities for this window: exactly the two
# dynamic_resolution (getattr) reads named above — nothing else.
REVIEWED_ADDITIVE_IDENTITIES: set[tuple[str, str, str]] = {
    ("src/webpent/shared/h2_race.py", "dynamic_resolution", "getattr(... )"),
    ("src/webpent/state/reducers.py", "dynamic_resolution",
     "getattr(record, ... )"),
}


def _key(record: dict) -> tuple:
    return (record.get("file"), record.get("kind"),
            record.get("normalized_symbol"))


def main() -> int:
    records = scan_direct_io(SRC)
    data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    old_records = data["records"]
    old_keys = {_key(record) for record in old_records}
    new_keys = {_key(record) for record in records}

    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)

    if removed:
        print("REFUSING: identity-level REMOVALS are fail-closed here:")
        for item in removed:
            print("  -", item)
        return 1
    unreviewed = [item for item in added
                  if tuple(item) not in REVIEWED_ADDITIVE_IDENTITIES]
    if unreviewed:
        print("REFUSING: additive identities outside the reviewed set:")
        for item in unreviewed:
            print("  +", item)
        return 1

    moved = sum(
        1
        for old in old_records
        if any(_key(new) == _key(old) and new.get("line") != old.get("line")
               for new in records))

    print(f"=== {len(added)} additive identity(ies), {len(removed)} "
          f"removals, {moved} records moved lines ===")

    data["records"] = records
    data["record_count"] = len(records)
    data["regenerated_at"] = datetime.now(UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    data["regen_reason"] = (
        "umdr44 window regen: B6(b) added the fail-closed "
        "verify_target_tls getattr read in shared/h2_race.py and the B2 "
        "identity-thread state work carried getattr(record, ...) reads in "
        "state/reducers.py — both dynamic_resolution (non-transport) "
        "additions only; ZERO removals")
    generated_from = data.get("generated_from")
    if generated_from:
        generated_from["commit"] = _git_head()
    ARTIFACT.write_text(json.dumps(data, indent=2) + "\n",
                        encoding="utf-8")
    print(f"regen_umdr44: artifact updated ({len(records)} records)")
    return 0


def _git_head() -> str:
    import subprocess
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
        text=True).stdout.strip() or "unknown"


if __name__ == "__main__":
    sys.exit(main())
