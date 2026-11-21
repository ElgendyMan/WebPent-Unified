#!/usr/bin/env python3
"""UM-DR-43C window regen for the direct-I/O inventory artifact.

Reviewed closure delta (this script's own gate):
  * The lifecycle contract touched src/webpent/state/reducers.py
    (merge_hypotheses field-wise merge, transition table,
    _merge_hypothesis_records) and src/webpent/production/
    hypothesis_dedup.py (v2 identity wiring + telemetry), and ADDED
    src/webpent/production/hypothesis_identity.py (pure functions:
    hashlib/json canonical forms only).
  * None of these changes imports or calls a scanned transport symbol;
    the ONLY expected delta is line drift of existing records inside
    state/reducers.py.
  * ZERO identity-level additions, ZERO identity-level removals
    (fail-closed gate holds; the unapproved-site pin is unchanged).
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

# The reviewed additive identities for this window. EMPTY: the UM-DR-43C
# window adds no new scanned transport identity (hypothesis_identity.py
# uses hashlib/json in-process only — never a scanned I/O symbol).
REVIEWED_ADDITIVE_IDENTITIES: set[tuple[str, str, str]] = set()


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
        "umdr43c window regen: the hypothesis lifecycle contract touched "
        "state/reducers.py, production/hypothesis_dedup.py and added "
        "production/hypothesis_identity.py (pure in-process hashlib/json "
        "only); ZERO identity-level delta, line drift only")
    generated_from = data.get("generated_from")
    if generated_from:
        data["generated_from"]["commit"] = _git_head()
    ARTIFACT.write_text(json.dumps(data, indent=2) + "\n",
                        encoding="utf-8")
    print(f"regen_umdr43c: artifact updated "
          f"({len(records)} records)")
    return 0


def _git_head() -> str:
    import subprocess
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
        text=True).stdout.strip() or "unknown"


if __name__ == "__main__":
    sys.exit(main())
