#!/usr/bin/env python3
"""Deliberately regenerate the G-02 direct-I/O inventory artifact for the
M2 AUTHORIZATION & SCOPE window (2026-11-05, UM-DR-15) per the DR-009
protocol.

Background (why this regen is due): the artifact's records were last
regenerated at the UNIFIED-MERGE phase-1/2 window (2026-11-02). Since then
the M0-era R1-R5 fixes, the M1-A safe-transport migration (M-4/M-5), the
M1-C wiring windows and this M2 window all touched transport-bearing files
WITHOUT a recorded artifact refresh — the no-drift gate has been failing
since the M1 windows closed (pre-existing drift this window closes
deliberately, with the delta fully declared below).

Declared delta (fail-closed gates encoded here):
  1. REMOVED identities == EXACTLY the 11 adjudicated sites:
     - apex/sandbox.py + memory/ab_lab.py + production/verdict_bridge.py
       subprocess identities (6) — became APPROVED in
       shared/direct_io_inventory.py this window (bounded argv-typed
       calls, reasons documented);
     - shared/legacy_containment.py httpx identities (2) and
       shared/oob.py urlopen identities (2) and
       integrations/notifications/dispatch.py urllib.request identity (1)
       — physically removed by the M-4/M-5 safe-transport migration
       (M1-A windows; the raw-call sites no longer exist in the tree).
  2. ADDED identities only from the declared file set (new modules since
     the last regen + this window's new authorization model).
  3. The unapproved-transport pin MUST equal the fail-closed constants in
     tests/test_g02_direct_io_inventory.py (36 records / 30 identities) —
     cross-checked by importing them.
  4. Every non-records artifact section is preserved; coverage,
     record_count, generated_at/generated_from recomputed; a regen_history
     entry appended.

Usage: python scripts/regen_direct_io_inventory_m2_authorization_scope.py
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
SRC = ROOT / "src"

#: Files whose NEW identities this window declares (new modules since the
#: 2026-11-02 regen plus this window's model + the reclassified files).
ALLOWED_NEW_FILES: set[str] = {
    "src/webpent/chained_exploits/analyzer.py",
    "src/webpent/cli/bounty.py",
    "src/webpent/cli/portfolio.py",
    "src/webpent/cli/unified_hunt.py",
    # M1-B era: the negative-control replay wiring added a sibling
    # getattr dynamic-resolution site next to the pinned post_state_replay
    # one (attacker_redirect_replay) — pre-existing drift this regen records.
    "src/webpent/agents/validator/family_checks.py",
    "src/webpent/integrations/notifications/dispatch.py",
    "src/webpent/jsintel/api_surface_shadow.py",
    "src/webpent/models/authorization.py",
    "src/webpent/shared/cve_advisory.py",
    "src/webpent/shared/legacy_containment.py",
    "src/webpent/shared/oob.py",
}

#: The EXACT removed-identity set (adjudicated; see module docstring).
#: NOTE: the six subprocess identities (apex/sandbox, ab_lab,
#: verdict_bridge) are NOT removals — they remain in the scan and only
#: their approval_status flips to "approved" (map documentation). The
#: physically-removed identities are exactly these five:
DECLARED_REMOVED_IDENTITIES: set[tuple[str, str, str]] = {
    ("src/webpent/shared/legacy_containment.py", "call", "httpx.Client"),
    ("src/webpent/shared/legacy_containment.py", "import", "httpx"),
    ("src/webpent/shared/oob.py", "call", "urllib.request.urlopen"),
    ("src/webpent/shared/oob.py", "import", "urllib.request.urlopen"),
    ("src/webpent/integrations/notifications/dispatch.py", "import", "urllib.request"),
}

WINDOW = "M2 AUTHORIZATION & SCOPE 2026-11-05"
REGEN_REASON = (
    "deliberate regen for the M2 authorization & scope window: closes the "
    "artifact drift accumulated since the UNIFIED-MERGE phase-1/2 regen "
    "(2026-11-02) — M0 R1-R5 fixes, the M1-A M-4/M-5 safe-transport "
    "migration (raw urlopen/httpx sites removed), M1-C wiring files, and "
    "the M2 subprocess-site adjudication (3 sites approved with reasons); "
    "unapproved pin re-pinned 47->36 records / 41->30 identities by "
    "adjudication only"
)


def _identity(record: dict) -> tuple[str, str, str]:
    symbol = record.get("normalized_symbol") or record.get("symbol", "")
    return (record["file"], record["kind"], symbol)


def main() -> int:
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    recorded = artifact["records"]
    fresh = scan_direct_io(SRC)

    recorded_ids = {_identity(r) for r in recorded}
    fresh_ids = {_identity(r) for r in fresh}

    # --- Gate 1: removals are EXACTLY the adjudicated set -----------------
    removed = recorded_ids - fresh_ids
    if removed != DECLARED_REMOVED_IDENTITIES:
        undeclared = removed - DECLARED_REMOVED_IDENTITIES
        missing = DECLARED_REMOVED_IDENTITIES - removed
        print(f"ABORT: removed identities != declared set; undeclared={sorted(undeclared)[:6]} "
              f"missing={sorted(missing)[:6]}")
        return 1
    print(f"  declared removals accepted: {len(removed)}")

    # --- Gate 2: additions only from declared files -----------------------
    added = fresh_ids - recorded_ids
    bad_added = {ident for ident in added if ident[0] not in ALLOWED_NEW_FILES}
    if bad_added:
        print(f"ABORT: {len(bad_added)} new identities outside the declared file set:")
        for item in sorted(bad_added)[:10]:
            print("  -", item)
        return 1
    print(f"  declared additions accepted: {len(added)}")

    # --- Gate 3: unapproved pin == the test's fail-closed constants -------
    sys.path.insert(0, str(ROOT / "tests"))
    from test_g02_direct_io_inventory import (  # noqa: E402
        PINNED_UNAPPROVED_IDENTITY_COUNT,
        PINNED_UNAPPROVED_RECORD_COUNT,
        _unapproved_sites,
    )

    fresh_unapproved = [r for r in fresh if r.get("approval_status") == "not_approved"]
    fresh_pin_identities = len(_unapproved_sites(fresh))
    if len(fresh_unapproved) != PINNED_UNAPPROVED_RECORD_COUNT or (
        fresh_pin_identities != PINNED_UNAPPROVED_IDENTITY_COUNT
    ):
        print(
            f"ABORT: unapproved counts ({len(fresh_unapproved)} records / "
            f"{fresh_pin_identities} identities) != test pin "
            f"({PINNED_UNAPPROVED_RECORD_COUNT}/{PINNED_UNAPPROVED_IDENTITY_COUNT})"
        )
        return 1
    print(f"  unapproved pin cross-checked: {len(fresh_unapproved)} records / "
          f"{fresh_pin_identities} identities")

    # --- Write: records from the scan, everything else preserved ----------
    previous_generated_from = artifact.get("generated_from", "")
    artifact["records"] = fresh
    artifact["record_count"] = len(fresh)
    artifact["generated_at"] = datetime.now(timezone.utc).isoformat()
    artifact["generated_from"] = (
        (previous_generated_from + " — " if previous_generated_from else "")
        + f"regenerated {WINDOW} (DR-009 protocol)"
    )
    artifact["coverage"] = {
        **(artifact.get("coverage") or {}),
        "total_records": len(fresh),
        "records": len(fresh),
    }
    artifact.setdefault("regen_history", []).append(
        {
            "window": WINDOW,
            "reason": REGEN_REASON,
            "regenerated_at": artifact["generated_at"],
            "record_count_before": len(recorded),
            "record_count_after": len(fresh),
            "removed_identities": len(removed),
            "added_identities": len(added),
        }
    )

    ARTIFACT.write_text(json.dumps(artifact, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(f"regenerated: {len(fresh)} records "
          f"(was {len(recorded)}; +{len(added)} -{len(removed)} adjudicated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
