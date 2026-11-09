"""Reviewed regeneration of docs/direct_io_inventory.json — v2 (2026-10-05).

Context (FINAL PREP SPRINT v3):
v1 of this script (regen_direct_io_inventory_reviewed_20261005.py) encoded
the unfreeze-sprint adjudication (14 reviewed getattr dynamic-resolution
identities). The FINAL PREP SPRINT then added the spec-mandated video-POC
recorder (src/webpent/reporter/poc_recorder.py), which contributes exactly
two new inventory records:

  1. import of playwright.sync_api.sync_playwright — transport_family
     "browser", approval "not_approved" → the unapproved record pin moves
     20 → 21 and the identity pin 17 → 18. Adjudication: browser-only
     recording surface, invoked solely by the operator CLI / opt-in watcher,
     never by the hunting path; precedent = the identical pinned playwright
     import in src/webpent/cli/commands.py.
  2. getattr(context, ... ) — dynamic_resolution / non_transport /
     not_applicable (playwright context handle read).

This v2 script encodes THAT decision (it does not hand-edit the artifact):
  * removed set MUST be empty;
  * added set MUST be exactly the 14 v1-reviewed getattr identities PLUS the
    two adjudicated poc_recorder identities above;
  * the ONLY allowed non-non_transport addition is the adjudicated playwright
    import identity (kind=import, family=browser) — any other raw transport
    addition still refuses;
  * every non-records artifact section is preserved verbatim;
  * coverage counts are recomputed from the new records.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webpent.shared.direct_io_inventory import scan_direct_io

ARTIFACT = ROOT / "docs" / "direct_io_inventory.json"
SRC = ROOT / "src"

# v1 reviewed identities (unfreeze sprint, 14 getattr reads)
V1_GETATTR_IDENTITIES = {
    ("src/webpent/agents/hunter_runner.py", "dynamic_resolution", "getattr(_halt_exc, ... )"),
    ("src/webpent/agents/hunter_runner.py", "dynamic_resolution", "getattr(crawl.surface_map, ... )"),
    ("src/webpent/agents/hunter_runner.py", "dynamic_resolution", "getattr(principal, ... )"),
    ("src/webpent/agents/hunter_runner.py", "dynamic_resolution", "getattr(provisioning.detection, ... )"),
    ("src/webpent/agents/hunter_runner.py", "dynamic_resolution", "getattr(reprovisioned, ... )"),
    ("src/webpent/integration/planner_enrichment_bridge.py", "dynamic_resolution", "getattr(e, ... )"),
    ("src/webpent/integration/planner_enrichment_bridge.py", "dynamic_resolution", "getattr(priority_adjustment, ... )"),
    ("src/webpent/integration/session_recovery_bridge.py", "dynamic_resolution", "getattr(h, ... )"),
    ("src/webpent/integration/session_recovery_bridge.py", "dynamic_resolution", "getattr(result, ... )"),
    ("src/webpent/recon/auth_detector.py", "dynamic_resolution", "getattr(p, ... )"),
    ("src/webpent/recon/auth_resilience.py", "dynamic_resolution", "getattr(resp, ... )"),
    ("src/webpent/recon/hypothesis_generator.py", "dynamic_resolution", "getattr(enriched_context, ... )"),
    ("src/webpent/recon/session_recovery.py", "dynamic_resolution", "getattr(login_result, ... )"),
    ("src/webpent/recon/session_recovery.py", "dynamic_resolution", "getattr(provisioned, ... )"),
}

# v3 adjudicated identities (FINAL PREP SPRINT — video POC recorder)
V3_POC_IDENTITIES = {
    ("src/webpent/reporter/poc_recorder.py", "import", "playwright.sync_api.sync_playwright"),
    ("src/webpent/reporter/poc_recorder.py", "dynamic_resolution", "getattr(context, ... )"),
}

REVIEWED_ADDED_IDENTITIES = V1_GETATTR_IDENTITIES | V3_POC_IDENTITIES

# the single non-non_transport addition allowed by this adjudication
ADJUDICATED_BROWSER_IMPORT = (
    "src/webpent/reporter/poc_recorder.py",
    "import",
    "playwright.sync_api.sync_playwright",
)
RAW_TRANSPORT_KINDS = {"import", "call", "dynamic_import"}


def main() -> None:
    records = scan_direct_io(SRC)
    data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    old_ids = {(r["file"], r["kind"], r["normalized_symbol"]) for r in data["records"]}
    new_ids = {(r["file"], r["kind"], r["normalized_symbol"]) for r in records}

    added = new_ids - old_ids
    removed = old_ids - new_ids

    if removed:
        print("REFUSING: removed sites present (requires human review):", sorted(removed))
        raise SystemExit(1)
    # v1's 14 getattr identities were merged by the v1 regen in the previous
    # sprint — they must still be PRESENT (no regression), not re-added.
    missing_v1 = V1_GETATTR_IDENTITIES - new_ids
    if missing_v1:
        print("REFUSING: v1-reviewed identities regressed (missing):", sorted(missing_v1))
        raise SystemExit(1)
    if added != V3_POC_IDENTITIES:
        print("REFUSING: added set != v3 adjudicated set.")
        print("  unexpected additions:", sorted(added - V3_POC_IDENTITIES))
        print("  adjudicated but absent :", sorted(V3_POC_IDENTITIES - added))
        raise SystemExit(1)

    added_records = [r for r in records if (r["file"], r["kind"], r["normalized_symbol"]) in added]
    bad = []
    for r in added_records:
        identity = (r["file"], r["kind"], r["normalized_symbol"])
        if identity == ADJUDICATED_BROWSER_IMPORT:
            if r.get("transport_family") != "browser":
                bad.append(r)  # adjudicated record must stay browser-family
            continue
        if r["kind"] in RAW_TRANSPORT_KINDS or r.get("transport_family") not in (None, "non_transport"):
            bad.append(r)
    if bad:
        print("REFUSING: non-reviewed raw-transport additions:", bad)
        raise SystemExit(1)

    data["records"] = records
    data["coverage"] = {
        "files_scanned": len({r["file"] for r in records}),
        "records": len(records),
    }
    ARTIFACT.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"regenerated {ARTIFACT}: {len(records)} records "
          f"(+{len(added)} v3 adjudicated additions; 14 v1 getattr identities verified present)")


if __name__ == "__main__":
    main()
