"""Reviewed regeneration of docs/direct_io_inventory.json (fix-sprint 2026-10-05).

Context (see EVIDENCE_REPORT_20261005.md, PHASE 3):
The recorded artifact pre-dates the approved 2026-10-05 unfreeze sprint
(docs/archive/2026-11-01-plan-exec-root-reports/UNFREEZE_APPLIED_REPORT_20261005.md).
That sprint edited the 5 unfrozen
production modules and added defensive getattr() reads on locally-held
objects. The AST scanner classifies each as a `dynamic_resolution` /
`non_transport` inventory record. The unfreeze sprint never regenerated the
artifact (its verification ran tests/team1_acceptance only; this drift test
lives in tests/ root), so the drift test failed on the first full-suite run
with conftest enabled.

Review adjudication (this script encodes the decision, it does not hand-edit):
  * removed set MUST be empty (no site disappeared);
  * added set MUST be exactly the 14 reviewed identities, all getattr
    dynamic-resolution reads introduced by the approved unfreeze sprint;
  * NO added record may be a raw transport (import / call / dynamic_import
    kind on an http/socket/importlib symbol) — the 20/17 unapproved-site
    security pin must be untouched;
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

REVIEWED_ADDED_IDENTITIES = frozenset(
    {
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
    if added != REVIEWED_ADDED_IDENTITIES:
        print("REFUSING: added set != reviewed set.")
        print("  unexpected additions:", sorted(added - REVIEWED_ADDED_IDENTITIES))
        print("  reviewed but absent :", sorted(REVIEWED_ADDED_IDENTITIES - added))
        raise SystemExit(1)

    added_records = [r for r in records if (r["file"], r["kind"], r["normalized_symbol"]) in added]
    bad = [
        r for r in added_records
        if r["kind"] in RAW_TRANSPORT_KINDS or r.get("transport_family") not in (None, "non_transport")
    ]
    if bad:
        print("REFUSING: an added record is a raw transport (needs security adjudication):", bad)
        raise SystemExit(1)

    data["records"] = records
    cov = data["coverage"]
    cov["record_count"] = len(records)
    cov["approved_record_count"] = sum(1 for r in records if r.get("approval_status") == "approved")
    cov["unapproved_record_count"] = sum(1 for r in records if r.get("approval_status") == "not_approved")
    families: dict[str, int] = {}
    for r in records:
        fam = r.get("transport_family") or "unknown"
        families[fam] = families.get(fam, 0) + 1
    cov["transport_families"] = families

    ARTIFACT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"REGENERATED OK: {old_count_before(data):d} -> {len(records)} records; "
          f"unapproved pin count = {cov['unapproved_record_count']} (must stay 20).")


def old_count_before(data: dict) -> int:
    return json.loads(ARTIFACT.read_text(encoding="utf-8")).get("coverage", {}).get("record_count", -1) if False else data["coverage"]["record_count"]


if __name__ == "__main__":
    main()
