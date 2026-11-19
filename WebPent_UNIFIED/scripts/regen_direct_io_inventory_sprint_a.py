"""Regenerate docs/direct_io_inventory.json from the canonical AST scanner.

Per the artifact's own contract (see tests/test_g02_direct_io_inventory.py):
the recorded artifact must equal a full current-source scan. Sprint A edited
non-frozen production modules, which shifts recorded line numbers without
adding any new transport site (verified: added = removed = empty). This script
regenerates the records from scan_direct_io() exactly as previous sprints did
(documented in docs/HOSTILE_AUDIT_REMEDIATION_20261003.md section 2.4 and
docs/VULNERABILITY_FAMILY_EXPANSION_REPORT.md) and preserves every other
artifact section verbatim.
"""
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webpent.shared.direct_io_inventory import scan_direct_io

ARTIFACT = ROOT / "docs" / "direct_io_inventory.json"
SRC = ROOT / "src"

records = scan_direct_io(SRC)
data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
old_count = data["coverage"]["record_count"]
new_count = len(records)

added_sites = {
    (r["file"], r["kind"], r["normalized_symbol"]) for r in records
} - {
    (r["file"], r["kind"], r["normalized_symbol"]) for r in data["records"]
}
removed_sites = {
    (r["file"], r["kind"], r["normalized_symbol"]) for r in data["records"]
} - {
    (r["file"], r["kind"], r["normalized_symbol"]) for r in records
}
if added_sites or removed_sites:
    print("REFUSING REGENERATION: transport-site set changed.")
    print("  added:", sorted(added_sites))
    print("  removed:", sorted(removed_sites))
    print("A changed site set requires explicit review before re-pinning.")
    raise SystemExit(1)

data["records"] = records
data["coverage"]["record_count"] = new_count
data["coverage"]["approved_record_count"] = sum(
    1 for r in records if r.get("approval_status") == "approved"
)
data["coverage"]["unapproved_record_count"] = sum(
    1 for r in records if r.get("approval_status") == "not_approved"
)
families: dict[str, int] = {}
for r in records:
    family = str(r.get("transport_family") or "unknown")
    families[family] = families.get(family, 0) + 1
data["coverage"]["transport_families"] = families
data["generated_from"] = f"canonical AST scan on {date.today().isoformat()}"

ARTIFACT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
print(f"regenerated: {old_count} -> {new_count} records; site set unchanged (line-shift only)")
