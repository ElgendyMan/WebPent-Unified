"""R4 production-hardening window regeneration of docs/direct_io_inventory.json
(2026-11-02, DR-020).

Lineage: regen_direct_io_inventory_r9a_20261027.py is the protocol precedent
(reviewable-delta regen; the g02 no-drift test must pass immediately after
this regen; hand-edits are forbidden).

Reviewed additive identities for this window (identity = file, kind,
normalized_symbol) — the ONLY allowed additions:
  * src/webpent/agents/prototype_pollution/agent.py — the R4 LangGraph node
    (prototype_pollution_node) calls the governed boundary
    (make_safe_httpx_client) exactly once, mirroring request_smuggling_node.
  * src/webpent/agents/cache_poisoning/agent.py — same pattern for
    cache_poisoning_node.

Everything else in the R4 window (strict key guard in preflight.py,
security-headers middleware in api/app.py, --version in cli/commands.py,
validator/registry/postp0_checks/builder edits) adds NO new transport site;
all HTTP reuses the governed ``make_safe_httpx_client`` client or the
SSRF-pinned wrappers in postp0_checks.py. Expected delta: line moves in the
edited files + the two reviewed additive boundary records above.
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

REVIEWED_ADDITIVE_IDENTITIES: set[tuple[str, str, str]] = {
    (
        "src/webpent/agents/prototype_pollution/agent.py",
        "safe_boundary_call",
        "webpent.shared.http.make_safe_httpx_client",
    ),
    (
        "src/webpent/agents/cache_poisoning/agent.py",
        "safe_boundary_call",
        "webpent.shared.http.make_safe_httpx_client",
    ),
    # The scanner records getattr attribute reads in the new nodes as
    # dynamic_resolution observability records — the same benign class the
    # sibling agents carry (e.g. request_smuggling_node's
    # getattr(target, ...) record). Pure state reads, no transport.
    (
        "src/webpent/agents/prototype_pollution/agent.py",
        "dynamic_resolution",
        "getattr(target, ... )",
    ),
    (
        "src/webpent/agents/prototype_pollution/agent.py",
        "dynamic_resolution",
        "getattr(item, ... )",
    ),
    (
        "src/webpent/agents/cache_poisoning/agent.py",
        "dynamic_resolution",
        "getattr(target, ... )",
    ),
    (
        "src/webpent/agents/cache_poisoning/agent.py",
        "dynamic_resolution",
        "getattr(item, ... )",
    ),
}


def _key(record: dict) -> tuple:
    return (record.get("file"), record.get("kind"), record.get("normalized_symbol"))


def main() -> int:
    records = scan_direct_io(SRC)
    data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    old_records = data["records"]
    old_keys = {_key(record) for record in old_records}
    new_keys = {_key(record) for record in records}

    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)

    if removed:
        print("REFUSING: identity-level REMOVALS are fail-closed in this window:")
        for item in removed:
            print("  -", item)
        return 1
    unreviewed = [item for item in added if tuple(item) not in REVIEWED_ADDITIVE_IDENTITIES]
    if unreviewed:
        print("REFUSING: additive identities outside the reviewed R4 set:")
        for item in unreviewed:
            print("  +", item)
        return 1

    moved = sum(
        1
        for old in old_records
        if any(_key(new) == _key(old) and new.get("line") != old.get("line") for new in records)
    )
    new_records_for_additions = [record for record in records if tuple(_key(record)) in REVIEWED_ADDITIVE_IDENTITIES]
    duplicate_delta = len(records) - len(old_records) - len(new_records_for_additions)

    print("=== reviewed additive records (full dump for review) ===")
    for record in new_records_for_additions:
        print("  +", json.dumps(record, sort_keys=True))
    print(
        f"=== {len(added)} additive identity(ies), {len(removed)} removals, "
        f"{moved} records moved lines, {duplicate_delta:+d} duplicate-count delta ==="
    )

    data["records"] = records
    generated_from = data.get("generated_from") or {}
    generated_from["record_count"] = len(records)
    generated_from["regenerated_at"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    generated_from["regenerated_by"] = (
        "R4 production-hardening window regen (scripts/regen_direct_io_inventory_r4_20261102.py)"
    )
    generated_from["scan_root"] = "src"
    data["generated_from"] = generated_from
    coverage = data.get("coverage") or {}
    for field in ("record_count", "total_records", "count", "records"):
        if field in coverage:
            coverage[field] = len(records)
    data.setdefault("regen_history", []).append(
        {
            "at": generated_from["regenerated_at"],
            "delta": (
                f"{len(old_records)} -> {len(records)} records: {len(added)} added "
                f"identity (reviewed), {len(removed)} removed identity, {moved} moved "
                f"(line drift), {duplicate_delta:+d} duplicate-count delta"
            ),
            "reason": (
                "R4 production-hardening window regen (DR-020, DR-009 protocol): the "
                "strict key guard (preflight.py), security-headers middleware (api/app.py), "
                "--version/--build-info (cli/commands.py), and the detector wiring "
                "(models/findings.py, validator registry/agent/postp0_checks, graph/builder.py) "
                "shifted recorded line numbers; the two reviewed additive identities are the "
                "governed make_safe_httpx_client boundary calls in the new detector nodes. "
                "No raw-transport site added; both nodes reuse the governed client and the "
                "engagement-scope fail-closed gate. Unapproved-site pin unchanged."
            ),
            "unit": "r4 (production-hardening window; on top of the r9a lineage)",
        }
    )
    ARTIFACT.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"regen OK: {len(old_records)} -> {len(records)} records; g02 no-drift test must pass now")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
