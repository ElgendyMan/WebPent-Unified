#!/usr/bin/env python3
"""Deliberately regenerate the G-02 direct-I/O inventory artifacts.

Run this ONLY after an intentional source change moved/added/removed a
transport site. It rewrites both files from a full current scan — never
hand-edit them:

- docs/direct_io_inventory.json  (the drift-gated artifact: records are
  replaced wholesale by ``scan_direct_io(src)``; policy keys such as
  approved_direct_files, approved_transport_records,
  dynamic_import_allowlist, logical_transports and the fail-closed pin
  note are preserved unchanged)
- docs/DIRECT_IO_INVENTORY.md    (human-readable rendering of the same
  scan)

The reviewable diff is ``git diff -- docs/direct_io_inventory.json
docs/DIRECT_IO_INVENTORY.md``.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from webpent.shared.direct_io_inventory import scan_direct_io

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
JSON_PATH = ROOT / "docs" / "direct_io_inventory.json"
MD_PATH = ROOT / "docs" / "DIRECT_IO_INVENTORY.md"

TRANSPORT_CLASSIFICATIONS = (
    "http_sync", "http_async", "http_transport", "http_implementation",
    "browser_implementation", "browser_playwright",
    "subprocess", "subprocess_boundary", "subprocess_implementation",
    "raw_tcp_dns", "raw_tcp_dns_implementation", "dynamic_import",
)


def main() -> None:
    records = scan_direct_io(SRC)
    artifact = json.loads(JSON_PATH.read_text(encoding="utf-8"))

    artifact["records"] = records
    artifact["record_count"] = len(records)
    artifact["generated_at"] = datetime.now(timezone.utc).isoformat()
    artifact["generated_from"] = "canonical AST scan of src"
    artifact["coverage"] = {
        "approved_transport": sum(
            1 for r in records
            if r["classification"] in TRANSPORT_CLASSIFICATIONS
            and r["approval_status"] in ("approved", "approved_with_expiry")
        ),
        "not_applicable": sum(
            1 for r in records if r["classification"] == "dynamic_resolution"
        ),
        "unapproved_raw_transport": sum(
            1 for r in records
            if r["classification"] in TRANSPORT_CLASSIFICATIONS
            and r["approval_status"] == "not_approved"
        ),
        "total_records": len(records),
    }

    JSON_PATH.write_text(
        json.dumps(artifact, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# G-02 Direct-I/O Inventory",
        "> This artifact is generated from the current `src/**/*.py` AST and is",
        "> enforced by the G-02 static/runtime gate. New direct transports,",
        "> unclassified sites, or artifact drift fail closed until reviewed.",
        f"Total records: **{len(records)}**.",
        "| File | Line | Kind | Symbol | Transport | Approval |",
        "|---|---:|---|---|---|---|",
    ]
    for r in records:
        lines.append(
            f"| `{r['file']}` | {r['line']} | `{r['kind']}` | "
            f"`{r['symbol']}` | `{r['classification']}` | "
            f"`{r['approval_status']}` |"
        )
    MD_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"regenerated: {len(records)} records")
    print("coverage:", json.dumps(artifact["coverage"]))
    print("approval_status:", dict(Counter(r["approval_status"] for r in records)))


if __name__ == "__main__":
    main()
