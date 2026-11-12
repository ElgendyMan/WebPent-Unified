#!/usr/bin/env python3
"""UM-DR-35.6 — gate for the OSV dependency audit report.

Consumes dependency_audit_report.json (produced by
umdr35_dependency_audit.py) and FAILS when any advisory affects a locked
package without a documented exception in scripts/quality/cve_allowlist.json.

An exception is honored only when it carries the UM-DR-35.6-required
fields: id, package, reason, owner, expiry, and an upstream remediation
plan. Expired exceptions fail the gate (re-approval required).

Exit codes: 0 = clean or fully-exceptioned, 1 = unhandled advisory, 2 =
report/allowlist unusable.
"""
from __future__ import annotations

import json
import sys
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "dependency_audit_report.json"
ALLOWLIST = ROOT / "scripts" / "quality" / "cve_allowlist.json"

REQUIRED_EXCEPTION_FIELDS = ("id", "package", "reason", "owner", "expiry")


def main() -> int:
    if not REPORT.exists():
        print("UM-DR-35.6 gate: dependency_audit_report.json missing — "
              "run scripts/umdr35_dependency_audit.py first", file=sys.stderr)
        return 2
    try:
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        allow = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"UM-DR-35.6 gate: unusable inputs: {exc}", file=sys.stderr)
        return 2

    exceptions: dict[str, dict] = {}
    for entry in allow.get("allowlist", []):
        missing = [f for f in REQUIRED_EXCEPTION_FIELDS if not entry.get(f)]
        if missing:
            print(f"UM-DR-35.6 gate: exception {entry.get('id')} lacks "
                  f"required fields {missing} — not honored", file=sys.stderr)
            continue
        try:
            expiry = datetime.fromisoformat(str(entry["expiry"])).date()
        except ValueError:
            continue
        if expiry < date.today():
            print(f"UM-DR-35.6 gate: exception {entry['id']} EXPIRED "
                  f"({entry['expiry']}) — re-approval required", file=sys.stderr)
            continue
        exceptions[str(entry["id"])] = entry

    unhandled: list[dict] = []
    for finding in report.get("findings", []):
        for adv in finding.get("advisories", []):
            if str(adv.get("id")) in exceptions:
                continue
            # Alias-level exception (GHSA id recorded, PYSEC alias reported)
            aliases = {str(a) for a in adv.get("aliases", [])}
            if aliases & set(exceptions):
                continue
            unhandled.append({
                "package": finding["package"],
                "version": finding["locked_version"],
                "advisory": adv.get("id"),
                "fixed_versions": adv.get("fixed_versions"),
            })

    if unhandled:
        print("UM-DR-35.6 gate: UNHANDDED advisories on the locked graph:")
        for u in unhandled:
            print(f"  {u['package']}=={u['version']} {u['advisory']} "
                  f"(fixed: {u['fixed_versions']})")
        print("Fix the lock or add a documented exception "
              "(id/package/reason/owner/expiry + upstream plan).")
        return 1
    print(f"UM-DR-35.6 gate: clean — {report.get('locked_packages')} locked "
          f"packages checked, {len(report.get('findings', []))} finding "
          f"packages, all advisories fixed or exceptioned with owner/expiry.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
