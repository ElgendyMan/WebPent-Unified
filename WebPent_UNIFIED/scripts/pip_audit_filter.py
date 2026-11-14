#!/usr/bin/env python3
"""P2-202 gate: filter pip-audit JSON output against the reviewed allowlist.

Reads a pip-audit JSON report (default: stdin, or --report PATH), removes
vulnerabilities covered by scripts/pip_audit_allowlist.txt, and:

  exit 0  — zero non-allowlisted vulnerabilities AND zero stale allowlist
            entries (every entry covered >= 1 advisory in the report)
  exit 1  — any non-allowlisted vulnerability, any stale (unmatched)
            allowlist entry, or a malformed report/allowlist

The double-sided check makes the allowlist a ratchet: entries cannot linger
after they stop matching, and new advisories cannot hide behind old text.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ALLOWLIST_PATH = Path(__file__).resolve().parent / "pip_audit_allowlist.txt"

# <pkg>==<version>  <advisory-id>  # <free text>
LINE_RE = re.compile(
    r"^(?P<pkg>[A-Za-z0-9._-]+)==(?P<ver>[A-Za-z0-9._+-]+)\s+"
    r"(?P<adv>[A-Za-z0-9._-]+)\s+#(?P<rest>.*)$"
)


def parse_allowlist(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    entries: list[dict[str, str]] = []
    errors: list[str] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            errors.append(f"{path.name}:{lineno}: unparseable line: {raw!r}")
            continue
        entries.append(m.groupdict())
    return entries, errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", default="-", help="pip-audit JSON report path (default stdin)")
    args = ap.parse_args()

    text = sys.stdin.read() if args.report == "-" else Path(args.report).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        print(f"pip_audit_filter: malformed report JSON: {exc}", file=sys.stderr)
        return 1
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    if not isinstance(deps, list):
        print("pip_audit_filter: unexpected report shape", file=sys.stderr)
        return 1

    flagged: dict[tuple[str, str, str], list[str]] = {}
    for dep in deps:
        pkg = str(dep.get("name", "")).lower()
        ver = str(dep.get("version", ""))
        for vuln in dep.get("vulns", []):
            vid = str(vuln.get("id", "?"))
            fixes = ",".join(vuln.get("fix_versions", []) or []) or "NO-FIX-UPSTREAM"
            flagged.setdefault((pkg, ver, vid), []).append(fixes)

    entries, parse_errors = parse_allowlist(ALLOWLIST_PATH)
    failures: list[str] = list(parse_errors)

    covered: set[tuple[str, str, str]] = set()
    for e in entries:
        key = (e["pkg"].lower(), e["ver"], e["adv"])
        if key in flagged:
            covered.add(key)
        else:
            failures.append(
                f"STALE allowlist entry: {e['pkg']}=={e['ver']} {e['adv']} "
                f"matches nothing in the current report — remove or re-review it"
            )

    uncovered = {k: v for k, v in flagged.items() if k not in covered}
    for (pkg, ver, vid), fixes in sorted(uncovered.items()):
        failures.append(
            f"UNALLOWLISTED vulnerability: {pkg}=={ver} {vid} (fix_versions: {', '.join(sorted(set(fixes)))})"
        )

    if failures:
        print(f"pip_audit_filter: GATE FAILURE ({len(failures)} issue(s))")
        for f in failures:
            print(f"  - {f}")
        return 1

    n_allowed = len(flagged)
    print(
        f"pip_audit_filter: PASS — {n_allowed} advisories present, all covered "
        f"by {len(entries)} reviewed allowlist entries (0 stale, 0 unallowlisted)"
    )
    for e in entries:
        print(f"  allowed: {e['pkg']}=={e['ver']} {e['adv']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
