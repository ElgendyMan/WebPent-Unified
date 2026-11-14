#!/usr/bin/env python3
"""Dependency CVE gate with an audited allowlist — Track 1 (الاعتماديات).

Roadmap contract (المسار 1، جدول البوابات — الاعتماديات):

    إعادة فحص CVEs، ثم ترقية عائلة LangGraph في مسار منفصل مع اختبارات
    تكامل وتوافق قبل الدمج.

    ("Re-scan the CVEs, then upgrade the LangGraph family on a separate
    track with integration/compatibility tests before merging.")

History and why this gate exists
--------------------------------
The 2026-10-27 snapshot measured 12 CVEs against the pinned 0.x
langgraph family, which is why CI ran ``pip-audit || true`` (report
only). Since then the lock moved to the langgraph 1.x family and the
recorded scan (``docs/pip_audit_release.json``) reports ZERO open
vulnerabilities — so the report-only excuse no longer holds. This gate
promotes the check to blocking while keeping an honest escape valve:

* any vulnerability NOT in ``scripts/quality/cve_allowlist.json`` fails
  the build (default posture),
* an entry may be allow-listed ONLY with an explicit documented reason
  (id, package, reason, added date) — the file is the audit trail,
* the allowlist must not be edited casually: the CI step name says
  "audited allowlist" and the roadmap's Definition of Done requires
  critical risks to follow an approved policy.

Input modes
-----------
* default: runs ``pip-audit --format json`` itself (CI mode; requires
  network access to the advisory DB),
* ``--input FILE``: consume a previously produced pip-audit JSON report
  (offline mode / tests).

Exit codes: 0 = no un-allow-listed vulnerabilities, 1 = new
vulnerability found (block), 2 = harness error (audit could not run).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "scripts" / "quality" / "cve_allowlist.json"


def load_allowlist() -> dict[str, dict]:
    if not ALLOWLIST.exists():
        print(f"ABORT: missing allowlist {ALLOWLIST}", file=sys.stderr)
        raise SystemExit(2)
    data = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    entries = {}
    for item in data.get("allowlist", []):
        key = str(item.get("id", "")).upper()
        if key:
            entries[key] = item
    return entries


def run_pip_audit() -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "pip_audit", "--format", "json", "--desc", "off"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    # UM-DR-24 fix (harness defect): pip-audit's exit code 1 means
    # "vulnerabilities found" WITH a valid JSON report on stdout — that is a
    # successful audit, and the allowlist evaluation below is the gate's own
    # decision point. Conflating "ran and found" with "could not run"
    # (SystemExit 2) made the gate report a harness error whenever the
    # audited environment contained any vulnerability, and silently skipped
    # the allowlist/waive accounting. A harness failure is now: NO parseable
    # report on stdout (true network/DB failure → rc=2, fail-closed).
    report: dict | None = None
    if proc.stdout.strip():
        try:
            parsed = json.loads(proc.stdout)
            if isinstance(parsed, dict):
                report = parsed
        except ValueError:
            report = None
    if report is None:
        print(
            "ABORT: pip-audit produced no parseable report (network to the "
            f"advisory DB is required). rc={proc.returncode}\n{proc.stderr[-1500:]}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return report


def extract_vulns(report: dict) -> list[dict]:
    """pip-audit JSON: list of {name, version, vulns: [{id, fix_versions...}]}."""
    vulns: list[dict] = []
    for dep in report.get("dependencies", []):
        for vuln in dep.get("vulns") or []:
            vulns.append(
                {
                    "id": str(vuln.get("id", "UNKNOWN")).upper(),
                    "package": str(dep.get("name", "unknown")),
                    "version": str(dep.get("version", "?")),
                    "fix_versions": [str(v) for v in (vuln.get("fix_versions") or [])],
                }
            )
    return vulns


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--input", default="",
        help="read a pip-audit JSON report instead of running pip-audit",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    if args.input:
        try:
            report = json.loads(Path(args.input).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"ABORT: cannot read input report: {exc}", file=sys.stderr)
            return 2
    else:
        report = run_pip_audit()

    allow = load_allowlist()
    vulns = extract_vulns(report)
    blocked = [v for v in vulns if v["id"] not in allow]
    waived = [v for v in vulns if v["id"] in allow]

    if args.json:
        print(
            json.dumps(
                {
                    "total": len(vulns),
                    "blocked": blocked,
                    "waived": waived,
                    "pass": not blocked,
                },
                indent=2,
            )
        )
    else:
        print(f"deps gate: {len(vulns)} vulnerability/vulnerabilities found")
        for v in waived:
            reason = allow[v["id"]].get("reason", "no reason recorded")
            print(f"  WAIVED {v['id']} ({v['package']} {v['version']}) — {reason}")
        for v in blocked:
            fixes = ", ".join(v["fix_versions"]) or "no fix version"
            print(f"  BLOCK  {v['id']} ({v['package']} {v['version']}) — fix: {fixes}")

    if blocked:
        print(
            "\nFAIL: un-allow-listed vulnerabilities block the build.\n"
            "  Preferred: upgrade the affected package (locked dep bump +\n"
            "  integration tests). Only with an approved risk decision add an\n"
            '  entry to scripts/quality/cve_allowlist.json with id/reason/added.\n'
            "  (allowlist edited last: "
            f"{json.loads(ALLOWLIST.read_text(encoding='utf-8')).get('updated_at', 'unknown')})"
        )
        return 1
    if not args.json:
        print("PASS: no un-allow-listed vulnerabilities.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
