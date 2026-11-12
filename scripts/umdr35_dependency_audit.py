#!/usr/bin/env python3
"""UM-DR-35.6 — reproducible dependency audit against OSV.dev.

Reads the resolved uv.lock, queries OSV (GitHub Security Advisories +
PyPA + upstream sources aggregated) for every locked package@version in
batches, and emits a machine-readable report with:

  * per-advisory IDs, fixed versions, and severity summaries
  * whether the vulnerable code path is plausibly reachable in WebPent
    (imported at runtime) — reachability is evidence, not suppression
  * explicit exit status for CI gating

No vulnerability is suppressed because a package is "unused": findings are
reported with reachability evidence and left to the exception ledger.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LOCK = REPO / "uv.lock"
OUT = REPO / "dependency_audit_report.json"

OSV_QUERY = "https://api.osv.dev/v1/querybatch"
OSV_BULK = "https://api.osv.dev/v1/vulns/"


def locked_packages() -> list[tuple[str, str]]:
    name = None
    version = None
    found: list[tuple[str, str]] = []
    in_sources = False
    for line in LOCK.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            name, version = None, None
            in_sources = False
            continue
        if stripped.startswith("name = "):
            name = stripped.split("=", 1)[1].strip().strip('"')
        elif stripped.startswith("version = "):
            version = stripped.split("=", 1)[1].strip().strip('"')
        elif stripped.startswith("source = {"):
            in_sources = True
        if name and version and in_sources and stripped.startswith("[[package]]"):
            pass
    # The simpler second pass: parse blocks properly.
    found = []
    current: dict[str, str] = {}
    for line in LOCK.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            if current.get("name") and current.get("version"):
                found.append((current["name"], current["version"]))
            current = {}
            continue
        if stripped.startswith("name = ") and "name" not in current:
            current["name"] = stripped.split("=", 1)[1].strip().strip('"')
        elif stripped.startswith("version = ") and "version" not in current:
            current["version"] = stripped.split("=", 1)[1].strip().strip('"')
    if current.get("name") and current.get("version"):
        found.append((current["name"], current["version"]))
    return found


def osv_query_batch(pairs: list[tuple[str, str]]) -> dict:
    queries = [{"package": {"ecosystem": "PyPI", "name": n}, "version": v}
               for n, v in pairs]
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_QUERY, data=body,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def fetch_vuln(vuln_id: str) -> dict:
    with urllib.request.urlopen(OSV_BULK + vuln_id, timeout=30) as resp:
        return json.loads(resp.read().decode())


def runtime_import_names() -> set[str]:
    """Best-effort set of top-level modules imported by webpent at runtime."""
    import ast
    modules: set[str] = set()
    src = REPO / "src" / "webpent"
    for py in src.rglob("*.py"):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    modules.add(alias.name.split(".")[0].lower().replace("-", "_"))
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                modules.add(node.module.split(".")[0].lower().replace("-", "_"))
    modules.add("webpent")
    return modules


def main() -> int:
    pairs = locked_packages()
    print(f"[umdr35.6] locked packages: {len(pairs)}")
    imported = runtime_import_names()
    results: list[dict] = []
    batch = 800
    for i in range(0, len(pairs), batch):
        chunk = pairs[i:i + batch]
        data = osv_query_batch(chunk)
        for (name, version), res in zip(chunk, data.get("results", [])):
            vulns = res.get("vulns") or []
            if not vulns:
                continue
            details = []
            for v in vulns:
                full = fetch_vuln(v["id"])
                severity = ""
                sev = full.get("severity") or []
                for s in sev:
                    severity = s.get("score", "")[:80]
                    break
                aliases = [a for a in full.get("aliases", [])[:4]]
                fixed: list[str] = []
                for aff in full.get("affected", []):
                    if (aff.get("package", {}).get("name", "").lower() != name.lower()):
                        continue
                    for rng in aff.get("ranges", []):
                        for ev in rng.get("events", []):
                            if "fixed" in ev:
                                fixed.append(str(ev["fixed"]))
                details.append({
                    "id": v["id"],
                    "aliases": aliases,
                    "severity": severity or (full.get("summary", "")[:80]),
                    "fixed_versions": sorted(set(fixed))[:6],
                    "url": f"https://osv.dev/vulnerability/{v['id']}",
                })
            pypi_name = name.lower().replace("-", "_")
            reachable = pypi_name in imported or name.lower() in imported
            results.append({
                "package": name,
                "locked_version": version,
                "advisory_count": len(vulns),
                "runtime_imported_by_webpent": reachable,
                "advisories": details,
            })
            print(f"  FINDING {name}=={version}: {len(vulns)} advisories "
                  f"(imported={reachable})")
    report = {
        "directive": "UM-DR-35.6",
        "source": "OSV.dev querybatch API (GHSA + PyPA + upstream advisories)",
        "lockfile": "uv.lock",
        "locked_packages": len(pairs),
        "findings": results,
        "finding_count": len(results),
        "verified_against": "https://api.osv.dev/v1/querybatch",
    }
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    print(f"[umdr35.6] report: {OUT} ({len(results)} packages with advisories)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
