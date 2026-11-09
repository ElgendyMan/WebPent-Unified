from __future__ import annotations

import json
from pathlib import Path

report = json.loads(Path("pip-audit-v63-locked.json").read_text(encoding="utf-8"))
for item in report.get("dependencies", []):
    vulns = item.get("vulns", [])
    if vulns:
        print(item["name"], item["version"])
        for vuln in vulns:
            print(
                "  ",
                vuln.get("id"),
                "fix_versions=",
                vuln.get("fix_versions", []),
            )
