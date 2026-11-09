#!/usr/bin/env python3
"""Generate the replica's compiled spec tables from the committed
ground truth (the server never reads ground truth at runtime)."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
gt = json.loads((ROOT / "benchmarks" / "blind_v3" / "ground_truth.json").read_text())
man = {c["case_id"]: c for c in json.loads(
    (ROOT / "benchmarks" / "blind_v3" / "manifest.json").read_text())["cases"]}

vuln_by_family: dict[str, list[int]] = defaultdict(list)
safe_by_family: dict[str, list[int]] = defaultdict(list)
for cid, g in gt.items():
    path = man[cid]["candidate"]              # e.g. /bv3/rsng/target_41
    n = int(path.rsplit("_", 1)[-1])
    fam = g["case_family"]
    (vuln_by_family if g["expected_label"] == "vulnerable" else safe_by_family)[fam].append(n)

for fam in sorted(vuln_by_family):
    print(f"{fam}: VULN = frozenset({sorted(vuln_by_family[fam])!r})")
    print(f"{fam}: SAFE count = {len(safe_by_family[fam])}")
