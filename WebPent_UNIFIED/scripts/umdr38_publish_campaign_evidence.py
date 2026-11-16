#!/usr/bin/env python3
"""UM-DR-38 §7.1 — publish the durable release-evidence set.

The historical problem: campaign scripts write machine-readable records
under ``artifacts/`` while ``.gitignore`` excludes most of that
directory, so the PUBLISHED repository lost the campaign evidence even
though reports claimed successful campaigns. This script publishes the
complete evidence set to the DEDICATED, TRACKED release-evidence path
``deliverables/umdr37/evidence/`` — with a SHA-256 digest for every
file and the exact source revision — without adding broad exceptions to
``.gitignore`` and without tracking runtime databases, cookies,
credentials or temporary campaign output (the campaign records are
already redacted, §7.2.F).
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PUB = Path(__file__).resolve().parents[2]
OUT = PUB / "deliverables" / "umdr37" / "evidence"

# (source, published-name, what it is) — every entry is real evidence
# regenerated at the release revision (or a tracked umdr37 record that
# survived publication under docs/).
EVIDENCE_SET = [
    ("artifacts/umdr37_production_campaigns.json",
     "umdr37_production_campaigns.json",
     "combined record of the three production campaigns (Phase 8) — "
     "requests, findings, CausalGuard verdicts, ProofBundle ids, "
     "replay verifications, negative controls, out-of-scope request "
     "log, authoritative final-state funnel"),
    ("artifacts/umdr37_production_campaign_run1.json",
     "umdr37_production_campaign_run1.json",
     "campaign 1 raw run record"),
    ("artifacts/umdr37_production_campaign_run2.json",
     "umdr37_production_campaign_run2.json",
     "campaign 2 raw run record"),
    ("artifacts/umdr37_production_campaign_run3.json",
     "umdr37_production_campaign_run3.json",
     "campaign 3 raw run record"),
    ("artifacts/umdr37_full_loop_learning.json",
     "umdr37_full_loop_learning.json",
     "four-arm full-loop learning proof (evidence channel changes a "
     "real decision; six-step chain held; ground truth confirmed only "
     "with evidence)"),
    ("artifacts/umdr37_learning_ablation.json",
     "umdr37_learning_ablation.json",
     "selector-level learning ablation (two-layer honest verdict; "
     "unit-level causal chain proven by the pinned test)"),
    ("artifacts/umdr37_graph_trace_after.json",
     "umdr37_graph_trace_after.json",
     "root-cause production campaign graph trace (after the fixes: "
     "endpoints, findings, guard calls, drop-offs)"),
    ("docs/UMDR37_FULL_LOOP_LEARNING.json",
     "UMDR37_FULL_LOOP_LEARNING.json",
     "tracked copy of the full-loop record"),
    ("docs/UMDR37_LEARNING_ABLATION.json",
     "UMDR37_LEARNING_ABLATION.json",
     "tracked copy of the ablation record (the published file was a "
     "missing-stub; replaced by the regenerated real record)"),
    ("docs/UMDR37_DISCOVERY_EFFICIENCY.json",
     "UMDR37_DISCOVERY_EFFICIENCY.json",
     "discovery-efficiency metrics from the release-revision campaigns"),
    ("docs/UMDR37_PRODUCTION_CAMPAIGN.json",
     "UMDR37_PRODUCTION_CAMPAIGN.json",
     "tracked combined campaign record (the published file was a "
     "missing-stub; replaced by the regenerated real record)"),
    ("docs/UMDR37_DECOY_CLOSURE.json",
     "UMDR37_DECOY_CLOSURE.json",
     "decoy exposure and closure (decoy unconfirmed; per-campaign "
     "decoy invariants also live inside the campaign records)"),
    ("docs/UMDR37_CONFIRMATION_CHAIN.json",
     "UMDR37_CONFIRMATION_CHAIN.json",
     "the confirmation authority chain record (CausalGuard -> "
     "ProofBundle -> replay)"),
    ("docs/UMDR37_GRAPH_TRACE.json",
     "UMDR37_GRAPH_TRACE.json",
     "the umdr37-era graph trace record (tracked)"),
    ("docs/UMDR37_MULTI_FAMILY_RESULTS.json",
     "UMDR37_MULTI_FAMILY_RESULTS.json",
     "multi-family validation results (controlled scope)"),
    ("docs/UMDR37_STAGE_METRICS.json",
     "UMDR37_STAGE_METRICS.json",
     "discovery stage metrics (tracked)"),
]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    missing = [(src, name) for src, name, _ in EVIDENCE_SET
               if not (REPO / src).is_file()]
    if missing:
        print("REFUSED — missing source artifacts (never publish an "
              "incomplete evidence set):", file=sys.stderr)
        for src, name in missing:
            print(f"  - {src} (would be {name})", file=sys.stderr)
        return 1
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
        text=True, check=False).stdout.strip()

    OUT.mkdir(parents=True, exist_ok=True)
    digests = []
    manifest = {
        "schema": "umdr38-release-evidence/v1",
        "published_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_commit": commit,
        "policy": (
            "durable release evidence under deliverables/umdr37/evidence/"
            " — tracked in git, one SHA-256 per file; runtime artifacts/"
            " stays ignored. All campaign records are redacted (§7.2.F); "
            "no cookies, credentials or runtime databases are published"),
        "files": [],
    }
    for src, name, description in EVIDENCE_SET:
        source = REPO / src
        target = OUT / name
        target.write_bytes(source.read_bytes())
        digest = _sha256(target)
        digests.append(f"{digest}  {name}")
        manifest["files"].append({
            "file": name, "source": src, "sha256": digest,
            "description": description})
    (OUT / "SHA256SUMS.txt").write_text(
        "\n".join(digests) + "\n", encoding="utf-8")
    (OUT / "EVIDENCE_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, default=str) + "\n",
        encoding="utf-8")
    print(f"[evidence] {len(digests)} files -> {OUT}")
    print(f"[evidence] source commit: {commit}")
    for entry in manifest["files"][:4]:
        print(f"  {entry['sha256'][:16]}…  {entry['file']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
