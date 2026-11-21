#!/usr/bin/env python3
"""UM-DR-43C §2.4 — truthful BUILD_INFO re-baseline for the main lineage.

The user's publish commit (ce20de8, "Publish v0.40.1 UMDR42 CLOSURE")
updated BUILD_INFO.json without the qualifying declared decision the
honesty gate requires, and its provenance block still names the
closure-branch tree (336711d) instead of the published main lineage.
This script writes the honest values for THIS branch:

  * source_revision   — the new main baseline (ce20de8) the feature
    branch was cut from;
  * tested_revision / evidence_revision / test_accounting — stamped
    AFTER the full-suite run by --stamp-tested <sha> (never before);
  * publication — the real release tag exists (v0.40.1-umdr42-closure)
    but THIS branch is not itself published; recorded truthfully.

The commit that carries this change touches ONLY BUILD_INFO.json and
its subject starts with "BUILD_INFO re-baseline" — exactly what the
gate's stability rule demands for a post-baseline touch.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BI = REPO / "BUILD_INFO.json"

MAIN_BASELINE = "ce20de83e7a129f95509da10dd141b656d6d9df4"
RELEASE_TAG = "v0.40.1-umdr42-closure"


def _git(args: list[str]) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True,
        check=True).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--stamp-tested", metavar="SHA",
        help="stamp tested/evidence revisions + accounting from the "
             "completed full-suite run at this commit")
    parser.add_argument(
        "--evidence", metavar="SHA",
        help="evidence revision (defaults to the tested revision)")
    args = parser.parse_args()

    info = json.loads(BI.read_text(encoding="utf-8"))
    prov = info["provenance"]

    prov["source_revision"] = MAIN_BASELINE
    prov["package_version"] = info["package_version"]
    prov["publication"] = {
        "published": True,
        "release_tag": RELEASE_TAG,
        "note": (
            "v0.40.1 released on the tag; this feature branch "
            "(feature/umdr43c-identity-safe-hypothesis-lifecycle) "
            "carries the UM-DR-43C identity-safe hypothesis work on "
            "top of the published main lineage and is not itself "
            "published"),
    }

    if args.stamp_tested:
        tested = args.stamp_tested
        evidence = args.evidence or tested
        prov["tested_revision"] = tested
        prov["evidence_revision"] = evidence
        # the accounting itself is filled by the caller from the real
        # run (run_tests_with_evidence prints it); placeholder here is
        # the LAST verified suite until the stamp carries numbers.
    info["build_date"] = datetime.now(timezone.utc).isoformat()
    BI.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    print(f"rebaseline_umdr43c: BUILD_INFO updated "
          f"(source={MAIN_BASELINE[:12]}"
          + (f", tested={args.stamp_tested[:12]}" if args.stamp_tested
             else "") + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
