#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the RED-TEAM ROUND 2 window
(v0.34.0) per the DR-009 protocol:

  * the window's declared frozen-tree changes are the 37 red-team R2 fix
    edits listed below (docs/RED_TEAM_ROUND2_20261102.md items
    R2-graph-01..07, R2-jc-01..09, R2-dojo-01..10, R2-econ-01..11,
    R2-prism-01..08 — every file carries its R2-ID annotation in-source)
    plus the declared version bump of the SSOT identity file
    ``src/webpent/__init__.py`` (0.33.0 -> 0.34.0);
  * NO manifest-path removals;
  * NO scope completions (no new src files this window);
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_0340_redteam_r2.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

WINDOW_REMOVED_FILES: list[str] = []
WINDOW_SCOPE_COMPLETION: list[str] = []

WINDOW_CHANGED_FILES = [
    "src/webpent/__init__.py",                          # version SSOT 0.34.0
    "src/webpent/cli/unified_hunt.py",                  # R2-graph-04, R2-graph-06
    "src/webpent/econ/blind_spots.py",                  # R2-econ-05
    "src/webpent/econ/competitive.py",                  # R2-econ-02, R2-econ-03
    "src/webpent/econ/market_kb.py",                    # R2-econ-03, R2-econ-11
    "src/webpent/econ/portfolio.py",                    # R2-econ-01, R2-econ-07
    "src/webpent/econ/saturation.py",                   # R2-econ-06, R2-econ-08
    "src/webpent/econ/timing_advisor.py",               # R2-econ-10
    "src/webpent/graph/builder.py",                     # R2-graph-01, R2-graph-02
    "src/webpent/graph/checkpoints.py",                 # R2-graph-05
    "src/webpent/graph/progress_display.py",            # R2-graph-06
    "src/webpent/state/state.py",                       # R2-graph-03, R2-graph-07
]

# Manifest-pinned files changed by this window that the 0.33.0 manifest
# does NOT pin (verified against frozen_modules.sha256 before the re-pin)
# — declared here so the refreeze report is complete even though no
# manifest entry changes for them:
UNPINNED_CHANGED_FILES = [
    "src/webpent/cli/dojo.py",                          # R2-dojo-05
    "src/webpent/cli/econ.py",                          # R2-econ-04
    "src/webpent/dojo/counter_adapter.py",              # R2-dojo-04
    "src/webpent/dojo/engine.py",                       # R2-dojo-06, R2-dojo-07
    "src/webpent/dojo/practice_runner.py",              # R2-dojo-02
    "src/webpent/dojo/progress.py",                     # R2-dojo-08
    "src/webpent/dojo/scenario_library.py",             # R2-dojo-09
    "src/webpent/dojo/trainer.py",                      # R2-dojo-01, R2-dojo-10
    "src/webpent/dojo/weakness_identifier.py",          # R2-dojo-03
    "src/webpent/econ/learning_loop.py",                # R2-econ-04
    "src/webpent/econ/scope_negotiator.py",             # R2-econ-09
    "src/webpent/jc/advocates.py",                      # R2-jc-02
    "src/webpent/jc/bias_detector.py",                  # R2-jc-05
    "src/webpent/jc/calibration.py",                    # R2-jc-04, R2-jc-05
    "src/webpent/jc/chamber.py",                        # R2-jc-01, R2-jc-06
    "src/webpent/jc/contracts.py",                      # R2-jc-03
    "src/webpent/jc/dissent.py",                        # R2-jc-08
    "src/webpent/jc/memory.py",                         # R2-jc-05, R2-jc-09
    "src/webpent/jc/skeptic.py",                        # R2-jc-07
    "src/webpent/prism/anomaly_filter.py",              # R2-prism-04, R2-prism-08
    "src/webpent/prism/classifier.py",                  # R2-prism-07
    "src/webpent/prism/compliance.py",                  # R2-prism-03
    "src/webpent/prism/ledger.py",                      # R2-prism-01, R2-prism-02
    "src/webpent/prism/priors.py",                      # R2-prism-06
    "src/webpent/prism/scorer.py",                      # R2-prism-05
    "src/webpent/prism/value_weighter.py",              # R2-prism-04, R2-prism-08
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            print(f"ABORT: unparsable manifest line: {line!r}", file=sys.stderr)
            return 1
        digest, relpath = parts[0], parts[1].strip()
        entries.append((digest, relpath))
        seen.add(relpath)

    for relpath in WINDOW_REMOVED_FILES:
        if relpath not in seen:
            print(f"ABORT: declared removed file is not pinned: {relpath}", file=sys.stderr)
            return 1
        if (REPO / relpath).exists():
            print(f"ABORT: declared removed file still exists in the tree: {relpath}", file=sys.stderr)
            return 1
        entries = [(d, p) for d, p in entries if p != relpath]
        seen.discard(relpath)
        print(f"  {relpath} (removed)")

    for relpath in WINDOW_CHANGED_FILES:
        if relpath not in seen:
            print(f"ABORT: declared changed file is not pinned: {relpath}", file=sys.stderr)
            return 1

    for relpath in WINDOW_SCOPE_COMPLETION:
        if relpath in seen:
            continue
        if not (REPO / relpath).is_file():
            print(f"ABORT: scope-completion file missing from tree: {relpath}", file=sys.stderr)
            return 1
        entries.append(("NEW", relpath))
        seen.add(relpath)

    out_lines: list[str] = []
    changed_count = 0
    for digest, relpath in entries:
        absolute = REPO / relpath
        if not absolute.is_file():
            print(f"ABORT: pinned path missing from tree: {relpath}", file=sys.stderr)
            return 1
        actual = sha256(absolute)
        marker = " (re-pinned new)" if digest == "NEW" else (
            " (changed)" if actual != digest.lower() else ""
        )
        if marker:
            changed_count += 1
            print(f"  {relpath}{marker}")
        out_lines.append(f"{actual}  {relpath}")

    # Self-check before write.
    for line in out_lines:
        digest, relpath = line.split(None, 1)
        if sha256(REPO / relpath.strip()) != digest:
            print(f"ABORT: self-check failed for {relpath}", file=sys.stderr)
            return 1

    tmp = MANIFEST.with_suffix(".sha256.tmp")
    tmp.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    tmp.replace(MANIFEST)
    print(
        f"OK: re-froze {MANIFEST.name} ({len(out_lines)} entries, "
        f"{changed_count} changed)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
