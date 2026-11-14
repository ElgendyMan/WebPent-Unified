#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the UM-DR-28 production
discovery-integration window (2026-11-07) per the DR-009 protocol.
DRIFT_REGISTER entry: UM-DR-28.

The window declares EXACTLY these frozen-tree changes (each verified by
new regression tests run BEFORE this refreeze —
tests/test_umdr28_representation_oracle.py [23],
tests/test_umdr28_stateful_discovery.py [15],
tests/test_umdr28_campaign_stateful_e2e.py [10], plus the byte-compat
regressions tests/test_blind_v3_replica.py +
tests/test_transition_sources.py [47] all green):

  - src/webpent/cqa_v2/causal_guard.py
    (UM-DR-28 representation-equivalence repair: the four context
    channels that were header-ONLY — effective_privilege,
    effective_privilege_granted, authorization_outcome, data_redacted —
    gain the same top-level observation fallback every other channel
    already had. Headers still win (checked first). This closes the
    comparator-oracle miss class: a body-represented authorization
    outcome was invisible to the guard even after the (non-frozen)
    observation layer surfaced it. The guard's verdict branches,
    thresholds, and confirmation logic are untouched.)

  - src/webpent/config/settings.py
    (UM-DR-28: the ``enable_stateful_discovery`` flag — fail-closed
    default False, consumed inside the wired family_execution node)

  - src/webpent/families/execution_node.py
    (UM-DR-28: step 4c — flag-gated, fail-soft invocation of
    production/stateful_discovery.run_stateful_discovery with the same
    executor the family plans use; CONFIRMED outcomes extend
    promoted_findings and pass the SAME adversarial review +
    self-verify as every other finding; the node's output gains the
    ``stateful_discovery`` summary key, including on the
    no_input_surface early return)

  - src/webpent/state/state.py
    (UM-DR-28: the ``stateful_discovery`` PentestState channel
    declaration — the R2-graph-03 lesson: an undeclared key is
    silently dropped by LangGraph channel filtering and the campaign
    report never sees it)

  * NO manifest-path removals; NO scope completions (the new modules
    cqa_v2/representation_oracle.py, production/stateful_discovery.py,
    and the new test/fixture files are OUTSIDE the frozen gate by
    construction);
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_umdr28_stateful_discovery.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

WINDOW_REMOVED_FILES: list[str] = []
WINDOW_SCOPE_COMPLETION: list[str] = []

# Run AFTER the edits — hashes re-read from the current tree.
WINDOW_CHANGED_FILES = [
    "src/webpent/cqa_v2/causal_guard.py",
    "src/webpent/config/settings.py",
    "src/webpent/families/execution_node.py",
    "src/webpent/state/state.py",
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

    out_lines: list[str] = []
    changed_count = 0
    for digest, relpath in entries:
        absolute = REPO / relpath
        if not absolute.is_file():
            print(f"ABORT: pinned file missing from tree: {relpath}", file=sys.stderr)
            return 1
        new_digest = sha256(absolute)
        if new_digest != digest:
            if relpath not in WINDOW_CHANGED_FILES and relpath not in WINDOW_SCOPE_COMPLETION:
                print(
                    f"ABORT: undeclared change detected in pinned file: {relpath}",
                    file=sys.stderr,
                )
                return 1
            changed_count += 1
            print(f"  re-pinned: {relpath}")
        out_lines.append(f"{new_digest}  {relpath}")

    # Self-check: exactly the declared window drifted.
    if changed_count != len(WINDOW_CHANGED_FILES):
        print(
            f"ABORT: expected exactly {len(WINDOW_CHANGED_FILES)} re-pinned "
            f"entries, found {changed_count}",
            file=sys.stderr,
        )
        return 1
    if len(out_lines) != len(entries):
        print("ABORT: output line count mismatch", file=sys.stderr)
        return 1

    MANIFEST.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    # Post-write self-check: re-read and verify every entry byte-identical.
    verification_failures: list[str] = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, relpath = line.split(None, 1)
        absolute = REPO / relpath.strip()
        if not absolute.is_file() or sha256(absolute) != digest:
            verification_failures.append(relpath.strip())
    if verification_failures:
        print(
            f"ABORT: post-write self-check failed for: {verification_failures}",
            file=sys.stderr,
        )
        return 1

    print(f"OK: manifest re-frozen with exactly {changed_count} declared changes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
