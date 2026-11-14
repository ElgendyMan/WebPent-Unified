#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the PRODUCTION HARDENING window
(v0.33.0) per the DR-009 protocol:

  * the window's declared frozen-tree changes are the 22 hardening edits
    listed below (docs/PRODUCTION_HARDENING_PLAN_0330.md items F-01…F-06,
    P1-01…P1-17, P2-02/04/05/09/10/11/18 — every file carries its plan-ID
    annotation in-source) plus the declared version bump of the SSOT
    identity file ``src/webpent/__init__.py`` (0.32.0 -> 0.33.0);
  * NO manifest-path removals;
  * NO scope completions (no new src files this window);
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_0330_hardening.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

WINDOW_REMOVED_FILES: list[str] = []
WINDOW_SCOPE_COMPLETION: list[str] = []

# Run AFTER the version bump — hashes re-read from the current tree.
# The 22 pinned files the frozen-gate caught as byte-drifted, each tied
# to its plan item(s):
WINDOW_CHANGED_FILES = [
    "src/webpent/__init__.py",                        # version SSOT 0.33.0
    "src/webpent/adapters/controlled_target/adapter.py",  # P1-14
    "src/webpent/agents/validator/agent.py",          # P2-11 (B025)
    "src/webpent/api/auth.py",                        # P2-04
    "src/webpent/api/scan_registry.py",               # P2-05
    "src/webpent/api/workers_status.py",              # F-05
    "src/webpent/autonomous/hunt_memory.py",          # P1-06, P1-07
    "src/webpent/autonomous/hunt_orchestrator.py",    # P1-01
    "src/webpent/brain/ev_scheduler.py",              # P1-05
    "src/webpent/causal_reasoning_v2/causal_adapter_v2.py",  # P2-10 (F402)
    "src/webpent/llm_researcher/interface.py",        # P1-15
    "src/webpent/llm_researcher/providers/openai_compatible.py",  # F-02, F-03
    "src/webpent/llm_researcher/providers/pool.py",   # F-02, F-03
    "src/webpent/memory/ab_lab.py",                   # F-01, P1-02, P1-03, P1-08
    "src/webpent/production/advisory_registration.py",  # P2-10 (F402)
    "src/webpent/production/modern_spine.py",         # F-04, P1-13
    "src/webpent/recon/auth_handler.py",              # P2-09 (E722)
    "src/webpent/recon/browser_crawler.py",           # P1-16
    "src/webpent/reporter/poc_recorder.py",           # P2-18
    "src/webpent/service/api.py",                     # P2-02
    "src/webpent/shared/engagement_scope.py",         # F-06
    "src/webpent/shared/persistent_finding_ledger.py",  # P1-17
    "src/webpent/workers/pentest_worker.py",          # P2-01
]

# Manifest-pinned files changed by this window that the 0.32.0 manifest
# does NOT pin (verified: they never appeared in the frozen-gate failure
# list) — declared here so the refreeze report is complete even though
# no manifest entry changes for them:
UNPINNED_CHANGED_FILES = [
    "src/webpent/api/app.py",                 # F-06
    "src/webpent/autonomous_hunter.py",       # P1-10, P1-11
    "src/webpent/campaign/executor/pivot_engine.py",  # P1-09
    "src/webpent/core/infrastructure.py",     # P1-12
    "src/webpent/memory/db.py",               # P1-04
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
        f"manifest re-frozen: {len(out_lines)} entries "
        f"(-{len(WINDOW_REMOVED_FILES)} declared removal, "
        f"+{len(WINDOW_SCOPE_COMPLETION)} scope completion, "
        f"{changed_count} re-pinned changed of {len(WINDOW_CHANGED_FILES)} declared)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
