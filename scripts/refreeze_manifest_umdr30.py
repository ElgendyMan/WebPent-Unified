#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the UM-DR-30 capability-wiring
window (2026-11-07) per the DR-009 protocol.

Documented scope of this refreeze (see DRIFT_REGISTER.md, UM-DR-30):

  * RE-PINNED — exactly four frozen files, each verified by its new
    regression tests BEFORE this re-pin:

      1. src/webpent/state/state.py — the UM-DR-30 channel contract:
         21 new advisory channels (the family spine's 20 output keys,
         previously silently dropped by LangGraph channel filtering —
         the R2-graph-03 miss class closed for the whole family — plus
         the coverage_gap_report and invariant_review channels).
      2. src/webpent/config/settings.py — the fail-closed (default
         False) enable_coverage_gap_report flag.
      3. src/webpent/graph/builder.py — the flag-gated wiring of the
         coverage_gap_report node between reporter and reflection.
      4. src/webpent/agents/business_logic_fuzzer/agent.py — the
         InvariantChecker wiring inside the workflow enrichment
         (advisory, non-promoting; required_validation names the
         causal-guard evidence contract).

Self-verifying: the result is re-hashed from disk before write.
Usage: python3 scripts/refreeze_manifest_umdr30.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

UMDR30_REPINNED_FILES = (
    "src/webpent/state/state.py",
    "src/webpent/config/settings.py",
    "src/webpent/graph/builder.py",
    "src/webpent/agents/business_logic_fuzzer/agent.py",
    # the same window's release-candidate version bump: 0.35.0 -> 0.36.0
    # in the frozen package root (byte change = the __version__ line
    # only, the UM-DR-29 precedent).
    "src/webpent/__init__.py",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    entries: list[tuple[str, str]] = []
    repinned = 0
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, relpath = line.partition(" ")
        relpath = relpath.strip()
        absolute = REPO / relpath
        if not absolute.exists():
            print(f"FAIL-CLOSED: manifest entry missing from tree: {relpath}", file=sys.stderr)
            return 1
        current = sha256(absolute)
        if current != digest:
            if relpath in UMDR30_REPINNED_FILES:
                repinned += 1
                digest = current  # documented re-pin
            else:
                print(
                    f"FAIL-CLOSED: undeclared drift on frozen file {relpath} "
                    "(only the five UMDR30 files may change)",
                    file=sys.stderr,
                )
                return 1
        if relpath in seen:
            print(f"FAIL-CLOSED: duplicate entry {relpath}", file=sys.stderr)
            return 1
        seen.add(relpath)
        entries.append((digest, relpath))

    # The manifest may be re-pinned in more than one pass within this
    # window (the wiring files first, the version bump second): accept
    # 1..5 re-pins — the per-file allowlist above plus the final
    # self-check (every entry re-hashed from disk) guarantee the end
    # state: all five files pinned to their current content.
    if not 1 <= repinned <= 5:
        print(
            f"FAIL-CLOSED: expected 1..5 re-pinned files from the declared "
            f"UMDR30 set (state.py, settings.py, builder.py, "
            f"business_logic_fuzzer/agent.py, __init__.py version bump), "
            f"got {repinned}",
            file=sys.stderr,
        )
        return 1
    if len(entries) < 630:
        print(
            f"FAIL-CLOSED: manifest floor violated ({len(entries)} < 630)",
            file=sys.stderr,
        )
        return 1

    # self-check: re-hash every kept entry from disk before write
    for digest, relpath in entries:
        if sha256(REPO / relpath) != digest:
            print(f"FAIL-CLOSED: self-check mismatch for {relpath}", file=sys.stderr)
            return 1

    MANIFEST.write_text(
        "\n".join(f"{digest}  {relpath}" for digest, relpath in entries) + "\n",
        encoding="utf-8",
    )
    print(f"OK: {len(entries)} entries unchanged in count, {repinned} re-pinned "
          "(the UM-DR-30 capability-wiring window + the 0.36.0 version bump)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
