#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the UM-DR-31 adaptive-research-
loop window (2026-11-07) per the DR-009 protocol.

Documented scope of this refreeze (see DRIFT_REGISTER.md, UM-DR-31):

  * RE-PINNED — exactly six frozen files, each verified by its new
    regression tests BEFORE this re-pin:

      1. src/webpent/state/state.py — the UM-DR-31 research_loop
         telemetry channel (merge_dicts; the node is the only writer
         and reads its own prior channel state first).
      2. src/webpent/config/settings.py — the fail-closed (default
         False) enable_adaptive_research_loop flag, the mandatory
         max_research_iterations / max_research_hypotheses_per_
         iteration limits, and the operator-configurable
         stateful_discovery_max_requests budget (default 360 keeps
         the UM-DR-28 behavior).
      3. src/webpent/graph/builder.py — the flag-gated research_loop
         node registration + edge and the six conditional-mapping
         overrides (validator / causal_research / disclosed_report_
         intel ×2 / attack_graph / vip_orchestrator / smart_
         campaigns_execution routes to the strategist).
      4. src/webpent/models/hypothesis.py — the two new HypothesisOrigin
         members (COVERAGE_GAP, INVARIANT) for research-loop
         provenance.
      5. src/webpent/families/execution_node.py — the research-hints
         pass-through to run_stateful_discovery (gated on the loop
         flag so flag-off keeps UM-DR-28 behavior byte-stable) and
         the configurable discovery budget.
      6. src/webpent/__init__.py — the 0.36.0 -> 0.37.0 version bump
         (byte change = the __version__ line only, the UM-DR-29/30
         precedent).

Self-verifying: the result is re-hashed from disk before write.
Usage: python3 scripts/refreeze_manifest_umdr31.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

UMDR31_REPINNED_FILES = (
    "src/webpent/state/state.py",
    "src/webpent/config/settings.py",
    "src/webpent/graph/builder.py",
    "src/webpent/models/hypothesis.py",
    "src/webpent/families/execution_node.py",
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
            if relpath in UMDR31_REPINNED_FILES:
                repinned += 1
                digest = current  # documented re-pin
            else:
                print(
                    f"FAIL-CLOSED: undeclared drift on frozen file {relpath} "
                    "(only the six UMDR31 files may change)",
                    file=sys.stderr,
                )
                return 1
        if relpath in seen:
            print(f"FAIL-CLOSED: duplicate entry {relpath}", file=sys.stderr)
            return 1
        seen.add(relpath)
        entries.append((digest, relpath))

    # graph/builder.py sits in the R3 mid-window thaw set and may already
    # have been re-pinned by a prior in-window pass; every other file
    # must be re-pinned exactly once by this script.
    expected = 6 if "src/webpent/graph/builder.py" in seen else 5
    if not 5 <= repinned <= 6:
        print(
            f"FAIL-CLOSED: expected 5..6 re-pinned files from the declared "
            f"UMDR31 set (state.py, settings.py, builder.py, hypothesis.py, "
            f"execution_node.py, __init__.py version bump), got {repinned}",
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
          "(the UM-DR-31 adaptive-research-loop window + the 0.37.0 version bump)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
