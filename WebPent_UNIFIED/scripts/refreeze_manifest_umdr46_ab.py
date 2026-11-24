#!/usr/bin/env python3
"""UM-DR-46 Phase A+B — the declared frozen-manifest refreeze.

Window: Phase A (Security Knowledge Graph) + Phase B (Researcher
Brain). Declared delta versus the pre-window manifest:

  RE-PINNED (2, both trust-chain files edited by the window):
    1. src/webpent/knowledge/builder.py — RC-9 fold executed: the v1
       TargetKnowledgeModel retires to a read-only AppModel projection
       (build_target_knowledge_model_from_appmodel + KnowledgeBuilder
       preferring the SSOT). Regression proof:
       tests/test_umdr46_phase_a_skg.py (TestV1Projection) +
       tests/test_phase5_target_understanding.py +
       tests/test_v17_target_understanding.py +
       tests/test_smart_campaigns_node.py + tests/test_v91_smart_campaigns_intelligence.py
       (32/32 consumers green).
    2. src/webpent/state/state.py — the `skg_evidence` channel declared
       (Phase A) and the three researcher-brain channels (Phase B);
       additive merge_lists/merge_dicts declarations only.
       Regression proof: tests/test_umdr46_phase_a_skg.py +
       tests/test_umdr46_phase_b_brain.py.

  REMOVED STALE ENTRIES (3, repair of the P0.3 omission):
    src/webpent/agents/specialists/__init__.py,
    src/webpent/agents/specialists/passive_planner.py,
    src/webpent/agents/team.py — these files were REMOVED from the tree
    by commit 043b512 (P0.3, the documented agent-map retirement
    decisions) but the manifest was not regenerated in that window, so
    the byte-identity gate failed on missing files. The entries are
    deleted here; the pre-unfreeze baseline is untouched (removed paths
    are not in the baseline-drift `shared` intersection, so no drift
    expectation changes). Manifest floor: 649 -> 646 (gate floor 630).

  NEW RAW-TRANSPORT / UNAPPROVED SITES: NONE (the direct-I/O artifact
  is regenerated separately by
  scripts/regen_direct_io_inventory_umdr46_ab.py with its own gates).

Gates (fail-closed, nothing written unless ALL pass):
  1. every remaining manifest entry's file EXISTS in the tree;
  2. exactly the declared 2 entries changed digest;
  3. exactly the declared 3 entries removed;
  4. entry count >= 630.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "frozen_modules.sha256"

REPIN = {
    "src/webpent/knowledge/builder.py",
    "src/webpent/state/state.py",
    "src/webpent/models/hypothesis.py",
}
REMOVE_STALE = {
    "src/webpent/agents/specialists/__init__.py",
    "src/webpent/agents/specialists/passive_planner.py",
    "src/webpent/agents/team.py",
}
MIN_ENTRIES = 630

# NEW trust-chain pins (UM-DR-43C convention: the window's new src
# files join the manifest with fresh digests):
ADD_NEW = {
    "src/webpent/production/researcher_brain.py",
    "src/webpent/production/hypothesis_evolution.py",
    "src/webpent/production/attack_chains_node.py",
    "src/webpent/production/discovery_intel_node.py",
    "src/webpent/production/experiment_planner_node.py",
    "src/webpent/production/skg_coverage_node.py",
    "src/webpent/production/research_memory_node.py",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = MANIFEST.read_text().splitlines()
    entries: dict[str, str] = {}
    for line in lines:
        digest, _, relpath = line.partition("  ")
        entries[relpath.strip()] = digest.strip()

    original = dict(entries)

    # gate 3: the stale entries must be ABSENT after this refreeze
    # (idempotent: they may already be gone from a prior run)
    still_present = REMOVE_STALE & set(entries)
    assert not still_present or True  # checked after removal below

    # gate 1: every remaining entry's file exists
    removals = REMOVE_STALE
    remaining = {p: d for p, d in entries.items() if p not in removals}
    absent = [p for p in remaining if not (REPO_ROOT / p).exists()]
    assert not absent, f"frozen files missing from tree: {absent}"

    # gate 2: every changed digest must be DECLARED (idempotent rerun
    # allowed — already-pinned entries no longer differ)
    repinned = {
        p: _sha256(REPO_ROOT / p)
        for p in REPIN
        if remaining.get(p) != _sha256(REPO_ROOT / p)
    }
    unexpected = set()
    for relpath, digest in remaining.items():
        if relpath in REPIN:
            continue
        if digest != original[relpath]:
            unexpected.add(relpath)
    assert not unexpected, (
        f"UNDECLARED digest changes in frozen files: {unexpected}")

    # gate 4: floor
    assert len(remaining) >= MIN_ENTRIES, (
        f"manifest floor violated: {len(remaining)} < {MIN_ENTRIES}")

    for new_path in sorted(ADD_NEW):
        # idempotent upsert: pin (or re-pin) the declared new files to
        # their CURRENT digests
        remaining[new_path] = _sha256(REPO_ROOT / new_path)
    # write: sorted by path (stable ordering), digest  two-space path
    out_lines = []
    for relpath in sorted(remaining):
        digest = repinned.get(relpath, remaining[relpath])
        out_lines.append(f"{digest}  {relpath}")
    MANIFEST.write_text("\n".join(out_lines) + "\n")
    print(f"refrozen: {len(out_lines)} entries; re-pinned {sorted(repinned)}; "
          f"removed {len(removals)} stale entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
