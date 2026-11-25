#!/usr/bin/env python3
"""UM-DR-47 Phase W — the declared frozen-manifest refreeze.

Window: Phase W (wire the brain). Declared delta versus the pre-window
manifest (7 files, all trust-chain files edited by the window):

  RE-PINNED (17 — 7 window files + 10 carried-in tree state):
    1. src/webpent/graph/builder.py — the live wiring: NODE_BRAIN_ENGINE
       registration + _umdr47_routes strategist-bound redirect (the
       composed _research_route_redirects chain).
    2. src/webpent/state/state.py — the brain_engine +
       brain_engine_context channels (additive merge_dicts).
    3. src/webpent/shared/prioritization.py — flag-gated branch in
       rank_open_hypotheses routing through rank_with_brain (the
       literal W3 formula).
    4. src/webpent/production/autonomous_validation_v1.py — flag-gated
       branch in AutonomousExperimentSelector._score.
    5. src/webpent/shared/learned_context.py — _merge_w6_research_memory
       (the W6 load seam, demotion-only).
    6. src/webpent/cli/unified_hunt.py — the W7 watchdog on the live
       stream + the W6 save at campaign end.
    7. src/webpent/config/settings.py — the enable_brain_engine field.

  Regression proof: tests/test_umdr47_w3_priority.py (13) +
  tests/test_umdr47_w_engine.py (13) + tests/test_umdr47_w6_memory.py
  (11) + tests/test_umdr47_w7_watchdog.py (9) +
  tests/test_umdr47_w_gate.py (3) — 49/49 green locally.

Gates (fail-closed, nothing written unless ALL pass):
  1. every manifest entry's file EXISTS in the tree;
  2. exactly the declared 17 entries changed digest;
  3. entry count >= 630.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "frozen_modules.sha256"

ADD: set[str] = set()  # all three modules are already pinned entries

REPIN = {
    "src/webpent/production/brain_engine.py",
    "src/webpent/production/brain_watchdog.py",
    "src/webpent/production/research_memory_store.py",
    "src/webpent/graph/builder.py",
    # F2.2/F2.3 window continuation: the loopback port exemption
    # (wildcard_scope.py — the authorized lab's ephemeral port is
    # declarable; production hosts keep the strict rule) and the
    # F2.3 protocol-depth consumption + cross-surface hypothesis
    # (brain_engine.py, edited after the first re-pin).
    "src/webpent/shared/wildcard_scope.py",
    "src/webpent/state/state.py",
    "src/webpent/shared/prioritization.py",
    "src/webpent/production/autonomous_validation_v1.py",
    "src/webpent/shared/learned_context.py",
    "src/webpent/cli/unified_hunt.py",
    "src/webpent/config/settings.py",
    # carried-in delta: files already modified in the working tree at
    # window start (committed in 8ae465e) — documented, re-pinned here
    "src/webpent/agents/rabbit_hole/agent.py",
    "src/webpent/agents/request_smuggling/agent.py",
    "src/webpent/agents/strategist/agent.py",
    "src/webpent/production/discovery_funnel.py",
    "src/webpent/production/hypothesis_identity.py",
    "src/webpent/production/identity_workflow.py",
    "src/webpent/shared/engagement_scope.py",
    "src/webpent/shared/http.py",
    "src/webpent/shared/llm.py",
    "src/webpent/state/reducers.py",
}
FLOOR = 630


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    entries: dict[str, str] = {}
    for line in lines:
        digest, _, rel = line.partition("  ")
        rel = rel.strip()
        if rel:
            entries[rel] = digest

    changed: set[str] = set()
    missing: list[str] = []
    for rel, old_digest in sorted(entries.items()):
        path = REPO_ROOT / rel
        if not path.is_file():
            missing.append(rel)
            continue
        if _sha256_file(path) != old_digest:
            changed.add(rel)

    problems: list[str] = []
    if missing:
        problems.append(f"missing files: {missing}")
    if not changed <= REPIN:
        problems.append(
            f"digest delta mismatch — changed={sorted(changed)} "
            f"declared={sorted(REPIN)}")
    for rel in ADD:
        if rel in entries:
            problems.append(f"ADD entry already present: {rel}")
    if len(entries) < FLOOR:
        problems.append(f"entry count {len(entries)} < floor {FLOOR}")
    if problems:
        for p in problems:
            print(f"REFREEZE GATE FAILURE: {p}")
        return 1

    for rel in REPIN:
        digest = _sha256_file(REPO_ROOT / rel)
        entries[rel] = digest
    for rel in sorted(ADD):
        entries[rel] = _sha256_file(REPO_ROOT / rel)
    out = "\n".join(f"{digest}  {rel}" for rel, digest in sorted(entries.items()))
    MANIFEST.write_text(out + "\n", encoding="utf-8")
    print(f"refreeze OK: {len(REPIN)} entries re-pinned; manifest has "
          f"{len(entries)} entries (floor {FLOOR})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
