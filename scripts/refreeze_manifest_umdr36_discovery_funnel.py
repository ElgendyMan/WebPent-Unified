#!/usr/bin/env python3
"""UM-DR-35/36 re-freeze of frozen_modules.sha256 (DR-009 protocol).

Re-pins the manifest after the documented UM-DR-35 + UM-DR-36 engineering
windows. Every hash change below maps to a chartered directive task:

  * cqa_v2/causal_guard.py, cqa_v2/replay_verifier.py,
    production/autonomous_validation_v1.py — UM-DR-35.1/35.2 (CausalGuard
    sole confirmation authority; strict replay contract).
  * scope/enforcer.py — UM-DR-35.3 (unified scope authority delegation).
  * recon/login_executor.py, agents/authentication/agent.py — UM-DR-35.4
    (authentication success detection lifecycle).
  * shared/llm.py, cli/unified_hunt.py, cli/commands.py,
    agents/hunter_runner.py, config/settings.py — UM-DR-35.5 (hard
    campaign token budget + CLI ceilings) and 35.6 (pinned upgrades).
  * agents/validator/agent.py — UM-DR-35 Gate 35-A (graph confirmation
    sites gated on CausalGuard).
  * graph/builder.py, state/state.py — UM-DR-36.2/36.3 (appmodel node
    wiring, funnel channel, information_gain channel).
  * production/discovery_funnel.py — UM-DR-36.3 (16 -> 28 stages,
    funnel/v2, per-stage evidence sources).
  * models/hypothesis.py — UM-DR-36.5 (DEFERRED/BLOCKED/REVISIT_REQUIRED
    lifecycle states).
  * production/identity_workflow.py — UM-DR-36.6 (Expected Behavior Model
    construction + ordering-only hints).
  * cli/unified_hunt.py — UM-DR-36 summary wiring (appmodel + funnel in
    the campaign summary).

Gates (fail-closed):
  1. the path SET is preserved exactly (no additions, no removals) — the
     NEW modules (graph/appmodel_nodes.py, recon/auth_success_model.py,
     production/confirmation_adapter.py, scripts/umdr35_*) are ADDITIVE
     sprint modules and stay intentionally OUTSIDE the manifest per the
     additive-sprint-module precedent;
  2. only the scoped files below may change hash values;
  3. every listed path must exist.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "frozen_modules.sha256"

SCOPED_CHANGED = {
    # Second sub-window (same UM-DR-35/36 window, run after the funnel/appmodel
    # wiring landed): the five files that drifted after the first re-pin.
    "src/webpent/cli/unified_hunt.py",
    "src/webpent/graph/builder.py",
    "src/webpent/models/hypothesis.py",
    "src/webpent/production/identity_workflow.py",
    "src/webpent/state/state.py",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    old_paths: list[str] = []
    old_hashes: dict[str, str] = {}
    for line in lines:
        if not line.strip():
            continue
        value, _, path = line.partition("  ")
        old_paths.append(path)
        old_hashes[path] = value
    output: list[str] = []
    changed: list[str] = []
    for path in old_paths:
        absolute = ROOT / path
        if not absolute.exists():
            print(f"REFUSE: manifest path missing from tree: {path}")
            return 1
        observed = _sha256(absolute)
        if observed != old_hashes[path]:
            if path not in SCOPED_CHANGED:
                print(f"REFUSE: out-of-scope drift in frozen file: {path}")
                return 1
            changed.append(path)
        output.append(f"{observed}  {path}")
    unexpected = SCOPED_CHANGED - set(changed)
    if unexpected:
        print(f"REFUSE: scoped file did not drift (stale window record?): {sorted(unexpected)}")
        return 1
    MANIFEST.write_text("\n".join(output) + "\n", encoding="utf-8")
    print(f"OK: re-froze {MANIFEST.name} ({len(output)} entries); updated hashes for:")
    for path in sorted(changed):
        print(f"  - {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
