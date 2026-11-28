#!/usr/bin/env python3
"""UM-DR-52 — the declared frozen-manifest refreeze.

Window: the behavioral reasoning layer (W1) + the adaptive engine
(W2). Declared delta versus the pre-window manifest:

  RE-PINNED (3, all files edited by the window, each re-pinned AFTER
  its changes were verified by the window's regression suites):
    1. src/webpent/production/brain_engine.py — the behavioral
       evidence wiring (ctx.behavioral + estimate_priority_inputs
       behavioral terms + invariant-spec pool injection). Regression
       proof: tests/test_umdr52_w1_behavioral.py (19/19).
    2. src/webpent/shared/prioritization.py — the brain decision map
       (priority_score + p/(p+k), the literal-priority contract).
       Regression proof: tests/test_umdr52_w1_behavioral.py (19/19)
       + the full battery (5 failures = re-bind gates, see
       BUILD_INFO suite_evidence).
    3. src/webpent/agents/strategist/agent.py — the priority_score
       handoff into recommend_action (the brain DECIDES, not only
       orders). Regression proof: same suites.

  NEW PINS: none — researcher/behavioral_layer.py and
  researcher/adaptive_engine.py are pure in-memory modules (no I/O,
  no transport; isolation asserted by their suites) and join the
  researcher package, which is not part of the frozen trust chain.

  REMOVED STALE ENTRIES: NONE.
  MIN_ENTRIES: unchanged floor (the gate's existing floor applies).

Gates (fail-closed, nothing written unless ALL pass): every remaining
entry's file exists; every digest change is DECLARED; no declared
repin without drift; no removal; manifest floor holds.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "frozen_modules.sha256"

REPINS = {
    # --- UM-DR-52 edits (declared by THIS window) ---
    "src/webpent/production/brain_engine.py": (
        "umdr52_w1_behavioral_evidence_wiring"),
    "src/webpent/shared/prioritization.py": (
        "umdr52_w1_brain_decision_map"),
    "src/webpent/agents/strategist/agent.py": (
        "umdr52_w1_priority_score_handoff"),
    # re-pin after the lint pass (the unused-var removal) — idempotent
    "src/webpent/researcher/behavioral_layer.py": (
        "umdr52_w1_behavioral_layer_fail_safe_boundaries"),
    # --- UM-DR-51 declared-thaw drift, never re-pinned at its window
    # --- close (inherited tail, same class as the 48/49 tail the
    # --- umdr50 closeout inherited). Public history of each edit:
    # --- settings b9b7601, modern_spine 3f5ea05, unified_hunt c5bf5b7,
    # --- access_control 8db809b, __init__ 7465670. Their regression
    # --- proofs are the post-publication green CI chain on main
    # --- (45991382017..45997282322) + this window's clean-tree battery
    # --- (9990 collected / 9969 passed / 5 = the re-bind gates).
    "src/webpent/config/settings.py": (
        "umdr51_declared_thaw_brain_flags_phase1_b9b7601"),
    "src/webpent/production/modern_spine_integration.py": (
        "umdr51_declared_thaw_unified_loop_entrypoint_3f5ea05"),
    "src/webpent/cli/unified_hunt.py": (
        "umdr51_declared_thaw_finding_report_phase5_c5bf5b7"),
    "src/webpent/agents/access_control/agent.py": (
        "umdr51_declared_thaw_promotion_regression_fix_8db809b"),
    "src/webpent/__init__.py": (
        "umdr51_rebind_version_identity_0_49_0_7465670"),
}

# NEW PIN — joins the frozen set (the ACCEPTED_EXCEPTIONS_REGISTER
# contract: every registered broad-handler src file must carry its
# frozen pin, the raw_transport umdr50 precedent). behavioral_layer.py
# joins with its fresh digest; regression proof:
# tests/test_umdr52_w1_behavioral.py (19/19).
NEW_PINS = {
    "src/webpent/researcher/behavioral_layer.py":
        "umdr52_w1_behavioral_layer_fail_safe_boundaries",
}
MIN_ENTRIES = 600


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = MANIFEST.read_text().splitlines()
    entries: dict[str, str] = {}
    for line in lines:
        if not line.strip():
            continue
        digest, _, relpath = line.partition("  ")
        entries[relpath.strip()] = digest.strip()

    absent = [p for p in entries if not (REPO_ROOT / p).exists()]
    assert not absent, f"frozen files missing from tree: {absent}"

    drifted = {p for p, d in entries.items()
               if d != _sha256(REPO_ROOT / p)}
    undeclared = drifted - set(REPINS)
    assert not undeclared, (
        f"undeclared frozen-file drift: {sorted(undeclared)}")
    missing_drift = set(REPINS) - drifted
    already = {p for p in missing_drift
               if entries.get(p) == _sha256(REPO_ROOT / p)}
    truly_missing = missing_drift - already
    assert not truly_missing, (
        f"declared repins with NO drift (stale declaration?): "
        f"{sorted(truly_missing)}")

    out: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        digest, _, relpath = line.partition("  ")
        rel = relpath.strip()
        if rel in REPINS:
            out.append(f"{_sha256(REPO_ROOT / rel)}  {rel}")
        else:
            out.append(line)
    for rel in NEW_PINS:
        if rel not in entries:
            out.append(f"{_sha256(REPO_ROOT / rel)}  {rel}")
    out.sort(key=lambda line: line.partition("  ")[2])

    assert len(out) >= MIN_ENTRIES, (
        f"manifest floor violated: {len(out)} < {MIN_ENTRIES}")

    MANIFEST.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"OK: refroze the manifest ({len(entries)} entries; "
          f"{len(drifted)} declared repins re-bound: "
          f"{sorted(drifted)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
