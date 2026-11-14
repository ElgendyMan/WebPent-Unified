#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the UM-DR-33 info-gain window
(2026-11-10) per the DR-009 / refreeze protocol.

Documented scope of this refreeze — exactly ONE frozen file:

  1. src/webpent/shared/prioritization.py — the information-gain
     operationalization (UM-DR-33 §8.2 / Workstream F, closing the
     UM-DR-31 review finding that varying ``info_gain`` did not change
     the strategist's ranking score because ``score_hypothesis`` never
     read the field). The change:

     * ``W_INFO_GAIN = 0.10`` joins the weighted sum; the other weights
       are rebalanced (severity .25->.22, confidence .20->.18, evidence
       .10->.09, cost .15->.13, criticality .20->.18; novelty unchanged)
       so the sum stays exactly 1.0 and the relative ordering of the
       pre-existing dominant terms is preserved.
     * ``Hypothesis.info_gain`` (0..1, None = not yet scored) is read
       with a neutral midpoint default (0.5) — unscored hypotheses are
       neither penalised nor boosted; explicit low ranks below unscored,
       explicit high above. Out-of-range values are clamped defensively.
     * The gate semantics are untouched: info_gain can reorder eligible
       hypotheses and move one across the PROMOTION threshold (candidacy
       for the authorized executor), but can never admit an out-of-scope
       endpoint, bypass scope/authorization admission, or extend a hard
       budget — those gates are score-independent by construction.

Regression coverage verified BEFORE this re-pin:
  tests/test_umdr33_info_gain_operational.py (19 tests):
    - monotonicity (delta == W_INFO_GAIN * delta_ig, exactly)
    - controlled ranking flips; determinism; neutral-default semantics
    - decision crossing (PROMOTE at ig=1.0 vs DEFER at ig=0.0, ceteris
      paribus) with the closed action set pinned
    - safety independence: scope admission, BudgetGuard counters,
      corrupted-trace fail-closed
  Pre-existing consumers green: test_v61_cognitive_upgrade,
  test_lessons_learning_loop, test_amplifiers_intuition,
  test_umdr31_adaptive_research, test_smart_campaigns_node (103 pass).

Old pin (recorded for the audit trail):
  912b71f003e36716df4dff57870e0cd5eb39cd3592f1fafa9eb766b4e2cc6cc5

No other frozen file changed. The pre-unfreeze baseline is untouched.
Self-verifying: the result is re-hashed from disk before write.
Usage: python3 scripts/refreeze_manifest_umdr33_info_gain.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

UMDR33_IG_REPINNED_FILES = (
    "src/webpent/shared/prioritization.py",
)

OLD_PINS = {
    "src/webpent/shared/prioritization.py":
        "912b71f003e36716df4dff57870e0cd5eb39cd3592f1fafa9eb766b4e2cc6cc5",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = [
        line.strip()
        for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    entries: list[tuple[str, str]] = []
    repinned = 0
    listed = set()
    for line in lines:
        digest, _, relpath = line.partition("  ")
        if relpath in UMDR33_IG_REPINNED_FILES:
            new_digest = sha256(REPO / relpath)
            if OLD_PINS[relpath] == new_digest:
                print(f"ERROR: {relpath} unchanged on disk — nothing to re-pin")
                return 1
            entries.append((new_digest, relpath))
            repinned += 1
            print(f"re-pinned {relpath}\n  old {OLD_PINS[relpath]}\n  new {new_digest}")
        else:
            entries.append((digest, relpath))
        listed.add(relpath)

    missing = set(UMDR33_IG_REPINNED_FILES) - listed
    if missing:
        print(f"ERROR: declared re-pin files absent from manifest: {sorted(missing)}")
        return 1

    for digest, relpath in entries:
        if sha256(REPO / relpath) != digest:
            print(f"ERROR: self-verification failed for {relpath}")
            return 1

    MANIFEST.write_text(
        "\n".join(f"{digest}  {relpath}" for digest, relpath in entries) + "\n",
        encoding="utf-8",
    )
    print(f"manifest written: {len(entries)} entries ({repinned} re-pinned this window)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
