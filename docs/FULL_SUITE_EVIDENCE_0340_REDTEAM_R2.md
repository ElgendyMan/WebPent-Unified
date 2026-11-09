# FULL SUITE + GATES EVIDENCE — 0.34.0 red-team round 2 (2026-11-02)

Window: docs/RED_TEAM_ROUND2_20261102.md (batches C1 + C2 + C3, 45 findings
from the round-2 red-team review; 16/17 Low items closed this window, the
lesson-wiring half of R2-graph-07 documented as deferred to 0.35.0).

## Collection gate (3a-2)

- `pytest --collect-only -q` -> **6844 tests collected, 0 errors**.

## Full suite — exact reconciliation (5 batches, 0 failed)

| Batch | Scope | Result |
|---|---|---|
| 1 | tests/*.py (root files) | 4170 passed, 4 skipped, 3 xfailed |
| 2 | tests/oracle tests/dojo tests/prism tests/jc | 1046 passed |
| 3 | tests/forge tests/apex tests/deep tests/campaign tests/egaie | 698 passed |
| 4 | tests/bridge tests/econ tests/lab tests/vip tests/ground_truth | 168 passed |
| 5 | tests/scenario_lab tests/team1_acceptance | 755 passed |
| **Total** | | **6837 passed / 0 failed / 4 skipped / 3 xfailed = 6844** |

Window tests: 61 new R2 tests (c1=19, c2=15, c3=8, dojo=9, econ=10), every
one verified failing on the pre-fix baseline, passing after.

One legacy source-string pin updated (tests/test_r3_e2_builder_rejection.py):
the combined recon node call moved from `dict(state)` to `dict(working)`
after the R2-graph-01 delta refactor; the modern-first intent is re-pinned.

## Static gates

- ruff ratchet: **6212 == 6212** (re-baselined with documented reason:
  ruff 0.17.3 tool-version drift in untouched legacy trees after sandbox
  rotation; ZERO new findings inside src/webpent from this window's 38
  changed files — trainer B905/SIM105 fixed in-source; builder.py I001
  verified pre-existing at HEAD under the same ruff).
- F821 / F402 / E722 / B025: all clean (decreased to 0 under 0.17.3).

## Freeze + inventory

- frozen_modules.sha256: 659 entries re-pinned; 13 pinned files changed
  (scripts/refreeze_manifest_0340_redteam_r2.py), 25 further changed files
  documented as never-pinned (advisory modules); thaw set
  REDTEAM_R2_20261102_THAW_PATHS = {graph/checkpoints.py} — every other
  changed pinned path is covered by earlier window sets.
- direct-I/O inventory: regenerated deliberately 814 -> 816 records
  (scripts/regen_direct_io_inventory_0340_redteam_r2.py): +2 blind_spots
  getattr(scope, ...) (R2-econ-05), +2 builder getattr(ann/m, ...)
  (R2-graph-01 channel derivation), -2 validation_status getattr probes
  (R2-graph-06). Zero new raw-transport sites; unapproved pin unchanged.

## Canary

- canary 7x: **STABLE=True** (7/7 runs match baseline, 855 passed each,
  collection gate clean) — reports/canary/CANARY_7X_20261101_0.34.0.{json,md}.

## Release gates

- version SSOT src/webpent/__init__.py = 0.34.0; pyproject.toml = 0.34.0;
  CHANGELOG.md leads with 0.34.0 (tests/test_release_packaging.py green).
