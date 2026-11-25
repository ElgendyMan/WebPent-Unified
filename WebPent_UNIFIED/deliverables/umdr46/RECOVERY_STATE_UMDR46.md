# UM-DR-46 — RECOVERY / CONTINUATION STATE (final)

## Branch state (authoritative — GitHub)
- Branch: `feature/umdr46-ultimate-researcher-brain` @ `8629774` ("Update project to v0.44.0 UMDR46 window: BUILD_INFO manifest-digest re-sync after the Phase A-K re-freeze")
- Phases A–K all LANDED (12 commits). See `deliverables/umdr46/PHASE_CLOSEOUT.md` (the durable mission memory) + `deliverables/umdr46/GOVERNANCE_INDEX.md`.

## CI status at hand-off
- CI run 45427553483 on 8629774: IN PROGRESS at hand-off.
- Full history of this session's CI failures, each root-caused and fixed:
  1. 25ac194..74c048e lineage: pre-existing P0.3 manifest omission (3 stale agent entries) + g02 drift + unregistered new-node broad handlers — ALL FIXED in the phase commits.
  2. ea5d425: secret scan flagged the Phase K battery copy (`scripts/umdr46_final_battery.py` — same OUT-OF-SCOPE dummy fixture as the baseline copy) → FIXED by the allowlist entry (commit 2389bab).
  3. 2389bab: every gate + the FULL regression suite GREEN; only `build_info_honesty` failed — `provenance.manifest_digest` stale after the window refreeze → FIXED (digest re-synced, commit 47916cb → amended to 8629774 with the qualifying publication-convention subject; all 24 `tests/test_umdr36_1_build_info_provenance.py` pass locally).

## What a follow-up message should do
1. `git clone https://github.com/ElgendyMan/WebPent-Unified.git && cd WebPent-Unified/WebPent_UNIFIED && git checkout feature/umdr46-ultimate-researcher-brain` (+ `uv sync --locked --extra dev`).
2. Check CI conclusion on 8629774 (run 45427553483). Expected GREEN: all three prior failure causes are eliminated (secret scan ✓ passed on 2389bab; full regression ✓ passed on 2389bab; build-info + the two provenance tests ✓ pass locally on 8629774).
3. If anything still fails, fetch the job log, fix at the root, and follow the same declared-decision commit conventions.

## Local verification at hand-off (already re-run on 8629774)
- `uv run python scripts/check_build_info_honesty.py` → PASS
- `pytest tests/test_umdr36_1_build_info_provenance.py` → 24/24
- Earlier full local suite on the same tree content (ea5d425): **9781 passed / 0 failed / exit 0** (log: worklogs/fullsuite_final2.log, sandbox-side)
