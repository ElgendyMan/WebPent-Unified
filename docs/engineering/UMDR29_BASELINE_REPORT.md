# UM-DR-29 Baseline Report — Repository Truth & Reproduced Suite

Window: UM-DR-29 (2026-11-07) · Start: v0.34.0_UMDR28 · End: v0.35.0_UMDR29

## 1. Starting claims vs verified reality (UM-DR-28 claims audit)

| UM-DR-28 claim | Verification | Result |
|---|---|---|
| Release zip `WebPent_UNIFIED_v0.34.0_UMDR28.zip`, SHA-256 `1b8c97…579f0` | `sha256sum` on the delivered artifact | **CONFIRMED** byte-identical |
| Commits b73e074 → 84b1618 → b752b46 | `git log` | **CONFIRMED** present, in order |
| Suite 8,608 passed / 0 failed / 8,617 collected | fresh chunked run on restored env | **CONFIRMED exactly** (13/13 chunks OK) |
| Accounting discrepancy (8,569 vs breakdown 8,568) | resolved from raw chunk logs | **RESOLVED**: 8,617 collected = 8,608 passed + 6 skipped + 3 xfailed; the historical 8,568-vs-8,569 delta was a rounding of the same skipped/xfailed classes |
| Stateful discovery campaign-integrated | import-graph + wired node tests | **CONFIRMED** (execution_node behind fail-closed flag) |
| Representation oracle wired with guard | cqa_v2 chain | **CONFIRMED** |
| `family_*` state channels outstanding | PentestState annotations audit | **CONFIRMED outstanding** — channels are declared via append-only annotation derivation (graph/builder.py `getattr(ann, ...)` records in the direct-I/O inventory); typed-contract tests cover serialization, but the family_* channel surface remains partially implicit (documented in the gap analysis) |
| M10 closed (no independent holdout) | status registry | **CONFIRMED** — still closed this window |

## 2. Baseline defects found by THIS window's truth audit (and fixed)

1. **`BUILD_INFO.git_head` = `ab97ab3…` does not exist in this repository.** The
   workspace git history was re-initialized (33 commits, root `fdcd515`);
   the recorded head belongs to the pre-re-init lineage and has been carried
   unchanged through every re-freeze since. Fixed: pointed at the actual
   window commit (dedicated re-freeze commit, per the established pattern).
2. **Repo-root junk commit `b547dc4`** (UUID subject) tracked operator
   artifacts (`download/*.zip`, `upload/*.txt`, `scripts/run_umdr28_batch.sh`)
   inside git. Fixed forward: paths untracked via `.gitignore`; files kept on
   disk (no user data touched).
3. **The Ultimate-Plan-2026-10-27-proposal-4 dead-code archive was a COPY,
   not a MOVE** — 17 "archived" packages still lived identically in
   `src/webpent/` (e.g. `abhc`, `goed_v1`). The frozen gate, the broad-
   exceptions register and the direct-I/O pin all documented the removal as
   done; the filesystem said otherwise. Fixed: src copies deleted (one
   differing src variant preserved losslessly under `archive/pre_v10_prototypes/abhie_v6/agent_core.py.umdr29_src_variant`).
4. **Six frozen `__init__.py` docstrings** claimed `webpent.goed_v1` as the
   core engine — false since the archive window. Fixed (docstring-only,
   DR-009 re-pin).
5. **Two unapproved raw-transport identities** (`cqa/execution.py` httpx
   import + AsyncClient call) remained pinned in the direct-I/O pin set 11
   days after the window that documented their removal. Fixed: physical
   removal realized; pin 36→34 records / 30→28 identities.

## 3. Reproduced baseline (before UM-DR-29 changes)

- Environment: `/home/z/.venv/bin/python3` (restored per
  `docs/engineering/REDTEAM_WINDOW_REPORT.md` recipe: langchain-core 1.6.7,
  langgraph 1.2.10, langgraph-checkpoint-sqlite 3.1.1, bcrypt, esprima,
  celery, jsbeautifier, aiosqlite, alembic, structlog; `uv pip install
  --no-deps -e .`)
- Command: chunked serial pytest, 664 files, 13 chunks × 55 files
  (`scripts/run_umdr29_batch.sh`), `--tb=line -q -p no:cacheprovider`
- Result: **8,608 passed / 0 failed / 6 skipped / 3 xfailed / 8,617 collected**
- Key gates pre-change: frozen gate 663 ✅, blind_v3 replica 20 ✅,
  M1b channel matrix 6 ✅, workspace artifact ownership 7 ✅ (696 total)

## 4. Post-change suite (after the dead-code disposition)

- Collected: **8,595** (−22 = exactly the frozen-gate parametrized
  byte-identity cases for the 22 removed manifest entries; no test was
  deleted)
- Result: all chunks OK (2 version-consistency failures during the run were
  the version-agreement gates doing their job mid-bump; both green after
  the version sources were updated; BUILD_INFO suite_count re-measured in
  the dedicated re-freeze commit per honest-drift rule 5)
- 2 additional honest skips: `test_five_families.py` goed_v1 strategy
  inventory tests skip via the pre-existing documented skipif (the archive
  completion they were written for finally happened)

## 5. Baseline record (machine-readable)

See `reports/qualification/umdr29_baseline.json` (regenerated this window)
and the chunk logs archived at delivery time.
