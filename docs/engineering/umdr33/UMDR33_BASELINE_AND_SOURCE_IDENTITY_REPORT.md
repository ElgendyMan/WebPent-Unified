# UM-DR-33 Baseline and Source Identity Report

Window: UM-DR-33 Phase 0 (baseline freeze)
Generated: 2026-11-10 (UTC)
Branch: `umdr33-researcher-brain-autonomous-campaigns` (created from `umdr32-identity-business-logic-evolution` @ `da1f828`)
Status: BASELINE FROZEN — machine-readable companion: `UMDR33_BASELINE_FREEZE.json`

---

## 1. Repository identity (§2.1 items 1–4)

| Field | Value |
|---|---|
| Repository root | `/home/z/my-project/webpent/WebPent_UNIFIED` |
| Remote URL | **none configured** (no `origin`; publication is `BLOCKED_EXTERNAL_DEPENDENCY`, see §6) |
| Default branch (local) | `main` |
| Development branch | `umdr32-identity-business-logic-evolution` (UM-DR-32 lineage) |
| New branch (this initiative) | `umdr33-researcher-brain-autonomous-campaigns` |
| Tags | none |
| HEAD at branch point | `da1f828496f02fc647aeaac5c1c1cc3d59cf5cfb` |
| HEAD tree SHA | `727e660e16b987f2ec7bbbacfaf80c4ae0170a5c` |
| `main` HEAD | `596591769e6c095a2e4e224179782e8d40d9d7fa` (the v0.37.1 import snapshot) |

## 2. UM-DR-32 lineage verification (§2.1 item 5, Workstream A §3.1)

The prompt's historical assumption ("GitHub showed only main; development
lineage not exposed") is **superseded by direct local evidence**: the complete
UM-DR-32 lineage exists locally with an unbroken parent chain (verified via
`git log --format="%h %p"`):

```
5965917  (root)  Import WebPent UNIFIED v0.37.1-UMDR31.1 release snapshot (= main)
└─ b1c380f  UM-DR-32 Phase 0+1 (partial): baseline freeze, portable runner, corrected builder
   └─ 1cf8d92  origin scheme admission fix + experiment provenance contract
      └─ b88df0a  UM-DR-32 Phases 2-6: four capabilities + unified production integration
         └─ 9593909  Phases 7-8: evaluation lab + security regressions + tenant-boundary rule
            └─ d3209e3  Phase 9: version reconciliation gates, lint, final accounting
               └─ ec5254f  benchmark artifact (release-grade, clean tree)
                  └─ 8552503  Phase 10: documentation deliverables
                     └─ d3937b2  Phase 10: A-K core set  ← v0.38.0 release-archive source commit
                        └─ 6b4d290  release: v0.38.0 archive + checksum + manifest + integrity report
                           └─ 52da06f  final acceptance: ACCEPTED WITH LIMITATIONS (gates A-J PASS)
                              └─ da1f828  direct-io inventory line-refresh (UM-DR-33 branch point)
```

- All commits carry their original author timestamps and identities; **no
  history was rewritten or fabricated**.
- The delivered `WebPent_UNIFIED_v0.38.0_UMDR32.zip` release manifest records
  `source_commit d3937b2a…` — that commit exists locally on this chain
  (Phase 1 re-verifies the archive tree against it byte-for-byte).
- **Publication gap (honest record):** this execution environment has no Git
  remote and no GitHub credentials. The lineage is verifiable locally only.
  `main` remains at the import commit; UM-DR-32 was never merged to `main`.
  Exact publication commands are provided in the release-integrity report.

## 3. Working-tree state (§2.1 item 6)

- On arrival: `git status --porcelain` = **4,767 modified files**.
- Root cause (diagnosed, not assumed): **file-mode bits only** — every tracked
  file carried `0755` while the index records `0644`; content diffs were empty
  (`git diff --stat` = 0 insertions/deletions), untracked files = 0. The
  archive extraction path set the executable bit.
- Resolution: `git config core.fileMode false` (recorded in repo config).
  Result: `git status --porcelain` = **0 lines** — content-clean tree, no
  source modification, baseline recoverable at `da1f828`.

## 4. Version and build metadata (§2.1 items 8–9)

- Package version: `0.38.0` — SSOT `pyproject.toml` + `CHANGELOG.md`,
  mirrored in `src/webpent/__init__.py` (`__version__`), `BUILD_INFO.json`
  (`package_version`), release manifest (`package_version`).
- `BUILD_INFO.json` carries the UM-DR-32 §3.4 version-identity contract
  (build_name kept as legacy lineage label only).
- Python floor declared: `>=3.11` (`pyproject.toml`; classifiers 3.11/3.12).
  Tested interpreter: **Python 3.12.16** (both UM-DR-32 and this baseline).
  README line 201 still states "Python **3.12**." flatly — the
  floor-vs-tested distinction is already explained at README:220-221; the
  Phase 1 documentation pass makes line 201 state floor + tested explicitly
  (Workstream A §3.5).
- Feature flags (UM-DR-32 §4–§7), all **fail-closed default False**:
  `enable_object_identity`, `enable_alias_resolution` (depends on object
  identity), `enable_multi_identity_reasoning`,
  `enable_composite_workflows`; caps `max_object_identities=5000`,
  `max_alias_pairs=500`, `max_identity_hypotheses=12`,
  `max_workflow_sequence_depth=4`, `max_workflow_candidates=8`
  (`src/webpent/config/settings.py:836-920`).
- Quality gates present: frozen-module gate
  (`tests/test_frozen_module_gate.py` + `frozen_modules.sha256`),
  editable-broad-exceptions register, release-archive builder test, CI
  workflows (`.github/workflows/`).
- Lockfile: `uv.lock` present and consulted for dependency pins.

## 5. Baseline testing (§2.2) — fresh collection and full suite

### 5.1 Environment reconciliation (before any measurement)

The execution sandbox arrived with an **off-specification environment**. All
deltas were resolved to the project's own declared pins before freezing the
baseline; nothing was changed in the source tree:

| Package | Arrived | Project pin (`pyproject.toml`/`uv.lock`) | Action |
|---|---|---|---|
| langchain-core | absent → 1.7.6 (latest, wrong) | `==1.6.7` | installed exact pin |
| langgraph | absent → 1.2.20 (wrong) | `==1.2.10` | installed exact pin |
| langgraph-checkpoint-sqlite | absent | `==3.1.1` | installed |
| celery | absent → 5.7.0 (wrong) | `==5.6.3` | installed exact pin |
| bcrypt | absent | `==5.0.0` | installed |
| esprima / jsbeautifier | absent | (test-path deps) | installed |
| pydantic | 2.12.5 (off-spec) | `==2.13.5` | upgraded to pin |
| filetype | orphan (no reverse deps) | not a project dep | removed — langchain-core's google_genai block-translator imports it when present, polluting the A-01 transitive closure |
| webpent importability | not installed (`python -m webpent.cli` failed) | — | `webpent_src.pth` points at `src/` (full `pip install -e .` was attempted but aborted: the torch/nvidia dependency chain exceeds sandbox disk; recorded as an environment limitation, not a source defect) |

### 5.2 Fresh collection and full-suite run (normalized environment)

- Discovery: `pytest --collect-only -q` → **8,903 unique node IDs**, 0
  collection errors, 680 test files (sorted unique ID list preserved at
  `umdr33_evidence/baseline_unique_ids.txt` in the execution workspace).
- Full suite: `scripts/run_suite.py` (portable chunked runner) — **13/13
  chunks executed**, every planned chunk ran to completion.
- Result: **8,894 passed + 6 skipped + 3 xfailed + 0 failed = 8,903 collected
  (exact)** — reproduces the published UM-DR-32 final accounting
  digit-for-digit.
- Skips (6): 1 legacy v4 lessons test (deliberately skipped at collection,
  documented) + 5 platform/env conditional marks across chunks 6/7/9.
  Xfails (3): documented expected-failure markers in chunk 9. No hidden
  collection error, no unexecuted chunk.
- An initial full-suite attempt in the pre-normalization environment produced
  10 failures across 4 test modules (CLI subprocess import, S2 composition
  A-01 closure, egaie evaluator package layout, sdd8 flag independence).
  Every one was re-run after normalization and **passes**; all 10 were
  environment artifacts, none is a source defect. The failing list is
  preserved in `baseline_collect_raw.txt` (pre-fix) for audit.

### 5.3 UM-DR-32 test-accounting discrepancy (§2.2, closed in Phase 1)

Recomputed from actual node IDs: the UM-DR-32 window added **159 unique test
IDs** = 154 across the nine `test_umdr32_*.py` files
(7+17+20+13+18+18+22+32+7) + 5 frozen-gate parametrized entries — exactly
what `UMDR32_TEST_ACCOUNTING.json` records. The prose "152 new tests" in
`UMDR32_EXECUTION_REPORT.md` (lines 12, 101) and
`UMDR32_FINAL_ACCEPTANCE_REPORT.md` (line 119) is an **arithmetic
undercount**; Phase 1 corrects the prose with a node-ID-backed
reconciliation and records the historical error without hiding it.

## 6. Limitations and blockers recorded at freeze

1. **No Git remote / no GitHub credentials** → tag, Release, and asset
   publication for v0.39.0 are `BLOCKED_EXTERNAL_DEPENDENCY`. All local
   release steps are completed; exact publication commands are provided
   (§17 final deliverables).
2. **`pip install -e .` not completable in this sandbox** (disk ceiling vs
   torch/nvidia chain). Mitigation: `.pth` src-path import — equivalent for
   all test and CLI paths exercised. Production dependency review in Phase 2
   uses the lockfile and `pip-audit` against the pinned set.
3. **MCP / external holdout / XBOW comparison**: out of scope per §1.5 — not
   attempted.
4. The 6 skips and 3 xfails are pre-existing documented conditions, not new
   gaps.

## 7. Phase 0 conclusions

- Source identity is **fully verifiable locally**: exact commit, tree, clean
  status, and the entire UM-DR-32 lineage with intact parents.
- The frozen baseline (8,903 / 8,894+6+3) is the authoritative denominator
  for every UM-DR-33 delta. Any test added, removed, or replaced from here is
  accounted against this list by node ID.
- Architecture mapping (execution path, strategist scoring, confirmation
  authorities, budget layers, OAST state, frozen-module layout) was completed
  in Phase 0 and drives the Phase 2+ workplans; the key confirmed findings —
  `info_gain` not participating in `score_hypothesis`
  (`src/webpent/shared/prioritization.py`, frozen), the AVI lane labeling its
  validator path `CausalGuard_deterministic_engine` without invoking
  `cqa_v2.guarded_causal_evaluate`, and the harness-only evaluation-lab
  differentials bypassing ToolBoundary/ScopeLaw — are carried as first-class
  work items in their respective workstreams.
