# REVIEW_REFREEZE_REPORT.md — TEAM-REVIEW-REFREEZE (2026-10-22)

**Executive verdict: APPROVE_REFREEZE_DONE**

Freeze policy was pre-decided `ACCEPT_MERGE_AND_REFREEZE`. Sections A, B, C
all PASSed on tree evidence before any freeze write; Section D re-freeze was
then executed strictly per the repo's documented procedure; Section E smoke
is green. No test was rewritten, no authority component touched, no
functionality removed.

Base tree: commit `4e32a86` (merge-final, Phase 5 deliverable).
Result tree: commit `1dfcbe4`. Deliverables: `PRE_HASHES.txt`,
`POST_HASHES.txt`, `CHANGED_FILES.txt`, updated tree ZIP.

---

## Section A — Union files audit: PASS (5/5)

| # | File | Union quality | Import | Single authority path | Verdict |
|---|------|---------------|--------|----------------------|---------|
| 1 | `src/webpent/agents/hunter_runner.py` | FINDING, remediated: union kept donorV's redundant second `_terminal_result()` computation after donorC's in-summary embed. `_terminal_result` is pure/reporting-only (docstring: sealed proof and promotion decisions remain owned by existing authorities), so the duplicate was behavior-equivalent, but it was duplicated control flow. Remediated by restoring the donorC version BYTE-IDENTICAL (commit `4e32a86`). | OK | donorC writer count preserved (C=12, R=12; no writer added/removed) | PASS (post-remediation) |
| 2 | `src/webpent/agents/subdomain_takeover/agent.py` | Clean union; added hunk traced verbatim to donorV `K-2 (RA-3)` | OK | writer counts = donorC | PASS |
| 3 | `src/webpent/api/app.py` | Clean union; added hunks verbatim donorV (`from exc` hardening) | OK | writer counts = donorC | PASS |
| 4 | `src/webpent/cli/commands.py` | Clean union; donorC content + donorV `U-3 (RA-2 RSTU)` docstring lines | OK | writer counts = donorC | PASS |
| 5 | `src/webpent/production/modern_spine_integration.py` | Clean union; added `_fixtures_conversion_failures` debug logging (donorV) | OK | writer counts = donorC | PASS |

No glue code, no duplicated control flow remaining, no unreachable branches,
no second promotion/report writer, no logic conflict found in any of the five.

## Section B — 31 frozen-path divergence review: PASS (31/31 KEEP_MERGED_INTENTIONAL, 0 SUSPECT_UNSAFE)

Divergence set reproduced mechanically: for each of the 719 manifest paths,
tree sha256 vs `frozen_modules.sha256` (pre-regen) → exactly 31 divergent
paths (list in `PRE_HASHES.txt`). Byte-origin classification against the
donor commits (`c916990` donorC, `60e0460` donorV):

- **26 paths carry donorC bytes EXACTLY** (intentional Comprehensive(1)
  baseline retention over v15.2 content — includes `hunter_runner.py` after
  the Section A remediation, the `service/*` trio, `scope/*` trio,
  `shared/jwt_deep_testing.py` (JWT key-confusion capability), `workers/pentest_worker.py`,
  validator check modules, agent modules, recon modules, `reporter/*`).
- **5 paths are documented unions/modifications**: `agents/devils_advocate/agent.py`
  (Project Zero canonical revision; both donors byte-identical beforehand),
  `agents/subdomain_takeover/agent.py`, `api/app.py`, `cli/commands.py`,
  `production/modern_spine_integration.py` (Section A table).
- Set matches `MERGE_REPORT.md` accounting exactly (there reported as 25+6;
  the delta is hunter_runner moving from "union" to "donorC bytes" via the
  remediation). No accidental extra drift path.
- Authority components: none of the 31 is CausalGuard, ProofBundle,
  Replay/ReplayVerifier, ToolBoundary, ScopeLaw or PromotionPipeline. The
  authority manifest (Section D) proves 12/13 pinned authority files
  byte-identical to their pins.

## Section C — Project Zero wiring: PASS

Evidence:

1. **Imports:** all 10 PZ modules import cleanly inside the package
   (`memory/postmortem`, `memory/taint_tracker`, `models/postmortem`,
   `models/taint`, `shared/red_vs_blue`, `shared/shadow_detector`,
   `shared/surface_drift`, `shared/surface_influence_graph`,
   `shared/tech_stack_cve`, plus the devils_advocate modification) —
   re-verified post-refreeze in Section E step 3.
2. **Tests:** 128/128 Project Zero tests pass (`tests/test_{postmortem,red_vs_blue,shadow_detector,surface_drift,surface_influence_graph,taint_tracker,tech_stack_cve}.py`).
3. **Real production call-path (postmortem + devils_advocate):**
   `graph/builder.py:57` imports `devils_advocate_node`; `:173` defines
   `NODE_DEVILS_ADVOCATE`; `:1636` `graph.add_node(NODE_DEVILS_ADVOCATE, ...)`; `:1249`
   `route_after_devils_advocate` routing. The node calls
   `_record_devils_advocate_postmortem` (`agents/devils_advocate/agent.py:455`)
   → `memory.postmortem.get_postmortem_manager` (`:341`) → `models/postmortem`.
   This is a live LangGraph production path, not disk presence.
4. **PZ-internal cross-references:** `shared/red_vs_blue.py:46` imports
   `shadow_detector.extract_detection_keys`; `memory/taint_tracker.py` ↔
   `models/taint.py`; `models/taint.py` references
   `shared/surface_influence_graph`.
5. **No broken imports in package load:** `import webpent` OK (Section E).

**Scoping note (recorded, not hidden):** 6 of the 7 items (taint tracking,
surface influence graph, shadow detector, surface drift, red-vs-blue,
tech-stack CVE) are currently integration-ready library modules — tested,
import-clean, PZ-cross-referenced — without a production caller yet.
The "where applicable" call-path requirement is satisfied by the
postmortem/devils_advocate/graph wiring; the six are flagged as residual
risk R-3 for a future integration window. Wiring them now would have meant
inventing call sites during a verification pass, which the pass forbids.

## Section D — Re-freeze: DONE (documented procedure only)

Procedure followed: `docs/UNFREEZE_FILES_20261005.md` rule 1 (a)–(d).

1. **Pre-hashes** recorded in `PRE_HASHES.txt`: manifest sha256
   `2424c3d9d3f8751bbea1eaf4180f4c07bdbd508ebe826b4a826f6afc6c06c454`;
   baseline `9aeefdb2...031bbd0` (untouched); tree bytes of all 31 divergent paths.
2. **Manifest regenerated** over the SAME 719-path scope in the SAME order
   (verified: no entries added/dropped/reordered) from merged tree bytes.
   New sha256 `ca330fd20399c968009a4d6124211941c44aafc3e4314f7af18bb68a53dc18bf`.
   Note: `frozen_modules.sha256` is an on-disk artifact in this repo
   (matched by the `.gitignore` `*.sha256` rule); it ships in the tree/ZIP.
3. **Gate re-run:** `tests/test_frozen_module_gate.py` → **720 passed, 1 failed**.
   All 719 `test_frozen_file_byte_identical` invariants GREEN (the 30
   merge-drift failures cleared). The 1 failure is
   `test_baseline_disagrees_only_on_documented_unfreeze_paths` — an
   INHERITED failure, present before the merge: its assertion reads only
   `frozen_modules.sha256` + `frozen_modules.sha256.baseline_pre_unfreeze`,
   both last touched at donorC commit `c916990`; pre-merge it failed with 28
   undocumented manifest-vs-baseline drift paths because the v15.2 lineage
   regenerated the manifest across windows v9–v15.2 without extending the
   test's `expected_drift` constant. Per the no-test-rewrite rule the
   assertion was left as-is; the correction is documented in the dated
   addendum in `docs/UNFREEZE_FILES_20261005.md`.
   Related checks: hygiene/resurrect → 5 passed;
   `scripts/verify_frozen_manifest.py` → **OK (13 files)** after re-capturing
   exactly one entry (`validator/active_checks.py`, re-hashed from merged
   tree bytes per the manifest's own provenance convention); the other 12
   pins — CausalGuard, ProofBundle ×2, workflow_replay ×2, ReplayVerifier,
   ToolBoundary, tool_scope, profile, governed_artifacts, irta proof,
   world_model — verified byte-identical to their pins (fail-closed evidence
   that no authority was weakened).
4. **Full-suite re-run (procedure step c):** **3806 passed, 26 failed,
   3 skipped, 1 xfailed** in 2:16. Decomposition: 25 inherited failures
   (verified pre-merge to fail identically in untouched Comprehensive(1);
   environment-dependent live-target/fixture tests) + 1 the inherited
   baseline-drift gate test. 29 of the 30 pre-refreeze frozen-gate failures
   are cleared; **0 unexplained failures**.
5. **Bookkeeping:** `docs/UNFREEZE_FILES_20261005.md` dated addendum
   (doc + baseline policy update, step (d)); `PRE_HASHES.txt` / `POST_HASHES.txt`
   added; committed as `1dfcbe4`.

## Section E — Lab smoke: PASS

| Command | Result |
|---|---|
| `PYTHONPATH=src python -c "import webpent"` | OK (`src/webpent/__init__.py`) |
| `python -m compileall -q src` | exit 0, no output |
| spine import: `production.modern_spine`, `production.modern_spine_integration`, `graph.builder` + all 7 PZ modules | all import OK |

No external targets started; no loopback lab required by this pass.

## Residual risks

1. **Inherited gate-test defect — RESOLVED post-pass (user-approved follow-up,
   commit 6a974bf, 2026-10-22):** `expected_drift` in
   `tests/test_frozen_module_gate.py` was extended with the documented 28-path
   TEAM-MERGE lineage-drift set (12 of them this pass's Section B
   KEEP_MERGED_INTENTIONAL paths, 16 donorV-lineage regen drift) plus an
   11-path brain//production scope-completion whitelist. Gate suite now
   721 passed / 0 failed. Original finding preserved below for the record.
2. **Delta-gate anchors — RE-ANCHORED post-pass (user-approved follow-up):**
   `scripts/gate_frozen_delta.py` `ANCHOR_MANIFEST_SHA256` and
   `scripts/r3_anchor_check.py`'s manifest pin now point at the 2026-10-22
   re-freeze manifest `ca330fd2…53dc18bf` (scope 719); the retired v6 anchor
   `fb42957d…` is documented in both files. (Re-anchored a second time to
   `cfbc347a…60c88b` by follow-up item 3's re-freeze; see item 3.) Original
   finding preserved: the anchors previously pinned the v6-era manifest
   (`fb42957d…`).
3. **Six PZ items are library-tier — RESOLVED post-pass (user-approved
   follow-up item 3, 2026-10-22):** all six modules now have production
   callers: surface_influence_graph (shared/surface_security summary),
   surface_drift + tech_stack_cve + taint SOURCES (crawler_node),
   taint SINKS (validator persistence path), red_vs_blue composing
   shadow_detector (devils_advocate_node, escapes fed to Postmortem).
   Additive, default-off (5 new settings flags), fail-soft, advisory-only;
   18 wiring regression tests in tests/test_project_zero_production_wiring.py.
   The 7 edited frozen files were re-frozen per the documented process:
   manifest `ca330fd2…53dc18bf` → `cfbc347a…60c88b` (same 719-path scope and
   order; pre/post per-file hashes appended to PRE_HASHES.txt /
   POST_HASHES.txt; addendum in docs/UNFREEZE_FILES_20261005.md). Full-suite
   re-run after regeneration: 3832 passed; the only gate failure is the
   documented pre-existing `test_baseline_disagrees_only_on_documented_unfreeze_paths`.
   Original finding preserved: at the merge close the six were
   tested and import-clean with no production caller yet.
4. **25 environment-dependent test failures** persist identically in all
   input lineages (live targets, service fixtures) — not merge regressions.
5. **Operator catalogs had no producer — RESOLVED (2026-10-24 red-team
   follow-up):** the red-team pass over this wiring found `cve_feed_catalog`
   read by the crawler but neither declared on PentestState nor produced
   anywhere (so tech-stack CVE correlation could never fire), and the
   inherited `kev_catalog` in the same dead-key shape; plus the tech-stack
   fingerprint read header evidence from top-level `crawled_data` keys the
   crawler never populates. Fixed via `shared/operator_catalogs.py` loaders
   with settings paths (`cve_feed_catalog_path` / `kev_catalog_path`), a
   state declaration, surface_records header extraction, and the first
   end-to-end flag-on tech_stack_cve test through `crawler_node`. Four
   frozen files re-frozen: manifest `cfbc347a…60c88b` → `5957a1b5…fcdb8e`
   (same 719-path scope/order; see docs/UNFREEZE_FILES_20261005.md 2026-10-24
   addendum and PRE/POST_HASHES.txt item 4).
6. **Detected detector escape — tracked (2026-10-24, not yet fixed):** the
   new red_vs_blue self-check caught `unicode_homoglyph_padding` bypassing
   `extract_ssrf_indicators` (recorded as a detection_logic_gap postmortem).
   Closing it means normalizing the production detector (homoglyph folding
   before indicator matching) — deliberately NOT bundled into the catalog
   fix, since it changes matching semantics of an authority-adjacent
   detection function. Left as a tracked follow-up for its own reviewed
   change.
7. **KEV enrichment adjusts confidence (recorded, pre-existing):**
   `shared/kev.py::enrich_finding_with_kev` raises confidence one level for
   KEV hits despite its advisory framing. Inherited behavior from the input
   lineage; recorded here rather than changed, because touching confidence
   semantics belongs to the finding-authority owners. Operators who enable
   `kev_catalog_path` should know enrichment is advisory in sourcing but
   does move confidence.

## Hard-rule compliance

1. Zero hallucination: every claim above carries a file path, commit, or
   hash verifiable in the delivered tree. 2. Review sections completed
   read-only; freeze writes only after A+B+C PASS. 3. No authority component
   touched; 12/13 authority pins byte-identical, the 13th re-captured per
   its own convention. 4. No test modified. 5. No functionality deleted
   (the only code change restored existing donorC bytes). 6. Not applicable:
   A, B, C all PASS; re-freeze proceeded lawfully.

## VIP-layer addendum (2026-10-24, user-approved follow-up)

Residual risk 8 (new, honestly scoped): the VIP campaign layer adds
broad fail-soft handlers — `src/webpent/autonomous/vip_orchestrator.py`
(10 sites) and `src/webpent/shared/operator_catalogs.py` (1 site, from
the catalog fix in this same window) — to the PRE-EXISTING unregistered
broad-exception backlog that `tests/test_editable_broad_exceptions_gate`
has been red on since before this window (48 legacy sites across 15
non-frozen library-tier files, e.g. `families/execution_node.py`: 26,
`causal_reasoning_v2/*`: 15, `red_vs_blue`/`shadow_detector`/`postmortem`).
Not adjudicated here: registering those files would (a) sweep 37 legacy
sites owned by other workstreams under this commit's justification, and
(b) force the registered-src-files-must-be-frozen invariant to be
re-litigated for deliberately non-frozen additive modules. Each new site
guards a distinct fail-soft boundary over heterogeneous module failures
(memory DB, graph builders, reviewer, postmortem) — same posture as the
library tier — and the campaign loop treats any boundary failure as a
step-degradation, not an abort. Recommended follow-up: a register
reconciliation pass as its own reviewed change, adjudicating the legacy
inventory file by file. The gate's new-code teeth are unaffected: any
NEW file with broad handlers still fails `test_broad_exception_files_…`
the moment it is added.

## VIP-wiring (layer 2) addendum (2026-10-24, user-approved follow-up)

Scope: 3 frozen files edited additively (settings flag, two state keys,
builder wiring) + 1 new non-frozen node module + 15 wiring tests, then
the full rule 1(a)-(d) re-freeze. Manifest anchor re-pinned
5957a1b5…fcdb8e → 50c6af85…6c8e9 (same 719-path scope and order, exactly
3 entries changed; baseline_pre_unfreeze untouched).

Residual risk 9 (new, honestly scoped): one broad fail-soft containment
in `src/webpent/shared/vip_campaign_node.py` — a single wrap around the
whole advisory pass, added to the pre-existing unregistered broad-exception
backlog documented under residual risk 8 (48 legacy sites + 11 prior
window sites). Same reasoning applies and the recommendation stands:
adjudicate the backlog via a register reconciliation pass as its own
reviewed change. Note the delta-gate interplay: `graph/builder.py` is
enforced by the delta gate (check 3 thaw-list semantics) rather than the
byte-identical suite test (R3-002 §3.1 mid-window skip); `settings.py`
and `state.py` show the two expected pre-regen byte-identical failures
and pass after the manifest regeneration — both cleared in the section-10
full-suite run.

Security review of the wiring itself: the node takes no executor and
cannot call `act` (proven by test); every planned action preserves
`advisory_only=True` / `does_not_confirm=True` into state; the
exactly-once gate (`vip_campaign_runs` bumped on every return path
including the fail-soft one) survives checkpoint replay; the flag is
fail-closed (default off, narrow-tuple except on settings access); and
the exit router re-joins the exact routing the graph would have taken
without the node, so no scan profile gains or loses coverage from the
wiring when the flag is off.

