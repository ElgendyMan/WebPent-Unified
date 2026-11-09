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


---

## Lessons-learning-loop re-freeze addendum (2026-10-24, Proposal 1)

Scope of the re-freeze: three frozen files, all additive
(PRE/POST_HASHES.txt item 6; UNFREEZE_FILES addendum of the same date):

- `brain/lessons.py` — persistence activation. Advisory posture preserved:
  `is_advisory_only()` is still unconditionally True; store failures
  degrade fail-soft to memory (a corrupt or unwritable store can never
  raise into an engagement); the `approve_lesson` owner-approval HITL
  gate is unchanged and, because loading restores still-pending beyond-lab
  rows, it now survives restarts instead of silently losing them.
- `shared/prioritization.py` — `compute_lesson_adjustment` rides the
  EXISTING novelty channel (same clamp, same weight, no `_W_SUM` change):
  flag-off is arithmetically identical to the pre-2026-10-24 formula, so
  the influence flag cannot shift any pre-existing test's expectations.
- `config/settings.py` — two additive fields, both default-off/conservative.

No residual-risk additions. Notes: the new `brain/lesson_emission.py`
module is outside the manifest (additive, non-frozen) and holds no
try/except at all — its failure mode is a clean exception at the call
site, not a swallowed one. The bounded-influence design (penalty ceiling
equal to the novelty cap) means even a ledger full of poisoned lessons
could not force a decision, only tilt an ordering by at most the same
amount the novelty channel may already tilt it. The two pre-existing
`test_editable_broad_exceptions_gate` failures and the baseline-disagrees
frozen-gate failure pre-exist at HEAD (verified by stash test) and are
unchanged; the three new byte-identical failures were the expected
pre-regen state and cleared with the manifest regeneration.

## Causal-chain-widening re-freeze addendum (2026-10-24, Proposal 2)

Scope of the re-freeze: four frozen files, all additive
(PRE/POST_HASHES.txt item 7; UNFREEZE_FILES addendum of the same date):

- `production/chain_composer.py` — chain types generalized into the
  frozen `ChainTypeSpec` dataclass with a fail-closed module-level
  registry and a third registered chain type (`idor_plus_mass_assignment`).
  The anti-fake proof discipline is byte-for-byte preserved: dependency
  digest, real execution, register-until-proven, inflation guards,
  `proven_chains()` as the only report-facing surface. Unknown chain
  types fail closed; the self-owned exclusion gate is now strictly more
  conservative (reads the registry from every leg). The 10 pre-existing
  `test_v1_chain_composer.py` proof tests passed unchanged on the first
  run — no proof-semantics drift.
- `agents/validator/agent.py` — advisory causal-candidate wiring behind
  `enable_causal_chain_candidates` (default False): confirmed findings
  feed causal_reasoning_v2's documented `on_finding_confirmed` hook;
  candidates land in `state.causal_chain_candidates`, never
  auto-confirmed. Fail-soft via a narrow exception tuple (an `except
  Exception` here would trip the exception-hygiene AST gate on this
  CRITICAL_FILE). Structurally absent when the flag is off.
- `config/settings.py` — two additive flags, both default False:
  `enable_causal_chain_candidates`, `enable_chain_review_section`.
- `state/state.py` — `causal_chain_candidates` merged advisory list.

No residual-risk additions. Notes: the reporter seam lives in the NEW
non-frozen `src/webpent/reporter/chain_review.py` — its suggested
"chains under review" section is structurally absent when the flag is
off (not merely empty) and always advisory-labeled with an inline UNPROVEN
warning when on, so a proposed chain still cannot reach a report as an
outcome without real proof through the normal pipeline. The exception
hygiene note above is deliberate: the wiring in a frozen CRITICAL_FILE
uses an explicit exception tuple precisely because the AST gate would
reject a broad handler there.


## Capability-batch re-freeze addendum (2026-10-25, Proposals 2/4/5/6)

Scope of the re-freeze: nine frozen files, all additive
(PRE/POST_HASHES.txt item 8; UNFREEZE_FILES addendum of the same date):

- `shared/llm.py` — `verify_llm_consistency` is advisory by construction:
  it returns a `ConsistencyResult` (majority verdict + agreement score),
  never raises, never decides, and makes zero LLM calls when the flag is
  off. Callers may only attach it as metadata (rabbit-hole `origin_detail`
  annotation for RCE/SSRF hypotheses; `supporting["llm_consistency"]` for
  CRITICAL/HIGH bounty findings). "LLM proposes, deterministic logic
  decides" is preserved: the agreement score cannot confirm, refute, or
  gate anything.
- `api/app.py` — the worker-status surface is read-only end to end
  (stats/ping/active snapshot + HTML dashboard), admin-only, 404 when
  `enable_worker_status_endpoint` is off (default), and structurally
  incapable of mutating worker state. Celery ping's list-of-dicts shape
  and its dict shape are both handled.
- `production/validators.py` + `agents/validator/registry.py` — the 6 new
  canonical validators follow the ONE-authority-per-family contract:
  pure functions over captured evidence, fail-closed on missing evidence,
  CONFIRMED only through an observed differential the negative control
  does not reproduce. Cache poisoning demands the two-request proof
  (poison + unpoisoned victim) and rejects self-reflection via
  `request_headers`; prototype pollution requires a benign-key control;
  GraphQL depth findings REFUTE below the timing thresholds rather than
  extrapolate a DoS.
- `config/settings.py` — four additive flags, all default False.
- `graph/builder.py`, `models/findings.py`, `agents/rabbit_hole/agent.py`,
  `reporter/bounty_report.py` — flag-gated wiring (probe nodes, 6 new
  VulnClass values, advisory annotations), structurally absent when off.

No residual-risk additions. Notes: the probe agents are non-frozen NEW
packages with hard bounds (10-request cap, 8s timeout, GET-only markers)
and the validators never see more than the probes could have captured.
The `test_frozen_module_gate.py` baseline-drift union was extended with
`CAPABILITY_BATCH_20261025_DRIFT_PATHS` exactly for the 9 paths above —
documenting the drift, not weakening the gate (a 10th drifting path still
fails). Verification: the 4 new test files (41 tests) all pass; the frozen
gate suite is 721/721 GREEN at the new anchor `12a3e0d0…1832b3`; full
suite 3948 passed / 32 failed with the delta vs pristine HEAD being only
the manifest byte-identity REDs the regeneration clears.

## Self-test-harness re-freeze addendum (2026-10-25, Proposal 6)

Scope of the re-freeze: ONE frozen file, purely additive
(PRE/POST_HASHES.txt item 9; UNFREEZE_FILES addendum of the same date):

- `config/settings.py` — the single flag `enable_benchmark_gate`
  (default False). The flag gates nothing in the production pipeline:
  the harness (`benchmark/fixtures/`, `metrics_store.py`,
  `scripts/benchmark_gate.py`) is importable library code either way.
  When opted in, its only network exposure is loopback fixture servers
  (ephemeral port, 127.0.0.1) whose URL is added to the
  engagement-scope allowlist for the run and removed at exit — the
  SSRF guard stays fully in force for the probe nodes themselves.

No residual-risk additions. The fixture plants a KNOWN vulnerability
set scored against the canonical validators, so the harness measures
the real pipeline's recall/false-positive rate and cannot inflate it:
CONFIRMED still requires the observed-differential proof shape the
validators enforce. Verification: 16/16 vulnbox tests GREEN; gate run
PASS (recall 1.00, FP=0, FN=0); manifest regen 719/719 OK at anchor
`ab17f455…b526e`; baseline-drift union unchanged (settings.py was
already a documented drift path).

## Proposals 1+2 re-freeze addendum (2026-10-25: refutation learning + coverage scheduling)

Scope of the re-freeze: THREE frozen files (PRE/POST_HASHES.txt item
10; UNFREEZE_FILES addendum of the same date):

- `config/settings.py` — three additive flags, all default
  False/empty. The flags gate nothing by default: the ledger hook and
  the planner advisory are structurally inert early-returns when off.

- `production/validators.py` — one flag-gated capture hook between the
  validator call and its return. Contract: fail-soft (any storage
  error is swallowed; the validator's outcome is returned unchanged),
  redaction-safe keys (class + truncated netloc+path hash + path
  label; no URLs, no payloads), CONFIRMED resets the pair. Reads fail
  OPEN: a broken ledger means "run the probe", never "skip detection".

- `agents/planner/agent.py` — one flag-gated advisory block. The
  advisory is deterministic text over explicit state cells and ledger
  patterns, delivered as an untrusted data block with the same
  discipline as `learned_context`: it never carries commands, never
  routes the graph, and degrades to the unmodified plan on failure.
  With the flag off the prompt and result are byte-identical to
  before (pinned by test).

Residual-risk assessment: the ledger records only refutation COUNTS
per (vuln class, truncated target fingerprint) and path labels — no
finding payloads, no URLs, no secrets. Suppression is advisory and
fail-open at every layer (flag off, missing URL, storage error, no
target). Coverage scheduling is pure computation over state the
pipeline already holds, with a determinism-pinned clock. No exploit
capability is added by this re-freeze; the probe nodes that consume
the suppression gate remain fully bounded by their existing caps and
the SSRF-guarded client.

Verification: 41/41 new tests GREEN (ledger lifecycle, fail-open/fail-soft
contracts, flag-off inertness of the capture hook and both probe
suppressors, cell generalization/dedup, scheduler ordering and plateau,
planner byte-identity and advisory-on paths, file-backed persistence);
affected suites 63 tests GREEN; manifest regen 719/719 OK at anchor
`32b09b34…1591`; baseline-drift union extended by one new path
(`agents/planner/agent.py`).

## Proposal 3 re-freeze addendum (2026-10-25: OOB collaboration engine)

Scope of the re-freeze: FIVE frozen files (PRE/POST_HASHES.txt item
11; UNFREEZE_FILES addendum of the same date):

- `config/settings.py` — three additive settings, all default
  False/empty: `enable_oob_collaboration` (master flag),
  `oob_collaborator_domain` (empty = engine disabled/fail-closed),
  and `oob_callbacks_db` (empty = in-memory store). With the flag off
  the payload_generator injection point is an early return and the
  pipeline is byte-identical to before (pinned by test).

- `production/validators.py` — three registry entries mapping the new
  families (BLIND_SSRF, XXE_OOB, BLIND_SQLI) to thin wrappers around
  `validate_blind_oob_confirmation` via the same late-binding
  `_oob_validator` factory pattern as `_graphql_validator` and
  `_advanced_validator` (lazy import, no module-level import cost).

- `models/findings.py` — three new VulnClass members before UNKNOWN
  (`blind_ssrf`, `xxe_oob`, `blind_sqli`). None routes into
  EXPLOITABLE_CLASSES: the confirmation is a callback differential,
  not a payload-injection, so these families never enter exploit
  tooling.

- `memory/db.py` — two new tables (`oob_probe_bindings`, token PK;
  `oob_callbacks`, autoincrement + token/seen_at index) wired into
  BOTH bootstrap sites, plus five DatabaseManager methods with
  fail-soft read/write contracts and fail-closed identity
  (`record_oob_callback` returns False for unregistered tokens —
  unknown tokens are dropped, never stored).

- `agents/payload_generator/agent.py` — one flag-gated block before
  the summary assembly: with the flag off nothing runs; with it on,
  `attach_oob_probes` stamps blind-family findings with per-probe
  OOB identity (128-bit `secrets.token_hex(16)` tokens, evidence keys
  `oob_token`/`oob_host`/`oob_registered_at`/`oob_engagement_id`) and
  merges bounded probe payloads (max 3 per finding) into the pass.
  Any failure degrades to the unmodified payloads (fail-soft).

Residual-risk assessment: tokens are 128-bit random and per-probe;
unregistered tokens presented to the collector are dropped and never
stored; source IPs are recorded only as SHA-256-truncated
fingerprints (never raw addresses); callback details are bounded at
256 chars. The validator is fail-closed: CONFIRMED only on a
matching-token callback inside the evidence window with a silent
negative control (OBSERVED_DIFFERENTIAL); a control callback REFUTES
(host phones home on its own); collaborator failures are
INCONCLUSIVE, never a halt and never a refutation. The
24-hour-callback-TTL prune bounds storage. No exploit capability is
added: the engine only observes callbacks the operator's own
collaborator domain receives.

Verification: 45/45 new OOB tests GREEN (registration fail-closed,
deterministic matcher, DB round-trip identity, validator contract
incl. live-mode control polling and INCONCLUSIVE path, 3-family
registry routing, byte-identity flag-off, 6 accelerated-pulse e2e
scenarios); frozen-gate suite 721 tests GREEN; manifest regen 719/719
OK at new anchor `6909ce8f…02cb` (pinned in `gate_frozen_delta.py`
and `r3_anchor_check.py`); baseline-drift union UNCHANGED —
`agents/payload_generator/agent.py` was already a documented drift
path, and `config/settings.py` / `production/validators.py` were
documented under prior addenda.

## Proposals 4+5 re-freeze addendum (2026-10-25: JS discovery + session pool)

Scope of the re-freeze: SIX frozen files (PRE/POST_HASHES.txt item 12;
UNFREEZE_FILES addendum of the same date):

- `config/settings.py` — two additive default-off flags:
  `enable_js_discovery` (Proposal 4) and `enable_session_pool`
  (Proposal 5). With the flags off no JS bundle is fetched and no
  session health/re-auth machinery is engaged; pipeline behavior is
  byte-identical (pinned by tests).

- `models/findings.py` — one new VulnClass member before UNKNOWN,
  `PRIVILEGE_DIFFERENTIAL` ("privilege_differential"). Does NOT route
  into EXPLOITABLE_CLASSES: the differential observation is the
  evidence; no payload-injection exploitation is implied.

- `production/validators.py` — a late-binding `_privilege_validator`
  factory (same lazy-import pattern as the GraphQL/advanced/OOB
  factories) plus the `PRIVILEGE_DIFFERENTIAL` registry entry mapping
  to `production/privilege_validator.py::validate_privilege_differential`
  — the ONE authority for the cross-principal family.

- `agents/access_control/agent.py` — the flag-gated session-pool
  filter (health probe + ONE bounded re-auth per dead identity
  session; unrecoverable roles are EXCLUDED from probing and declared
  as engagement limitations — no result is ever produced from a dead
  session) and the privilege-differential confirmation gate on the
  Tool-Confirmed promotion path (any validator error or
  non-confirmation keeps the finding at Needs Human Review; the flag
  can only make confirmation STRICTER).

- `workers/pentest_worker.py` — a flag-gated, READ-ONLY session-pool
  snapshot in the worker status dict (role, healthy, age, re-auth
  count — never any session material). Fail-soft: with the flag off
  or on any import/poll failure the status dict is unchanged.

- `graph/builder.py` — the `js_discovery` node wired into the
  deep-probe chain (request_smuggling → js_discovery → graphql_testing
  → advanced_web_vulns). Gating lives entirely in the agent (flag
  default-off AND JS-URL evidence gate); the wiring is unconditional.

Residual-risk assessment: the JS extractors are pure regex with no
code execution and no network I/O; secret hints are redacted at the
source (6-char bounded preview + length, never verbatim) and are
deliberately NOT emitted as findings — unvalidated secret claims
would be a false-positive factory. JS fetching is same-origin only,
bounded (20 files x 5 MB, 20 requests, 8 s timeout) and passes
through the SSRF-guarded client with a node-local rate governor. The
session pool never exposes session material (snapshot() is a
read-only status view; reauth callbacks resolve credentials only
through the existing bounded login path). Fail-closed everywhere:
dead session = excluded, not probed-with; validator error = Needs
Human Review, never auto-confirm.

Verification: JS-discovery + session-pool suites 36/36 GREEN
(extractors incl. redaction and bounds; node flag-off identity,
same-origin filter, fail-soft degradation, GraphQL merge; SessionPool
fail-closed acquire, bounded re-auth, material-free snapshot; the
privilege-differential contract — CONFIRMED only on the differential,
three REFUTED paths, INCONCLUSIVE on transport failure; registry
routing; worker flag-off identity); frozen-gate suite 721 GREEN;
manifest 719/719 OK (sha256sum -c) at new anchor `0a6e5393…61a7`
(pinned in `gate_frozen_delta.py` and `r3_anchor_check.py`);
baseline-drift union extended by exactly two NEW paths
(`agents/access_control/agent.py`, `workers/pentest_worker.py`);
`config/settings.py`, `production/validators.py`,
`models/findings.py` and `graph/builder.py` were already documented
drift/thaw paths under prior addenda.

Validator-coverage fix found during test-writing: the
`candidate_body_matches_denial` refutation path was UNREACHABLE as
first written (it compared via `responses_similar`, which fails on
differing statuses, while `candidate_denied` always fired first).
Replaced with a status-independent body comparison
(`_denial_body_matches`: exact body, fingerprint match, or >= 0.85
token overlap) ordered AFTER the status-level checks, so a spoofed
success (200 carrying the denial page without error keywords) is now
caught. Test added; contract unchanged: fail-closed, one authority.

## Addendum 2026-10-27 — Proposals 8+10 re-freeze (campaign resume + safety governor v2)

Seven frozen files were edited; manifest regenerated over the SAME
719-entry scope in the SAME order; sha256sum -c verifies 719/719; new
anchor `138b6f2b…6f46` pinned in `scripts/gate_frozen_delta.py` and
`scripts/r3_anchor_check.py`; PRE/POST_HASHES.txt Item 13 appended.

Per-file diff (reviewable, all additive and flag-gated; every flag
defaults OFF so flag-off behaviour is byte-for-byte the pre-edit
behaviour):

- `config/settings.py` — six additive fields after the Proposals 4+5
  block: `enable_campaign_resume`, `enable_request_ledger`,
  `enable_kill_switch`, `enable_llm_spend_cap`,
  `enable_robots_override` (all bool, default False) and
  `llm_token_cap_per_engagement` (int, default 1,000,000). No
  existing field touched.

- `workers/pentest_worker.py` — four additive blocks:
  (1) `_MAX_CAMPAIGN_RETRIES_HINT = 3` module constant;
  (2) redelivery branch: flag-gated auto-resume — `should_auto_resume`
      (bounded 3 retries, exponential backoff 30/60/120/600s cap) and
      only interrupt markers written by SoftTimeLimitExceeded handlers
      are resumable; HITL pauses never write markers, so a human-in-
      the-loop pause is never auto-resumed; on any error it falls
      through to the existing report-only path;
  (3) both SoftTimeLimitExceeded handlers: flag-gated interrupt-marker
      write (reason `soft_time_limit`, state fingerprint audit-only)
      followed by `self.retry(countdown=_resume_countdown)`; flag off
      → the existing terminal `soft_timeout` return, unchanged;
  (4) status snapshot: flag-gated `resumable` + `safety` sections.

- `api/app.py` — two additive admin endpoints
  (`POST /api/v1/safety/kill`, `POST /api/v1/safety/release`), each
  gated on `require_role("admin")` AND the `enable_kill_switch` flag
  (404 when the flag is off). Read-only status returned by both.

- `shared/http.py` — flag-gated append of `ledger_request_hook` to the
  request hooks of `make_safe_httpx_client`; the whole block is inside
  try/except, so observability can never break client construction.

- `shared/rate_governor.py` — kill-switch check placed FIRST inside
  `acquire` (before the already-aborted/cap/error-rate checks), so an
  engaged switch aborts every permit in the same request cycle
  (≤5s propagation bound) WITHOUT consuming host state; flag off →
  the check never runs.

- `llm_researcher/providers/base.py` — flag-gated
  `enforce_spend_cap(response)` after the token tally in `generate()`;
  at cap the LLM lane fails CLOSED by replacing LLMResponse with an
  `LLM_SPEND_CAP_REACHED` error of the same type, so every downstream
  fallback takes its existing deterministic path; try/except keeps
  enforcement from ever corrupting a real response.

- `recon/autonomous_crawler.py` — the `respect_robots=False` lift in
  `_robots_allows` now passes through the Proposal 10 agency double
  gate when `enable_robots_override` is on (settings flag AND
  explicit per-engagement allowlist env `WEBPENT_ROBOTS_OVERRIDE_
  ENGAGEMENTS`); flag off → legacy posture unchanged. Fail-closed:
  any gate error keeps robots respected.

New packages `webpent.resume` / `webpent.safety` (unfrozen, all
flag-gated): interrupt markers + probe ledger (deterministic probe id
= sha256(target|kind|path); reads fail in the SAFE direction — ledger
error → False = duplicate probe safe, never a skipped probe; 50k
rows/engagement), kill switch (in-process lock-guarded by design — a
safety interlock, not shared config; worker restart starts UNENGAGED,
operator re-issues the freeze; best-effort Redis fanout for
multi-process), request ledger (observability only, fail-soft
everywhere, 100k rows / 7-day TTL, `prune()` for the amortized
sweep), LLM spend governor (per-engagement counters, cap fail-closed
via dataclass replace), agency double gate, and a read-only combined
`safety_snapshot()`.

Verification: campaign-resume + safety-governor suites 51/51 GREEN
(default-off flag contract; probe-id determinism and separator-collision
resistance; backoff 30/60/120/600 cap; marker lifecycle incl.
first-reason-wins and retry-budget exhaustion; probe-ledger SAFE read
direction on corrupted store; state fingerprint audit-only and never
raising; kill-switch engage/release/idempotent-first-reason; rate-
governor integration — abort before cap, host state not consumed,
release restores; request-ledger fail-soft record, memory
degradation, TTL and row-cap via injected clock, hook fail-soft;
spend-cap replacement contract incl. at-cap, provider-error
passthrough, and flag-on generate capping after threshold; agency
double gate — flag-off legacy lift, flag-on fail-closed, allowlist
authorization, crawler fall-through to robots respect); frozen-gate
suite 721 GREEN; baseline-drift union extended by exactly four NEW
paths (`llm_researcher/providers/base.py`,
`recon/autonomous_crawler.py`, `shared/http.py`,
`shared/rate_governor.py`); `config/settings.py` (TEAM_MERGE),
`workers/pentest_worker.py` (Proposals 4+5) and `api/app.py` (R3
ruling-thaw) were already documented drift/thaw paths under prior
addenda.

Two defects found and fixed during test-writing, both caught by the
SAFE-direction contract rather than by inspection: (1)
`state_fingerprint` referenced `f.get("title")` with `f` undefined,
so dict findings always degraded the fingerprint to "unavailable"
inside the audit-only except; fixed to `finding.get(...)`. (2)
`was_executed`'s memory path could still raise when the store
degraded past `self._memory = None`, violating "ledger error →
False"; the whole body is now wrapped so ANY error resolves False.
Also fixed `RequestLedger` prune semantics: ttl ≤ 0 now means no TTL
expiry (a ttl-0 sweep previously deleted every row).

Post-verification correction: the first full-suite run surfaced one
NEW failure beyond the 25 pre-existing — the P1 hygiene gate
(`test_named_critical_modules_have_no_broad_exception_handlers`) on
`shared/http.py:980`, the ledger-hook attachment block, which had
been written with a broad `except Exception`. Narrowed to
`(ImportError, AttributeError, RuntimeError)` — the only failures
possible there — and re-pinned: manifest updated for `shared/http.py`
(new file hash `1b54480c…47ca6`), anchor recomputed to
`138b6f2b…6f46` and re-pinned in both gate scripts, POST_HASHES
Item 13 corrected. Full suite re-run: failure set IDENTICAL to clean
HEAD (25 failures, byte-for-byte the pre-existing list).

## Addendum 2026-10-28 — Proposals 7+9 re-freeze (chain v3 + workflow fuzzing)

1 frozen file edited for Proposals 7 (chain v3 artifact-flow replay)
and 9 (workflow-integrity fuzzing): `config/settings.py` — two
additive default-off fields, `enable_chain_v3` and
`enable_workflow_fuzzing`. Everything else is NEW unfrozen code:
`chained_exploits/graph_v3.py` (confirmed-inventory artifact-flow
graph, simple paths max depth 4, deterministic Delta-impact ranking,
replayable curl PoC per chain) and the `workflow_fuzzing/` package
(`strategies.py` bounded mutations — reorder/skip/replay/price-tamper/
race, max 8 steps, each mutation carrying a benign control twin;
`agent.py` confirmation contract: a break is CONFIRMED only when the
mutated step succeeds with a state delta AND the control fails on the
same mutation — one authority per family, fail-closed).

Flag-off invariance: with both flags off no chain is built or emitted
and no workflow mutation executes, so pipeline behavior is
byte-identical to pre-feature; the v2 live planner is unchanged.

Verification: proposal suites (tests/test_chain_v3.py,
tests/test_workflow_fuzzing.py) GREEN; frozen-gate suite GREEN;
manifest regenerated same scope/order, 719/719 OK, new anchor
`2be9ce19…0cc0` pinned in `scripts/gate_frozen_delta.py` and
`scripts/r3_anchor_check.py`; no new drift-union paths needed —
`config/settings.py` is already a documented TEAM_MERGE drift path;
PRE/POST Item 14. Full-suite comparison against clean HEAD 2447f2e:
failure set IDENTICAL (25 pre-existing failures, byte-for-byte).
