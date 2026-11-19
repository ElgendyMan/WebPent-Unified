# The 5 Unfrozen Files — Contracts & Documentation (2026-10-05)

On 2026-10-05 five files were deliberately unfrozen from the frozen trust
manifest and modified **additively, default-off** (approval record:
`UNFREEZE_APPLIED_REPORT_20261005.md`; defect fixes:
`UNFREEZE_FIX_REPORT_20261005.md`). The frozen manifest was regenerated after
the changes were accepted, so the gate is 695/695 OK again — the pre-change
state is preserved in `frozen_modules.sha256.baseline_pre_unfreeze` and is
pinned by `tests/test_frozen_module_gate.py::test_baseline_disagrees_only_on_documented_unfreeze_paths`.

| # | File | Change | Default-off gate | Audit events |
|---|---|---|---|---|
| 1 | `src/webpent/agents/hunter_runner.py` | `run_hunter_campaign(..., recovery_enabled=False, enrichment_enabled=False)`; wraps `exploit_callback` with `RecoveringExploiter` when recovery is on; passes `enriched_context` into `HypothesisGenerator.generate` when enrichment is on. Lazy imports; recovery fail-closed; enrichment fail-soft. | both params `=False` | `campaign.halted` on propagated halt |
| 2 | `src/webpent/recon/hypothesis_generator.py` | `generate(..., enriched_context=None)`; advisory merge into `payload_advice` + metadata only. Never overrides scope/family selection; forbidden authority fields rejected by ContextEnricher. | `None` | — |
| 3 | `src/webpent/recon/login_executor.py` | New public `login_with_api_key(alias, value, name="X-API-Key", validation_url=None)`. **Fail-closed:** missing `validation_url` → `success=False, reason="validation_url_required"`. `_validate_material` honors `material.name` header for `api_key` kind. | opt-in method | — |
| 4 | `src/webpent/recon/auth_detector.py` | 5th auth signal `api_key` (X-API-Key/Apikey header; non-Bearer/non-Basic Authorization; `?api_key=`/`?key=` query — explicit evidence only, generic `?key=` FP removed in D3). Conservative confidence 0.4–0.6; ranked lowest priority. | detection-only, advisory | `auth.detected` |
| 5 | `src/webpent/recon/principal_provisioning.py` | `api_key` added to the allowed auth-type sets (2 sites) so an `api_key` AuthSignal binds as M4 material `api-key:name=value`. Still gated by existing provisioning flags. | existing flags | — |

## Rules for future edits

1. These five files are again covered by `frozen_modules.sha256`. Any further
   edit requires: (a) reviewable diff, (b) manifest regeneration via the
   documented review process, (c) full-suite re-run, (d) update of this doc
   and the baseline policy.
2. The baseline manifest must always disagree with the current tree on
   **exactly** these five paths — enforced by test. A sixth differing path
   fails `tests/test_frozen_module_gate.py`.
3. `session_recovery_bridge.py`, `auth_resilience.py`, `session_recovery.py`,
   `planner_enrichment_bridge.py`, `browser_hypothesis_bridge.py`,
   `hypothesis_priority_contract.py`, `learning_ab_contract.py`, and
   `production/validators.py` are additive sprint modules — NOT in the frozen
   manifest; they are covered by the regular suite and ruff.

## TEAM-MERGE re-freeze addendum (2026-10-22)

The donorC+donorV team-merge (2026-10-22) was closed with a manifest
regeneration after the documented review process:

1. Reviewable diff: the 31 divergent frozen paths are enumerated and
   classified KEEP_MERGED_INTENTIONAL in `MERGE_REPORT.md` and in the
   TEAM-REVIEW-REFREEZE `REVIEW_REFREEZE_REPORT.md` Section B (hostile
   review: Sections A-C all PASS before any freeze write; pre/post hashes in
   `PRE_HASHES.txt` / `POST_HASHES.txt`).
2. `frozen_modules.sha256` was regenerated over the SAME 719-path scope and
   order (no scope change, no new entries, no entries dropped) from merged
   tree bytes. Manifest sha256: `2424c3d9...c06c454` (pre) →
   `ca330fd2...53dc18bf` (post). `frozen_modules.sha256.baseline_pre_unfreeze`
   was NOT touched.
3. Full-suite re-run executed after regeneration (see
   REVIEW_REFREEZE_REPORT.md Section D.3 for the counts).
4. This doc is the baseline-policy bookkeeping update for the pass.

Honest gate state after re-freeze: all 719 `test_frozen_file_byte_identical`
invariants are green (the 30 merge-drift failures are cleared).
`test_baseline_disagrees_only_on_documented_unfreeze_paths` still FAILS, and
failed identically BEFORE the merge: the v15.2 lineage regenerated the
manifest across windows v9-v15.2 without extending the test's
`expected_drift` constant, so the pre-unfreeze baseline disagrees with the
manifest on 28 undocumented paths that predate this merge (inputs to that
assertion are `frozen_modules.sha256` + `frozen_modules.sha256.baseline_pre_unfreeze`
only, both last touched at donorC commit `c916990`). Per the no-test-rewrite
rule of this pass the assertion was left as-is; the doc, not the test, carries
the correction. Additionally, `docs/integration/WEBPENT_AUTHORITY_MANIFEST.json`
was re-captured at this unit boundary (single entry: validator/active_checks.py;
the other 12 pinned files, CausalGuard / ProofBundle / Replay /
ReplayVerifier / ToolBoundary included, verified byte-identical to their
pins). `scripts/verify_frozen_manifest.py` → OK (13 files).

## PROJECT-ZERO production wiring re-freeze addendum (2026-10-22, item 3)

The user-approved follow-up item 3 (wiring the six library-tier Project
Zero modules to production callers) edited seven frozen files additively;
the manifest was regenerated afterward per rule 1(a)-(d):

1. Reviewable diff: all seven diffs are additive wiring only — 5 default-off
   settings flags, advisory state keys, and flag-gated helper calls; no
   existing behavior changed, findings/promotion/requests untouched. The
   wiring and its guarantees are pinned by
   `tests/test_project_zero_production_wiring.py` (18 tests) and recorded in
   `REVIEW_REFREEZE_REPORT.md` residual-risk item 3 and
   `ADDITIONS_AND_FIXES_20261022.md`.
2. `frozen_modules.sha256` regenerated over the SAME 719-path scope and
   order from tree bytes. Manifest sha256: `ca330fd2…53dc18bf` (pre) →
   `cfbc347a…60c88b` (post). Exactly 7 entries changed (the files below);
   `frozen_modules.sha256.baseline_pre_unfreeze` was NOT touched.
3. Full-suite re-run after regeneration: 3832 passed; failures are the
   pre-existing environment-dependent set plus the documented
   `test_baseline_disagrees_only_on_documented_unfreeze_paths` only.
4. This doc is the bookkeeping update. Delta-gate anchors re-pinned to the
   new manifest (`scripts/gate_frozen_delta.py`, `scripts/r3_anchor_check.py`);
   per-file pre/post hashes appended to `PRE_HASHES.txt` / `POST_HASHES.txt`.

The seven edited frozen paths (all default-off / advisory):

- `src/webpent/config/settings.py` — 5 PZ flags (all default False)
- `src/webpent/models/surface_security.py` — optional `surface_influence_graph` summary field
- `src/webpent/shared/surface_security.py` — flag-gated influence-graph attachment (+ missing import fixed)
- `src/webpent/state/state.py` — 4 advisory state keys (LangGraph drops undeclared keys)
- `src/webpent/agents/crawler/agent.py` — surface_drift / tech_stack_cve / taint SOURCES wiring
- `src/webpent/agents/validator/agent.py` — taint SINK recording on the persistence path (narrow-tuple except for P1 hygiene)
- `src/webpent/agents/devils_advocate/agent.py` — red_vs_blue self-check (composing shadow_detector), escapes → Postmortem



- Sprint regression: `test_hunting_sprint_*.py` 46/46; unfreeze fixes
  `tests/test_unfreeze_fixes.py` 13/13; chain/browser synthetic 21/21.
- Zero-FP: healthy 200 responses pass through `RecoveringExploiter`
  untouched; recovery triggers only after 3 consecutive dead-session
  responses; exhaustion halts (never loops) — see zero-FP cases in
  `test_hunting_sprint_session_recovery.py`.
- D2/D3/D4/D7/C7 defect fixes verified by the 13 fix-verification tests.

## Catalog-fix re-freeze addendum (2026-10-24, red-team follow-up)

The red-team pass over the 2026-10-22 Project Zero wiring found that two
advisory catalogs were consumed with no producer anywhere (`cve_feed_catalog`
— also undeclared on PentestState, so LangGraph would drop any producer's
update — and the inherited `kev_catalog`), that the tech-stack fingerprint
read header evidence from top-level `crawled_data` keys the crawler never
populates, and that no test exercised tech_stack_cve through `crawler_node`.
The fix edited four frozen files additively; the manifest was regenerated
afterward per rule 1(a)-(d):

1. Reviewable diff: a new non-frozen module
   `src/webpent/shared/operator_catalogs.py` (fail-soft JSON loaders with
   operator-visible settings paths `cve_feed_catalog_path` /
   `kev_catalog_path`); state declaration for `cve_feed_catalog`; loader use
   in the crawler's correlation site and the reporter's KEV enrichment site;
   surface_records header extraction in the tech-stack fingerprint helper;
   stale gate-script texts corrected (695→719 scope, `--baseline` help);
   PZ flags + catalog paths documented in `.env.llm.example`; 4 new tests in
   `tests/test_project_zero_production_wiring.py` (22 total, including the
   first end-to-end flag-on tech_stack_cve test through `crawler_node`).
2. `frozen_modules.sha256` regenerated over the SAME 719-path scope and
   order. Manifest sha256: `cfbc347a…60c88b` (pre) → `5957a1b5…fcdb8e`
   (post). Exactly 4 entries changed (the files below);
   `frozen_modules.sha256.baseline_pre_unfreeze` was NOT touched.
3. Full-suite re-run recorded in `ADDITIONS_AND_FIXES_20261022.md` section 8.
4. Delta-gate anchors re-pinned to `5957a1b5…fcdb8e`
   (`scripts/gate_frozen_delta.py`, `scripts/r3_anchor_check.py`); per-file
   pre/post hashes appended to `PRE_HASHES.txt` / `POST_HASHES.txt`.

The four edited frozen paths (all additive / fail-soft):

- `src/webpent/config/settings.py` — 2 catalog-path settings (default "")
- `src/webpent/state/state.py` — `cve_feed_catalog` state declaration
- `src/webpent/agents/crawler/agent.py` — loader use + surface_records headers
- `src/webpent/agents/reporter/agent.py` — loader use for `kev_catalog`

## VIP-wiring re-freeze addendum (2026-10-24, layer 2 of the VIP tier)

Layer 1 (commit c3a24c6) added the VIP Orchestrator as a code-only API,
explicitly NOT wired into the production graph. Layer 2 wires it in,
following the same additive pattern as the Project Zero wiring and the
autonomous controller: a new settings flag gates a single one-shot graph
node, the node body lives OUTSIDE the frozen manifest (so future changes
to the pass never need another re-freeze), and the graph edits are the
minimum possible (one constant, one import, two helpers, one exit router,
two one-line router insertions, one conditional registration, one
conditional edge block). Executed per rule 1(a)-(d):

1. Reviewable diff: new non-frozen module
   `src/webpent/shared/vip_campaign_node.py` (the one-shot perceive->plan
   pass, exactly-once accounting, one fail-soft containment); frozen edits
   below; 15 new tests in `tests/test_vip_graph_wiring.py` (flag default,
   registration, both entry routers, exit routing, node advisory contract,
   fail-soft bump, no-executor proof, graph-level edge map).
2. `frozen_modules.sha256` regenerated over the SAME 719-path scope and
   order. Manifest sha256: `5957a1b5…fcdb8e` (pre) → `50c6af85…6c8e9`
   (post). Exactly 3 entries changed (the files below);
   `frozen_modules.sha256.baseline_pre_unfreeze` was NOT touched.
3. Full-suite re-run recorded in `ADDITIONS_AND_FIXES_20261022.md` section 10.
4. Delta-gate anchors re-pinned to `50c6af85…6c8e9`
   (`scripts/gate_frozen_delta.py`, `scripts/r3_anchor_check.py`); per-file
   pre/post hashes appended to `PRE_HASHES.txt` / `POST_HASHES.txt`.

The three edited frozen paths (all additive, default-off, fail-closed):

- `src/webpent/config/settings.py` — `enable_vip_orchestrator` flag
  (default False) with its advisory-only contract documented at the site
- `src/webpent/state/state.py` — `vip_campaign_state` (merge_dicts) and
  `vip_campaign_runs` declarations
- `src/webpent/graph/builder.py` — `NODE_VIP_ORCHESTRATOR` constant;
  `vip_campaign_node` import; `_vip_orchestrator_enabled()` (settings
  flag, fail-closed) + `_vip_pass_pending()` (exactly-once) helpers;
  `route_after_vip_orchestrator` exit router; one-line hand-off in
  `route_after_disclosed_report_intel` (after the attack-graph branch)
  and `route_after_attack_graph`; conditional node registration;
  conditional exit edges back into the ordinary routing (budget cutoff →
  smart tier → strategist). The node never calls `act`: there is no
  executor inside the graph, so wiring the leader cannot make the graph
  send a single request it was not already sending.
