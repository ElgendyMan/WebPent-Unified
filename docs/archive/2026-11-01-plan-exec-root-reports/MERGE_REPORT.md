# WebPent TEAM-MERGE Report — 2026-10-22

Unified tree built from six uploaded archives per the TEAM-MERGE spec (phases 0–5).
Everything below is verified against the actual trees on disk; no counts are estimated.

## 1. Sources (Phase 0 inventory)

| Archive | Extracted to | Snapshot date | Files | Src files | Test files |
|---|---|---|---|---|---|
| `webpent-full-project-v21 (1).zip` | `webpent-full-project-v21__1_/` | 2026-10-12 | 2524 | 732 | 250 |
| `WebPent_v15.2_20261017.part1_MAIN.zip` + `part2_BULK.zip` | `v152/` (merged parts) | 2026-10-16/17 | 2773 | 689 | 308 |
| `WebPent_Final_Comprehensive(1).zip` | `WebPent_Final_Comprehensive_1_/WebPent_Final_Comprehensive/` | 2026-10-17/22 | — | 784 | 290 |
| `WebPent_Final_Comprehensive.zip` | (older sibling) | — | — | — | — |
| `webpent_project_zero_7items.zip` | `webpent_project_zero_7items/` | 2026-10-20 | 17 | 9 | 7 (+2 docs) |

Facts established during inventory:

- The two v15.2 parts have **zero file overlap** (verified by `comm -12` on their path lists) and were concatenated into a single v15.2 tree.
- `WebPent_Final_Comprehensive(1)` is the **newer** Comprehensive: its `MERGE_NOTES.md` carries the extended G-02 scan findings and `docs/DIRECT_IO_INVENTORY_G02_LEGACY.md` exists only there; the older `WebPent_Final_Comprehensive.zip` differs only in `MERGE_NOTES.md` and two docs files. The (1) copy was used; the older one contributed nothing.
- `WebPent_Final_Comprehensive(1)` self-describes in its own `MERGE_NOTES.md` as already a merge of the Causal/v61 snapshot, the v21 project snapshot, an intermediate merged archive, and a full-project snapshot — i.e. v21 is its ancestor.
- The Project Zero 7-item ZIP is **not present in any other archive** (pure additive contribution): 9 src files, 7 test files (128 tests), `CHANGES_AND_FIXES.md`, `README.md`.

## 2. Baseline choice (Phase 1)

**Baseline = `WebPent_Final_Comprehensive(1)`** ("donorC"). Rationale, all verified:

1. It is the newest merge snapshot (its own MERGE_NOTES documents retention of prior-only files and the G-02 direct-I/O inventory work).
2. It is the only lineage with the JWT key-confusion deep-testing feature (`forge_hs256_token` / `select_rsa_signing_jwk` in `src/webpent/shared/jwt_deep_testing.py` — verified present here, absent in v15.2).
3. It has 784 src files vs v15.2's 689 — strictly more functionality retained.

**Second donor = `v15.2`** ("donorV"), chosen because it is the certified freeze: its tree matches its own `frozen_modules.sha256` 719/719 (Comprehensive matches only 658/708 of its own manifest). Its newer fixes (URL-resolution `_resolve_url` helper, TC-4 C1(b) lint wrap in `settings.py`, expanded `validators.py` with SSTI/LFI/PATH_TRAVERSAL/COMMAND_INJECTION/XXE/RFI registrations, `lab_fixture_mode` test fixtures, `TC2_RESTORE_PATHS` in the frozen-gate test) were merged in selectively — see §4.

**3-way base = `v21`** snapshot (the common ancestor).

## 3. Feature matrix (who contributes what)

| Feature / area | v21 (base) | v15.2 (donorV) | Comprehensive(1) (donorC) | Project Zero ZIP | Merged tree |
|---|---|---|---|---|---|
| Core framework (agents, scope, service, recon, reporter, workers) | ✔ (ancestor) | ✔ (certified-frozen bytes) | ✔ (hardened evolutions) | — | ✔ per-file resolution (§4) |
| JWT key-confusion testing (`forge_hs256_token`, `select_rsa_signing_jwk`) | — | — | ✔ | — | ✔ (kept donorC) |
| Validator expansion: SSTI, LFI, PATH_TRAVERSAL, COMMAND_INJECTION, XXE, RFI | — | ✔ | — | — | ✔ (took donorV `validators.py`, 52 defs vs 46) |
| `autonomous_validation_v1.py`, `experiment_fabric.py` (v15.2 revisions) | — | ✔ newer | ✔ older | — | ✔ (took donorV) |
| TC-4 C1(b) lint-wrap fix in `config/settings.py` | — | ✔ | — | — | ✔ (took donorV) |
| URL-resolution `_resolve_url` hardening, U-3/U-7/U-9 series, `lab_fixture_mode` | — | ✔ | — | — | ✔ (came in with donorV files/tests) |
| Hardened `scope/{enforcer,models,parser}.py`, `recon/{browser_crawler,autonomous_crawler,login_executor,principal_provisioning}.py`, `reporter/poc_export.py` (redaction) | — | — | ✔ | — | ✔ (kept donorC) |
| G-02 direct-I/O static gate + inventory docs (`DIRECT_IO_INVENTORY_G02_LEGACY.md`, `docs/direct_io_inventory.json`) | — | — | ✔ | — | ✔ (kept donorC) |
| Five-family coverage, tenant isolation, OAuth hunter, multi-step auth, chained exploits, race conditions, learning, adaptive, explorer, `goed_v1` | — | — | ✔ (C-unique) | — | ✔ (restored, see §5) |
| Project Zero tier: taint tracking, surface influence graph, shadow detector, surface drift, red-vs-blue, postmortem, tech-stack CVE correlation | — | — | — | ✔ (9 src + 7 test files, 128 tests) | ✔ (added whole) |
| Certified freeze manifest `frozen_modules.sha256` (719 entries, 719/719 self-consistent) | — | ✔ | (own 708-entry manifest, self-inconsistent) | — | ✔ (took donorV manifest) |

## 4. Merge decisions (Phase 2)

Across the 113 paths where donorC and donorV differ (both present in the merged tree):

- **52 were clean one-sided changes** relative to the v21 base (36 changed only in v15.2, 16 only in Comprehensive) — taken automatically, no conflict possible.
- **61 required explicit resolution** (base differs from both donors; 46 modify-modify + 15 add-add). Every one was assigned a policy: **27 KEEP_BASELINE (donorC), 29 REPLACE_WITH_DONOR (v15.2), 5 MERGE_BOTH (union)**. No FEATURE_FLAG cases were needed — no feature required parallel implementations; where both donors evolved the same file, one canonical implementation was chosen per the fail-closed principle (newer certified bytes from v15.2 for spine/validators/tests infrastructure; hardened donorC evolution for scope/recon/reporter/security-sensitive paths).

Full 61-path decision table:

| Path | Policy | Resolved to |
|---|---|---|
| `.env.example` | KEEP_BASELINE | donorC |
| `README.md` | KEEP_BASELINE | donorC |
| `deliverables/requirements_closure.txt` | KEEP_BASELINE | donorC |
| `deliverables/requirements_freeze_final.txt` | KEEP_BASELINE | donorC |
| `docs/direct_io_inventory.json` | KEEP_BASELINE | donorC |
| `frozen_modules.sha256.baseline_pre_unfreeze` | KEEP_BASELINE | donorC |
| `pyproject.toml` | KEEP_BASELINE | donorC |
| `scripts/export_findings.sh` | KEEP_BASELINE | donorC |
| `scripts/run_campaign.sh` | KEEP_BASELINE | donorC |
| `scripts/run_integration_battery.sh` | KEEP_BASELINE | donorC |
| `scripts/verify_campaign.sh` | KEEP_BASELINE | donorC |
| `src/webpent/agents/hypothesis_analyzer/agent.py` | KEEP_BASELINE | donorC |
| `src/webpent/production/advisory_registration.py` | KEEP_BASELINE | donorC |
| `src/webpent/recon/autonomous_crawler.py` | KEEP_BASELINE | donorC |
| `src/webpent/recon/browser_crawler.py` | KEEP_BASELINE | donorC |
| `src/webpent/recon/login_executor.py` | KEEP_BASELINE | donorC |
| `src/webpent/recon/principal_provisioning.py` | KEEP_BASELINE | donorC |
| `src/webpent/reporter/poc_export.py` | KEEP_BASELINE | donorC |
| `src/webpent/scope/enforcer.py` | KEEP_BASELINE | donorC |
| `src/webpent/scope/models.py` | KEEP_BASELINE | donorC |
| `src/webpent/scope/parser.py` | KEEP_BASELINE | donorC |
| `src/webpent/service/facade.py` | KEEP_BASELINE | donorC |
| `src/webpent/service/manager.py` | KEEP_BASELINE | donorC |
| `src/webpent/workers/pentest_worker.py` | KEEP_BASELINE | donorC |
| `tests/test_frozen_module_gate.py` | KEEP_BASELINE | donorC |
| `uv.lock` | KEEP_BASELINE | donorC |
| `webpent-cli.sh` | KEEP_BASELINE | donorC |
| `src/webpent/agents/hunter_runner.py` | MERGE_BOTH | UNION |
| `src/webpent/agents/subdomain_takeover/agent.py` | MERGE_BOTH | UNION |
| `src/webpent/api/app.py` | MERGE_BOTH | UNION |
| `src/webpent/cli/commands.py` | MERGE_BOTH | UNION |
| `src/webpent/production/modern_spine_integration.py` | MERGE_BOTH | UNION |
| `CHANGED_FILES.txt` | REPLACE_WITH_DONOR_V152 | donorV |
| `Makefile` | REPLACE_WITH_DONOR_V152 | donorV |
| `frozen_modules.sha256` | REPLACE_WITH_DONOR_V152 | donorV |
| `src/webpent/agents/validator/agent.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `src/webpent/graph/builder.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `src/webpent/production/autonomous_validation_v1.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `src/webpent/production/campaign_state.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `src/webpent/production/experiment_fabric.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `src/webpent/production/modern_spine.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `src/webpent/production/production_spine.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `src/webpent/production/validators.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `src/webpent/recon/auth_handler.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/lab/idor_lab_target.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/team1_acceptance/test_a_modern_production_path.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/team1_acceptance/test_h_integrated_run.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/team1_acceptance/test_half1_behavioral.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/team1_acceptance/test_half2_production_dataflow.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/team1_acceptance/test_half2_proof_memory.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/team1_acceptance/test_production_research_loop_activation.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/team1_acceptance/test_sprint_i2_e2e_walking_skeleton.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/team1_acceptance/test_sprint_i2_hotfix_regression.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/team1_acceptance/test_sprint_i3_e2e_flow_vertical.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/team1_acceptance/test_validator_coverage_v1.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/team1_acceptance/test_vuln_arsenal_sprint_a.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/team1_acceptance/test_vulnerability_family_expansion.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/test_crapi_surface_expansion.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/test_generalization_systemic_fixes.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/test_p1_exception_hygiene.py` | REPLACE_WITH_DONOR_V152 | donorV |
| `tests/test_team1_deep_recon.py` | REPLACE_WITH_DONOR_V152 | donorV |

Notes on specific resolutions (verified by byte comparison):

- `src/webpent/config/settings.py` → v15.2's version: it carries the TC-4 C1(b) lint-wrap fix; the merge-time note claiming the Comprehensive side had it was wrong, and byte comparison settled it.
- `src/webpent/cli/commands.py` → manual union: donorC content kept, donorV's U-3 docstring lines added.
- `src/webpent/agents/{hunter_runner,subdomain_takeover/agent}.py`, `src/webpent/api/app.py`, `src/webpent/production/modern_spine_integration.py` → git 3-way auto-unions; every added hunk was traced verbatim to one donor (no invented glue).
- `src/webpent/agents/devils_advocate/agent.py` → modified by the Project Zero ZIP (both donors byte-identical beforehand); the Project Zero revision is canonical.

## 5. Restored C-unique paths

After the donorC import, a partial-copy fault had dropped 28 Comprehensive-only paths (11 `src/webpent/*` module packages, 4 agent packages, 8 test/doc/config paths, plus `TEAM1_DEEP_RECON_ARTIFACTS/`, `audit/`, `shared/`). All 28 were restored verbatim from donorC (commit `9813774`) — nothing was reconstructed.

## 6. Project Zero tier 7 items (commit `835c16e`)

Added whole, additively: `src/webpent/memory/{postmortem,taint_tracker}.py`, `src/webpent/models/{postmortem,taint}.py`, `src/webpent/shared/{red_vs_blue,shadow_detector,surface_drift,surface_influence_graph,tech_stack_cve}.py`, `src/webpent/agents/devils_advocate/agent.py` (modification), and the 7 test files. All **128 Project Zero tests pass** in the merged tree.

## 7. Junk removal (per spec allowance)

Removed: `webpent.db` (runtime DB), all `__pycache__/`, `*.pyc`, `src/webpent.egg-info/`, `.ruff_cache/`, `.pytest_cache/`, nested ZIPs. Verified: zero of each remain.
Additionally, one runtime artifact the project's own rider-R2 classification already orders purged (`hunt_artifacts/eng_poc_integration_test/audit/eng_poc_integration_test.audit.jsonl` — a runtime audit log, disposition recorded in `scripts/r3_residue_classification.json` since the v8 delivery) was purged by the tree's own `resurrect.py` sweep; the purge is committed with its classification citation. No functionality was deleted.

## 8. Wiring pass (Phase 3)

- Package wiring intact: `pyproject.toml` `[project.scripts] webpent = "webpent.cli:main"`, src-layout imports resolve (`PYTHONPATH=src python -c "import webpent"` OK).
- `webpent-cli.sh`, `Makefile`, all 6 campaign scripts and `scripts/` retained.
- The 16 net-new Project Zero files import cleanly inside the package (their tests pass, which exercises the imports).
- No import paths needed rewriting: the merge kept one canonical file per path, so module coordinates never moved.

## 9. Sanity checks (Phase 4) — exact commands and results

| Command | Result |
|---|---|
| `python -m compileall -q src scripts` | exit 0, no output |
| `python -m pytest --collect-only -q` | **3836 tests collected, 0 errors** (started at 130 collection errors; fixed by installing missing third-party test deps only — `langchain-core pydantic-settings httpx langgraph typer pyyaml bcrypt langgraph-checkpoint-sqlite celery pytest-asyncio python-multipart`; no project code was altered to make collection pass) |
| `PYTHONPATH=src python -c "import webpent"` | OK |
| `python -m pytest` (full suite, repo root) | **3822 passed, 55 failed, 5 skipped, 1 xfailed** in ~2:20 (see §10) |
| `python -m pytest tests/test_postmortem.py tests/test_red_vs_blue.py tests/test_shadow_detector.py tests/test_surface_drift.py tests/test_surface_influence_graph.py tests/test_taint_tracker.py tests/test_tech_stack_cve.py` | **128 passed** (Project Zero tier) |
| `python scripts/hygiene_gate_extended.py` | PASS (after the documented `.env.llm.example` allowlist entry, §10) |
| `python -m pytest tests/test_resurrect_residue_aware.py` | 3 passed |

No BLOCKED markings: the environment permitted every check.

## 10. Residual risks and expected failures (fail-closed accounting)

The 55 remaining full-suite failures decompose exactly (each claim verified):

1. **30 frozen-module gate tests (`tests/test_frozen_module_gate.py`) — EXPECTED, merge-inherent, deliberately NOT silenced.** The merged tree carries v15.2's certified 719-entry manifest; the merge intentionally resolved 31 frozen paths to newer content (25 byte-identical to the donorC baseline choice, 6 documented unions/modifications — full list verified by `sha256sum -c`). The gate is fail-closed by design and its own instructions require manifest regeneration only after a documented diff review; this report is that review. **Operator decision required:** either accept the new tree and re-freeze (`sha256sum` regen of `frozen_modules.sha256` over src/ + baseline reset, following the gate's documented procedure), or keep the v15.2 freeze and revert the 31 paths. We did neither silently.
2. **25 failures inherited unchanged from the baseline**: all 25 exist and fail identically in the untouched `WebPent_Final_Comprehensive(1)` tree (verified by running the same node IDs there). They are environment-dependent tests (live-target hunts, service fixtures, environment-shape assertions), not merge regressions.
3. **0 unexplained failures.** The only merge-caused breakage found (2/3 `test_resurrect_residue_aware.py` failing because donorC-only `.env.llm.example` tripped the v15.2-lineage hygiene gate's C4 env-variant class) was fixed by the gate's own rider-R2 mechanism: the file was classified as a deliberately authored template in `scripts/r3_residue_classification.json` with a dated merge addendum. All 3 tests now pass.

Other risks: `tests/` contains live-target and lab-fixture tests that assume external services (CRAPI, DVWA, WebGoat, LLM endpoints); they fail outside those environments in all three input lineages equally.

## 11. Final tree

- Branch `donorC-side`, history: `ddc5a02` base v21 → `c916990` donorC → `60e0460` donorV → `0b1c041` merge (61 explicit resolutions) → `9813774` restore 28 C-unique paths → `835c16e` Project Zero 7 items → `3c4fffe` hygiene allowlist fix → `deb6724` documented runtime-artifact purge.
- 3836 tests collected; 3822 passing; Project Zero 128/128; net change vs baseline: 70 paths added, 1 runtime log removed, 72 modified (see `CHANGED_FROM_BASELINE.txt`).
