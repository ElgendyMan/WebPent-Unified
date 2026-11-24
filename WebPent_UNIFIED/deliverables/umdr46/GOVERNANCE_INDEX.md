# GOVERNANCE_INDEX — UM-DR-33 → UM-DR-46 decision index

One page that indexes every standing engineering decision across the
mission waves, each with its durable proof anchor (in-tree file, git
tag, or release-ZIP path). Companion to the UM-DR-45 authorities map
(`deliverables/umdr45/GOVERNANCE_INDEX.md` — the five authorities and
standing registers); this page adds the per-mission decision layer the
UM-DR-46 mission requires (P0.4).

Working-tree rule (UM-DR-46 §0.5 cleanliness law): educational `.md`
reports live only inside the release ZIP (`umdrXX-docs/`); anchors
below therefore point at JSON registers, code, tests, tags, or ZIP
paths — never at deleted working-tree reports.

| Mission | Decision (what stands) | Proof anchor |
| --- | --- | --- |
| UM-DR-33 | Baseline/source-identity, release-integrity and security/dependency verification cadence established; wave content absorbed onto the trunk via the v0.40.x upload commits (patch-id classifies the branch commits UNIQUE — content arrived restructured) | `deliverables/umdr45/patch_id_equivalence.json`; tag `archive/features-v0.39.0-umdr33-bbe7c4e7`; ZIP `umdr45-docs/` |
| UM-DR-34 | Origin/scope hardening: canonical scope contract; ambiguous-path rejection (`%2f/%2e/%5c`, bounded re-decode) and explicit port-zero rejection; fail-closed scope authority at the final execution boundary | `src/webpent/shared/engagement_scope.py` (`_AMBIGUOUS_PATH_TOKENS`, `_path_is_ambiguous`, port `is None` contract); `src/webpent/scope/authority.py` (`scope_path_ambiguous` deny reason); `tests/test_v63_vip_security_regression.py` (ambiguous-path + port-zero regressions); ZIP `umdr45-docs/` umdr34 reports |
| UM-DR-34 → 46 (P0.1) | PR #1 (`security/umdr34-origin-scope-hardening`) is CLOSE, not merge: all 5 branch commits are content-absorbed on main (4 fully byte-identical, 1 superseded by the later in-sync lockfile state); merging a 70-behind branch would regress the trunk; the branch stays preserved as its archive tag | This window's content-diff verification (recorded in `deliverables/umdr46/PHASE0_CLOSEOUT.md`); `patch_id_equivalence.json`; tag `archive/security-umdr34-origin-scope-hardening-155690053341` |
| UM-DR-35/36 | Corrective baseline: recovery integrity, production E2E and test-evidence integrity discipline; repository/mission deliverable layout | ZIP `umdr45-docs/` (35/36 reports); `deliverables/umdr36_1/` evidence JSONs |
| UM-DR-37 | Production-campaign instrumentation pattern: reversible `campaign_instrumentation`, lab request log as ground truth, out-of-scope-origin zero-request proof | `scripts/umdr37_production_campaigns.py`; `tests/test_umdr38_campaign_instrumentation.py` |
| UM-DR-38 | Repository-structure governance, evidence provenance, CI verification, documentation consistency; confirmation-chain per-finding join | `deliverables/umdr38/` (JSON registers); `scripts/confirmation_chain.py` |
| UM-DR-39 | ROOT_CAUSE_REGISTER origin: RC-1..RC-10 root-cause codes with acceptance criteria | `deliverables/umdr39/ROOT_CAUSE_REGISTER.md` (in-tree; not a mission report pattern) |
| UM-DR-40 | RC-4..RC-7 COMPLETE_LOCAL; RC-8/9/10 assessed and honestly REMAINS_OPEN (no coverage claimed) | `deliverables/umdr40/UMDR40_ACCEPTANCE_MATRIX.json`; ZIP `umdr45-docs/` umdr40 design/closeout |
| UM-DR-41 | Baseline audit, architecture map, dependency audit; K5 cross-process scope authority and K6 dependency single-source-of-truth decisions | `deliverables/umdr41/` (JSON registers); `deliverables/umdr45/K5_SCOPE_AUTHORITY_ACROSS_PROCESSES.json`, `K6_DEPENDENCY_SINGLE_SOURCE_OF_TRUTH.json` |
| UM-DR-42 | Dead-code ratchet (baseline `scripts/quality/dead_code_baseline.json`), A5 reconciliation, release-integrity closure | `deliverables/umdr42_closure/FULL_SUITE_EVIDENCE.json` (BUILD_INFO honesty-gate input); `scripts/quality/` |
| UM-DR-43c | Identity-safe hypothesis lifecycle (deterministic identity, append-only merge policy) | `deliverables/umdr43c/` (JSON registers + tests `tests/test_umdr43c_*`) |
| UM-DR-44 | A5a-d: AppModel tuple identity (scheme/host/port/path + cumulative methods + revision) and hypothesis lifecycle fields (`deterministic_match`, `evidence_contract`, `novelty_score`, `preconditions_satisfied`, `info_gain`, `model_revision`); B1 scope-exclusion materialization fix; B10 documented RETAIN (not delete) for `chain_planner`/`oauth_hunter` wrappers with structural gate | `src/webpent/appmodel/`; `src/webpent/production/hypothesis_identity.py`; `tests/test_umdr44_b10_wrapper_decision.py`; tag `umdr44-deferred-batch`; ZIP `umdr45-docs/` umdr44 report |
| UM-DR-45 | Convergence & ascension: RC-5/6/7 COMPLETE (real info-gain + challenger); RC-8/9 PARTIALLY_COMPLETE; RC-10 owner-decision; agent decision register (54 units: 44 KEEP wired / 8 KEEP-DORMANT / 2 RETIRE-CANDIDATE); X-track benchmark executed (battery A: CLI surface recall 0.0 — the query-param authentication wiring gap, measured not hidden; battery B: labsuite engine precision/recall 1.0); parallel branches archived as tags; 3-green CI gate over one tree; v0.44.0 @ `7f3807a` | `deliverables/umdr45/D_TRACK_REGISTER.md`, `CLOSEOUT.md`, `X_TRACK_BENCHMARK.json`, `agent_decision_register.json`, `orphan_inventory.json`, `parallel_branch_archive_manifest.json`, `run_files/ci_gate.json`; tags `v0.44.0` = `umdr45-convergence` = `7f3807a` |
| UM-DR-46 (P0.2 folds) | RC-8 folds into Phase F/I (the per-branch new-evidence delta test becomes the Phase C explored-space counting gate and the Phase I no-knowledge-free-requests QC metric). RC-9 folds into Phase A/B (decision: `knowledge/target_knowledge.py` v1 retires to an AppModel projection — the Security Knowledge Graph becomes the contradiction-preserving SSOT; extend-not-rewrite applies). RC-10 REMAINS an owner entry-point decision (recommendation recorded: wire the hunt_* stack only if Phase F's experimentation loop requires it; otherwise classify formally as library-complete dormant) | `deliverables/umdr46/PHASE0_CLOSEOUT.md` §P0.2; `deliverables/umdr45/D_TRACK_REGISTER.md` §D4 |
| UM-DR-46 (P0.3 executed) | The two RETIRE-CANDIDATEs executed: `agents/specialists/` and `agents/team.py` removed (zero importers re-verified incl. string/dynamic scan; advisory-only modules); `tenant_isolation` folded into Phase A/J; `chain_planner`/`oauth_hunter` stay KEEP-DORMANT per B10 | commit `043b512`; `deliverables/umdr45/agent_decision_register.json` (decision record); `deliverables/umdr46/PHASE0_CLOSEOUT.md` §P0.3 |
| UM-DR-46 (P0.4) | This decision index created; LICENSE verified canonical MIT (repo root), `pyproject.toml` `license = MIT` consistent; placeholder contact `security@example.com` flagged for owner-approved replacement | this file; `LICENSE`; `WebPent_UNIFIED/pyproject.toml` |
| UM-DR-46 (P0.5) | BASELINE BENCHMARK executed on the converged trunk before any Phase A+ code: 6 family labs × vulnerable/secure × 3 campaigns through the official entrypoint; numbers live in the machine record | `deliverables/umdr46/BASELINE_REPORT.md` + `BASELINE_METRICS.json` + `run_files/`; `scripts/umdr46_baseline_battery.py` |
| UM-DR-46 (standing laws) | Push economy (one squash commit + one push per Phase); actions:write token for parallel 3-green re-runs; documentation cleanliness on BOTH sides (team tree clean of `umd*.md`; owner side deletes the delivered prompt copy); LLM = advisory only (deterministic researcher brain: verdicts, scope and evidence are pure functions); extend-not-rewrite (no suspended modules — the 44/5 lesson); measurement determinism (fixed seeds, mocked clocks, replayable double-run) | UM-DR-46 mission prompt (§0.5); enforced per-phase in `deliverables/umdr46/` evidence |

## Standing quality gates (unchanged, see the UM-DR-45 authorities map)

Ruff ratchet (`scripts/quality/ruff_baseline.json`), dead-code ratchet
(`dead_code_baseline.json`), test-count floor 8115
(`scripts/test_count_floor.json`), coverage floor, BUILD_INFO honesty
gate, G-02/G-08 direct-I/O inventory with per-record expiry (all
current records expire 2027-02-17), release discipline (3-green on one
SHA, fast-forward main only, tags, archive-never-delete).
