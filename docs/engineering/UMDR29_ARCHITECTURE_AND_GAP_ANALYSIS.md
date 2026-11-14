# UM-DR-29 Architecture & Gap Analysis — Dead Code, Dead Capabilities, Weak Wiring

Window: UM-DR-29 (2026-11-07) · Method: full import-graph reachability audit
(`scripts/umdr29_dead_code_audit2.py`, Python import semantics: package
`__init__` side-effect imports included) + repo-wide reference check
(`scripts/umdr29_ref_check.py`) + manual verification of every disposition.

## 1. The audit (numbers)

| Population | Count |
|---|---|
| Modules under `src/webpent` (pre-window) | 1,263 |
| Reachable from real entry points (main/server/worker/viewer/verify_all + all cli subcommands + workers.pentest_worker + campaign/api/families/core/config/state/production roots) | 731 |
| Orphan (zero runtime, zero test, zero script/config references) | 306 |
| Test-only (tests import them; runtime does not) | 226 |

## 2. Dead code REMOVED (24 packages, ~190 modules)

### 2.1 Completed archive move (17 packages — copies already canonical in `archive/pre_v10_prototypes/`)

`abhc abhie abhie_v6 abhip adi asros avde avrip avrp cqa dcvu goed_v1 rta
vabhfil_v8 vabhfqr_v10 vabhfqr_v9 vabhic_v7`

These are the pre-v10 autonomous-bug-hunter prototype generations. The
2026-10-27 window archived them (and updated the frozen manifest, the
broad-exceptions register, and the direct-I/O pin) **but never deleted the
`src/` copies** — the UM-DR-29 truth audit found the duplication and this
window completed the move. One src variant (`abhie_v6/agent_core.py`,
missing the `research_memory` parameter) is preserved losslessly next to
its archive twin.

### 2.2 Frozen-but-dead archive (7 packages → `archive/umdr29_dead_code/`)

`contracts copilot experience persistence profiles security_models validation`

Zero importers anywhere. Notable: `webpent/validation/` was a frozen **dead
duplicate** of the live `webpent/validators/` package; `webpent/contracts/`
was a dead re-export facade. Removed via the DR-009 declared thaw +
refreeze (`scripts/refreeze_manifest_umdr29.py`, manifest 661→639 entries;
the ≥630 floor holds).

## 3. Dead capabilities NOT removed — honest status instead

The directive forbids removing tests to shrink the suite and forbids
claiming integration without evidence. These subsystems are kept, with
their true status recorded in
`UMDR29_FEATURE_QUALIFICATION_MATRIX.json`:

| Subsystem | Truth | Status |
|---|---|---|
| `webpent/campaign/` (U-CAMPAIGN-1..15: strategist, executor + BudgetGuard, storyteller, historian, warroom) | an isolated, self-documenting research layer with its own laws; **the runtime campaign path is `shared/campaign_executor.py` + graph builder** — the two never meet | UNIT_TESTED (not campaign-integrated) |
| `egaie/` (32 modules, 31 test-only), `forge/` (21 test-only), `deep/` (15), `research_engine/` (5 test-only + 11 orphans kept) | research islands with their own tests | UNIT_TESTED / partially orphaned-by-design |
| `irta/` (19 orphans + 2 test-only) | frozen benchmark lineage — `irta/v3/blind.py` is the blind_v3 measurement heritage | kept frozen |
| `adapters/{juice_shop,crapi,webgoat,mock_target,generic_web,local_causal_lab}` | frozen target-adapter inventory (selection-time wiring is the design) | INVENTORY |
| 18 unwired agent modules (`dom_xss`, `graphql_testing`, `oauth_hunter`, `multi_step_auth`, `sourcemap_analysis`, `role_matrix`, `tenant_isolation`, `chain_planner`, `specialists`, `team`, `advanced_web_vulns`, `cache_poisoning`, `prototype_pollution`, …) | complete-looking agent nodes the graph builder never schedules | INVENTORY — the recall program's first wiring candidates |
| `business_logic/{invariant_checker, state_transition, workflow_analyzer, abuse_case_generator}` (orphans), `value_fuzzer` (test-only) | business-invariant reasoning exists as code, not as capability | PROPOSED |
| `coverage/{coverage_map, gap_detector}` (orphans) | coverage-gap intelligence exists as code, not as capability | PROPOSED |
| `production/{product_layer, oob_verification, hypothesis_charter, business_logic_workflows, hypothesis_qualification_harness, real_target_qualification_v1_1, business_logic_inferrer, chain_composer, parallel_orchestrator, qualification}` | research/qualification harnesses; `campaign_worker` is a documented manual subprocess entry (workers_ops_runbook.md) | UNIT_TESTED / documented entries |

## 4. Weak wiring FIXED this window

1. `BUILD_INFO.git_head` → pointed at a commit that does not exist
   (pre-re-init history) — corrected to the real window commit.
2. Six frozen `__init__.py` docstrings named `goed_v1` as the core engine —
   corrected to `families/cqa_v2/models/smart` (the actual live roots).
3. The proposal-4 archive COPY-not-MOVE (section 2.1) — completed.
4. Direct-I/O pin contained 2 identities whose removal was documented but
   never executed — realized; pin updated with adjudication note.
5. `pyproject.toml` / `Dockerfile` / `src/webpent/__init__.py` version
   sources bumped in lockstep (the version-agreement gates verified them).
6. Repo-root git hygiene: operator artifact paths untracked via
   `.gitignore` (junk commit `b547dc4` documented, not rewritten).

## 5. Remaining architecture gaps (ranked, roadmap)

1. **Recall program (M10 reopening)** — extend discoverable vulnerability
   families; wire the stateful prober to learned transition grammars;
   measure on a real blind corpus (needs operator-provided holdout:
   BLOCKED_EXTERNAL_DEPENDENCY). First wiring candidates: the 18 unwired
   agent modules + `business_logic` invariant reasoning.
2. **Knowledge graph → planning feedback loop** (directive §5): graph
   facts must change discovery decisions; today they don't.
3. **family_\* channel contracts** (carried from UM-DR-28): the remaining
   implicit channel derivations need typed contracts.
4. **Coverage Gap Map** in campaign runtime (§9).
5. **Notification transports** operator configuration (carried).
6. **`run_campaign.sh` rewrite + langgraph CVE accumulation** (0.34.2
   cleanup, carried — unchanged this window).
