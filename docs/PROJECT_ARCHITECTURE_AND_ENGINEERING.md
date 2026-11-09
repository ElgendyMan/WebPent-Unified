# WebPent — Project Architecture and Engineering

**Document A** (per the Ultimate Transformation Directive §14). Status

date: 2026-11-07 (post UM-DR-28). Version line: v0.34.0 unified lineage
(build v15.2 base). This document describes the ACTUAL system — every
claim carries a source path; measured numbers carry an evidence path.

---

## 1. What WebPent is

An autonomous, evidence-driven web-application penetration-testing
PLATFORM: a LangGraph state machine orchestrates reconnaissance,
identity discovery, hypothesis generation, attack planning, payload
execution, causal validation, and reporting — under an authorization
manifest, scope law, safety governors, and a tamper-evident audit
spine. The unit of truth is the **Finding with reproducible evidence**;
nothing is a finding until a deterministic validator (or a
Charter-qualified LLM path) confirms it causally.

Two honesty labels govern every capability claim (M11 ladder):
`unit_tested → lab_qualified → production_qualified`. As of this
document: deception verifier = production_qualified; deterministic
engine = lab_qualified (blind_v3 aggregate 0.137 recorded; the
methodology ceiling lifted by UM-DR-27, the comparator-oracle miss
class repaired by UM-DR-28, and the discovery now CAMPAIGN-INTEGRATED —
see Document B); LLM hypothesis production = refused by the Charter
§4.1 gate (by construction).

## 2. Repository and build

- Root: `WebPent_UNIFIED/`. Package: `src/webpent/` (~100 subpackages;
  the large ones: shared 3.4M, agents 2.1M, egaie 1.1M, production 1.1M).
- Tests: `tests/` (665 files; 8,617 collected post-UM-DR-28 — 8,608
  passed / 6 skipped / 3 xfailed / 0 failed, chunked serial run).
  Floor ratchet: 8,115 (`BUILD_INFO.json`).
- Freeze discipline: `frozen_modules.sha256` (661 paths) + the
  `tests/test_frozen_module_gate.py` gate (663 tests). Changes to frozen
  paths require a declared refreeze script (DR-009 protocol) — see
  `DRIFT_REGISTER.md` (UM-DR-01…28).
- Machine gates (CI): frozen-module, broad-exception register
  (`docs/ACCEPTED_EXCEPTIONS_REGISTER.md`), direct-I/O inventory
  (`docs/DIRECT_IO_INVENTORY.md`), vault authority, isolation denylist,
  P-1 hygiene, release packaging, editable-install, coverage ratchet
  (4.27% ≥ 4.07% required), test-count floor, SBOM + blocking CVE gate
  (`.github/workflows/ci.yml`).
- Release: `docs/engineering/RELEASE_PROCESS.md` (14-gate chain);
  v0.35.0 notes draft: `docs/engineering/RELEASE_NOTES_v0.35.0_DRAFT.md`.

## 3. Execution lifecycle (a campaign)

1. **Authorization** — `models/authorization.py`: the tamper-evident
   manifest (`webpent-authorization-manifest-v1`, sha256-over-canonical-
   JSON, validity window, origin-level coverage); `webpent hunt
   --authorization-manifest` cross-checks the pointer (M2).
2. **Workspace** — `shared/target_workspace.py`: per
   (workspace_root, target_origin, client_id, engagement_id) isolation;
   layout `reports/ artifacts/ sessions/ databases/ ledgers/ rag/`;
   fail-closed switching (`shared/target_workspace_context.py` throws
   `target_workspace_switch_blocked` on cross-engagement activation).
3. **Graph** — `graph/builder.py` + `state/state.py`: PentestState
   (261 channels: 144 reducer-merged / 117 last-write-wins) and
   UnifiedState superset; production checkpoints through
   `graph/checkpoints.py` (RedactingSqliteSaver —
   `_SECRET_CHANNELS` persisted empty; `auth_state` key fields
   cleared; `jwt_weak_secret_candidates → []`).
4. **Recon & crawling** — `recon/autonomous_crawler.py` (robots
   double-gate), `recon/browser_crawler.py` + `browser_farm.py`
   (Playwright; SSRF guard allowlists the campaign's own declared
   target — UM-DR-26 fix — every other private host stays blocked),
   `jsintel/js_reversing.py` (esprima AST, multi-level constant
   propagation, call-site-verified sinks — M3 ف3.2).
5. **Identity** — `recon/identity_discovery.py` + `principal_provisioning.py`
   (r6c two-branch S1 ladder; resource-SEED semantics; zero-probe
   short-circuit) → `recon/login_executor.py` (r9 validation ladder)
   → `auth/worker_session_factory.py` (ق7 reauth-vault identity runner
   behind `enable_identity_orchestrator`).
6. **Hypotheses & planning** — `recon/hypothesis_generator.py`,
   `agents/planner/agent.py` (coverage advisory behind
   `enable_coverage_scheduling`), `agents/hunter_graph.py` (replan
   contract: REFUTED → replan-once, no re-exploitation),
   `attack_graph/` (evidence_status per edge; honest backfill only).
7. **Execution & validation** — `production/validators.py` (canonical
   dispatch, 29 families — Document B matrix),
   `production/advanced_validators.py`, `production/graphql_validator.py`,
   `deception/` (causal verifier 24/24, zero-FP gate),
   `stateful_api/` (M5 engine: OpenAPI/observed-surface ingestion,
   inferred dependency model, bounded replayable sequence plans,
   two-identity BOLA/IDOR differentials), `production/stateful_probe.py`
   + `production/transition_sources.py` (UM-DR-27 grammar-free
   stateful discovery) + `production/stateful_discovery.py` (UM-DR-28:
   the CAMPAIGN integration — structural case mining from the observed
   inventory, scope-validating executor adapter, bounded whole-run
   budgets; invoked by the wired `family_execution` node behind
   `enable_stateful_discovery`, fail-closed default off, outcomes on
   the declared `stateful_discovery` PentestState channel).
   The confirmation layer gained the representation-equivalence oracle
   (`cqa_v2/representation_oracle.py`, UM-DR-28): canonical JSON
   normalization (documented volatile-key rule set) + body-represented
   authorization semantics surfaced through the causal guard's context
   channels — headers always win; the frozen guard's four header-only
   channels gained the standard top-level fallback (declared refreeze).
8. **Safety** — `safety/agency.py` (ActionAuthority default-deny;
   smart_auto_approve cannot rescue out-of-scope), `shared/rate_governor.py`
   (kill-switch BEFORE slot consumption; robots double-gate; spend caps
   at the LLM funnel boundary), `approvals/` (M9 tiers 0–3, immutable
   ApprovalBinding, one-time consume, JSONL audit).
9. **Persistence & reporting** — `memory/db.py` (per-workspace sqlite
   stores; `DATA_SOURCE_OF_TRUTH` in `models/contracts.py`), ledgers
   (`ledgers/findings|actions.sqlite3`), `reporter/` + `reporting/`,
   POC recorder with path-traversal guard (`safe_artifact_stem`).

## 4. Agent architecture (the operational set)

The graph's load-bearing agents (fully wired, state-affecting):
planner, hunter (hunter_graph replan loop), validator
(`agents/validator/`), recon crawler set, identity ladder, reporter.
Advisory-only (flag-gated, fail-soft, provenance-preserved):
cve_advisory (ق6), api_surface_shadow (ق8), coverage advisory,
refutation-learning advisory, stateful_api plans. Every agent's
position, flags, and contracts are pinned by tests
(`tests/test_m3_research_wiring.py`, `tests/test_hardening_0330_b3.py`,
the r6/r9 identity suites). The consolidation rule (directive §8.1)
applies: no new agent is added while an existing one can own the
capability — UM-DR-27 deliberately extended the prober instead of
adding a "stateful agent".

## 5. Target intelligence (as built)

- `appmodel/` — the greenfield Organization→…→Observation model with
  discovery confidence and attack-graph projection (no graph DB).
- `shared/family_feeds.py` — the REAL-state seam: derives
  `endpoint_inventory` (explicit inventory → OpenAPI routes → crawl
  surface records → forms → JS shadow endpoints → endpoint lists),
  `auth_flows`, `multi_tenant` from live campaign channels. UM-DR-27
  added the transition-source adapter on top of it; UM-DR-28's
  `production/stateful_discovery.py` consumes it inside the wired
  `family_execution` node (the campaign path constructs the source
  from live crawl state — the RCA §5 blocker closed).
- `knowledge/` + `ekg/` — typed executable knowledge (M7: argv-only
  execution, per-template lifecycle regressions).
- `brain/`, `intelligence/`, `experience/`, `learning/` — knowledge
  consolidation layers (lineage-merged; the lessons v4 subsystem was
  deliberately deleted in the 0.29.0 G-1 window — skip-marked tests
  document it).

## 6. Security architecture (controls at execution boundaries)

Authorization manifest mandatory (sign-time H-2 refusal) → scope law
(`shared/scope_*`, DNS-rebinding TOCTOU + multi-record + redirect
revalidation, link-local admission, poison hard-deny) → SSRF guards
(crawler/browser/validator) → argv-typed `run_command` with executable
allowlist (AST-proven zero shell=True) → rate governor + kill switch →
LLM spend caps + prompt-injection boundary (`llm_researcher/`,
`docs/LLM_SECURITY_BOUNDARY.md`) → secret redaction at checkpoints →
per-engagement workspace isolation (cross-engagement invisibility
tested) → approvals (cannot grant what policy denies) → evidence
integrity (Tool-Confirmed provenance; `APPROVED_TOOL_CONFIRMED_WRITERS`).
Negative cases tested as seriously as positive ones (each control has
adversarial suites — see the M2/M9/M12 reports).

## 7. Known limitations and standing decisions (honest)

- M4 (source-intake) and M8 (MCP) remain closed by recorded gate
  decisions (`docs/engineering/M4_PHASE_REPORT.md`,
  `M8_M10_GATE_DECISIONS.md`) with reopening conditions.
- M10 remains blocked on independent-holdout qualification (Document B
  — the in-repo capability is campaign-integrated and lab-qualified;
  the LABEL waits on operator-deployed corpora).
- The 0.34.2 cleanup window owns: run_campaign.sh retirement, the
  langgraph-adjacent CVE backlog (each advisory must be verified
  against the ACTUAL installed package per the directive §3.4 — no
  blanket upgrades).
- ~~The read-only comparator-oracle residual (15 blind_v3 misses on the
  absent original target)~~ — CLOSED by UM-DR-28: the miss CLASS is
  reproduced on the equivalence fixture (0 recall under the legacy
  comparator) and fully recovered by the representation oracle
  (73/73, 0 FP) with the adversarial no-over-normalization pin; the
  exact original bytes remain unrecoverable (target absent — recorded
  as the honesty boundary, not a defect).
- ~~The source-driven prober's campaign-node wiring awaits the next
  builder thaw~~ — CLOSED by UM-DR-28 (declared 4-file refreeze,
  DR-009): the wired node invokes it behind a fail-closed flag.
- DISCOVERED residual (UM-DR-28): the family spine's non-findings
  output keys (`family_execution_status`, `family_candidates`, …) are
  NOT declared PentestState channels, so LangGraph channel filtering
  drops them in the real graph — only `findings` (declared, merged)
  and the newly declared `stateful_discovery` survive. Owner: next
  builder window (declare the family_* channels or fold them into a
  declared telemetry channel). Findings delivery is unaffected.
- Legacy grammar-path evidence asymmetry (documented): the UM-DR-25
  name-grammar fallback keeps its pinned byte-compatible behavior
  (its transition record can under-report pre-confirmation POSTs); the
  SOURCE-DRIVEN production path records the full application log. The
  legacy path exists to keep the recorded-methodology measurements
  comparable.

## 8. Verification evidence map

| Claim | Where proven |
|---|---|
| 8,617-test suite (8,608/0), frozen gate 663 | `BUILD_INFO.json` + the UM-DR-28 chunked full-suite run (`reports/qualification/umdr28_baseline.json` records the pre-change baseline incl. the 1 real UM-DR-27 regression found and fixed) |
| Workspace isolation | `tests/test_m1b_workspace_artifact_ownership.py` (7) |
| Checkpoint redaction, 261 channels | `tests/test_m1b_checkpoint_channel_matrix.py` (6) |
| Scope law adversarial corpus | M2 report + its named corpus tests |
| Deception resistance 24/24, blind 8/8 | `reports/deception/benchmark_v1.json`, M6 report |
| Approvals tiering/voiding | M9 report (19 tests) |
| Qualification labels + weekly ق5 canary | `reports/qualification/weekly_*.json`, M11 report |
| Backup/restore integrity | M12 report (7 tests) |
| Grammar-free stateful discovery 73/0/0/47 | `reports/qualification/blind_v3_generalization_*.json` + `tests/test_transition_sources.py` (27) |
| Representation-equivalence recovery 73/0/0/47 on body-represented targets | `reports/qualification/umdr28_equivalence_measurement.json` + `tests/test_umdr28_representation_oracle.py` (23) |
| Campaign integration (node + LangGraph runtime + builder wiring, structurally different target, 3/3 confirmed with provenance, scope refusals, budgets) | `reports/qualification/umdr28_campaign_e2e.json` + `tests/test_umdr28_campaign_stateful_e2e.py` (10) |
| Evidence sequencing (full application log, ordered trace, control rotation) | `tests/test_umdr28_stateful_discovery.py` (15) |
| P102 flake root-caused + closed (designed no-op outcome documented) | `tests/test_hardening_0330_b3.py` (UM-DR-28 comment; deterministic reproduction in the window evidence) |

— End of Document A —
