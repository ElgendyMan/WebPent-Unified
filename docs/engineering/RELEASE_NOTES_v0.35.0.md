# WebPent v0.35.0 — Release Notes (2026-11-07)

**Status:** finalized per the RELEASE_PROCESS.md §3 contract; the release
tag/publish is the operator side of the discipline. Gate evidence:
DRIFT_REGISTER UM-DR-24..29 + the per-window records.

---

## What changed

### The 2026-11-05/06 engineering execution window (UM-DR-15..23)

Every registry phase M0–M12 carries a disposition; ten phases COMPLETE,
two closed by recorded optionality-gate decisions, one blocked by its own
measured dependency:

| Window | Phase | Delivered |
|---|---|---|
| UM-DR-15 | M2 Security Boundary | structured tamper-evident Authorization Manifest (`webpent-authorization-manifest-v1`), `--authorization-manifest`/`--scope-file` CLI intake, the named adversarial scope corpus, argv-typed execution + allowlist + non-root drop |
| UM-DR-16/17 | M3 Research Brain | ق6/ق8 advisory wiring, hypothesis contract fields, the Charter §4.1 fail-closed LLM gate, real JS AST reversing (`jsintel/`), tenant-isolation seam (`family_feeds`), ق7 identity runner, OAST + campaign-resume production wiring, attack-graph evidence edges, the appmodel, the blind_v3 harness (EXECUTED: 120 samples) |
| UM-DR-18 | M5 Stateful API | the `stateful_api/` engine — contract ingestion, inferred dependency model, bounded replayable sequence plans, two-identity BOLA/IDOR differentials |
| UM-DR-19 | M6 Deception | the `deception/` corpus + causal verifier (24/24 rejected, 0 FP), per-vuln-class evidence contracts, sqlmap differential extraction, benchmark_v1 (blind 8/8) |
| UM-DR-20 | M7 EKG-CG | typed executable knowledge, argv-only execution, lifecycle with per-template regressions |
| UM-DR-21 | M9 Approvals | Tier 0–3 classification, immutable ApprovalBinding, one-time consume, notification-cannot-grant, append-only audit trail |
| UM-DR-22 | M11 Qualification | per-family metrics (structural no-aggregate rule), the label ladder, the wired weekly ق5 canary — EXECUTED |
| UM-DR-23 | M12 Production | verified backup/restore harness, weekly-benchmarks CI enrollment, RELEASE_PROCESS.md (the 14-gate chain) |
| — | M4 / M8 | NOT EXECUTED — optionality gates not met; reopening conditions recorded (`M4_PHASE_REPORT.md`, `M8_M10_GATE_DECISIONS.md`) |
| — | M10 | BLOCKED by its own dependency (discovery quality); reopening conditions recorded |

### The 2026-11-06/07 execution windows (UM-DR-26..29)

- **UM-DR-26 (red-team phase 2):** the remaining 67 behavioral failures
  closed; alias corruption, validator dead code and the SSRF guard
  false-positive on the target itself fixed; ~245 regression tests
  recovered; two-window red team fully closed.
- **UM-DR-27 (recall generalization):** replica-harness measurement
  discipline; suite 8,542→8,569.
- **UM-DR-28 (production discovery integration):** source-driven stateful
  discovery wired into the real Campaign path behind fail-closed
  `enable_stateful_discovery` (proven E2E 3/3 ground-truth vulns with full
  provenance on a structurally different live target); the
  representation-equivalence oracle (comparator miss class 0.0→1.0 at 0
  FP); ordered evidence traces; P102 root-caused and closed; 48 new
  tests; suite 8,617 collected / 8,608 passed.
- **UM-DR-29 (dead-code disposition + qualification truth):** the
  Ultimate-Plan-2026-10-27-proposal-4 archive move **physically
  completed** (17 dead prototype packages deleted from `src/`;
  canonical copies in `archive/pre_v10_prototypes/`); 7 frozen-but-dead
  packages archived to `archive/umdr29_dead_code/` with a DR-009
  refreeze (manifest 661→639); 6 frozen docstrings falsely naming
  `goed_v1` as the core engine corrected; `BUILD_INFO.git_head` (pointed
  at a nonexistent commit since the history re-init) fixed; the
  direct-I/O inventory regenerated (1197→1149 records, −31 identities all
  inside the archived prefixes; the cqa/execution.py pin finally realized
  36→34); the machine-readable feature-qualification matrix introduced
  (`UMDR29_FEATURE_QUALIFICATION_MATRIX.json` — no capability claim
  without evidence); repo git hygiene (operator artifacts untracked).
  Suite: 8,595 collected (−22 = exactly the removed manifest entries'
  parametrized gate cases), 0 failures.

### The 2026-11-06 red-team window (UM-DR-25)

The operator-ordered adversarial sweep found and closed six defect
families (~245 tests recovered from a 310-failure + 19-error red
baseline): the wholesale Settings field drift (33 subsystem flags + ~20
knobs dead on arrival), the phantom OOB DB API, the unregistered
blind-OOB/privilege-differential validators, the missing third chain
type (IDOR→MASS_ASSIGNMENT via the ChainTypeSpec seam), stale tests vs
hardened contracts, and the machine-gate register drift — plus the
first M10-unblock engineering step: the blind_v3 same-spec replica and
the deterministic stateful prober (replica-corpus: recall 0.3425 →
1.0000, precision 1.0, 13.2 req/case; honesty boundary recorded). Full
record: `docs/engineering/REDTEAM_WINDOW_REPORT.md` + DRIFT_REGISTER
UM-DR-25; 10-file declared refreeze, frozen gate 661/661 (UM-DR-29 note:
now 639/639 after the dead-code disposition). The
remaining 67-test behavioral rework (identity ladder, login validation,
replan traces, governor integrations, e2e suites) is root-caused and
owned in the phase-2 plan — recorded, not silently dropped.

### Post-window compliance sweep (UM-DR-24)

Four red gates of the 14-gate release chain closed with evidence (3 OAST
state channels declared on the frozen PentestState via a DR-009 declared
refreeze; the ق7 identity-runner vault seam adjudicated onto Table 2-2
after deliberate review; BUILD_INFO re-frozen 8115→8505 via a committed,
subject-declared, field-scoped re-freeze; 14 secret-scan detections waived
value-precisely after source inspection) and one harness defect fixed
(deps gate no longer conflates pip-audit's findings-exit with harness
failure).

### New capability flags (every one fail-closed, default False)

`enable_cve_advisory_hypotheses` · `enable_api_surface_shadow_hypotheses`
· `enable_family_execution_spine` · `enable_identity_orchestrator` ·
`enable_stateful_api_testing` · `enable_oast` (+ `enable_campaign_resume`
verified existing). Flag-off behavior is byte-identical legacy behavior;
the flag list is the operator's enablement surface.

---

## Known limitations (the honest list)

- **Discovery quality is NOT production-qualified.** The deterministic
  hypothesis engine is measured **lab_qualified**: blind_v3 recall 0.137 /
  precision 0.6667 (120 samples). The Charter §4.1 gate (recall ≥ 0.5 ∧
  precision ≥ 0.7) refuses budget expansion — by construction, honestly.
  M10 (remediation PRs) stays blocked until the label reaches
  production_qualified or an operator scopes a human-confirmed-finding
  engagement. UM-DR-25's stateful prober lifted the REPLICA-CORPUS
  recall to 1.0/1.0 — recorded progress toward reopening, not a label
  change (the original blind server is absent from the repo; the
  replica is author-built from the committed spec).
- **Live-corpus benchmarking requires operator-deployed targets** (Juice
  Shop / crAPI / OWASP Benchmark); the weekly runner's interfaces accept
  them and never fabricate their absence. The dojo self-benchmark reports
  `self_benchmark_not_configured` until the operator configures the agent
  factory.
- **The LLM hypothesis producer does not exist yet, by design** — the
  Charter §4.1 gate + measurement harness + baseline replay are live and
  fail-closed.
- **M4 (SAST) and M8 (MCP client) remain closed** by their optionality
  gates: no authorized source-intake surface; no operator MCP integration
  demand. The M8 server is verified (160 tests) and loopback-only.
- **0.34.2 window backlog (recorded, with owners):** run_campaign.sh
  retired-flag rewrite; deep/ bridge + graphql↔deep-mode link;
  js_discovery/sourcemap/role_matrix flag defaults; E-4 oauth fields;
  langgraph-adjacent CVE re-scan; the ruff lint debt (ceiling frozen at
  8056, style-level, attribution in `scripts/quality/ruff_baseline.json`).
- **Two release-gate halves are CI-bound:** the BUILD_INFO provenance
  anchor (tag `v15.2-audit-baseline` resolves only in the full-history
  lineage) and the locked-env CVE re-scan (the recorded release scan
  evaluates PASS offline; the sandbox venv is not the release env).

---

## Declared qualification levels (MEASURED, from the M11 rollup)

| Component | Label | Evidence |
|---|---|---|
| deception verifier | **production_qualified** | zero-FP on the 24-fixture corpus + blind 8/8 (`reports/deception/benchmark_v1.json`) |
| deterministic hypothesis engine | **lab_qualified** | blind_v3 120 samples, recall 0.137 / precision 0.6667; honestly below the production bar |
| frozen core (state, scope, checkpoints, orchestrator) | verified | frozen gate 639 (UM-DR-29 disposition) + adversarial corpora + 8,595-test suite, all green |

---

## Migration notes

- **New state channels are additive**: `oast_correlation_status`,
  `oast_sessions_armed`, `oast_candidate_findings` on PentestState —
  `total=False`, so legacy checkpoints load unchanged; no migration
  required.
- **Fresh install vs upgrade:** the Alembic lineage is unchanged by this
  window (M12 verified the migration seam); upgrades follow the standing
  path. New capability flags default OFF — existing deployments behave
  byte-identically until an operator enables a flag.
- **Operator credentials template:** `docs/operator_credentials.example.json`
  carries placeholder values (`replace-at-runtime`) — fill at deploy time;
  fail-closed secret keys refuse well-known defaults.

## Rollback

Per RELEASE_PROCESS.md §4: stop intake → `python
scripts/verify_backup_restore.py --workspace <workspace>` (verified
backup) → restore via the same harness → pin the previous release's
content-addressed manifests → re-run the 14-gate chain before intake
reopens.
