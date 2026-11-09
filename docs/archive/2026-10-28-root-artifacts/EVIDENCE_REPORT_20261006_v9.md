# EVIDENCE REPORT v9 — SPRINT M2-IMPL, REOPENED WINDOW (Dispatch #009-A)

**Team:** TEAM-CODE | **Window:** M2-impl REOPENED per Amendment A1 (P0
escalation intake) | **Date:** 2026-10-06 | **Baseline:** v8 (commit
c61519a) | **Exit state:** v9 (commit 6e97c69)

Zero external-target interaction; all reproduction targets are local
synthetic stand-ins; zero offensive technique.

---

## 1. Mission outcome (Amendment A1)

| WP | Deliverable | Status |
|---|---|---|
| WP-J (P7 root cause) | D-J report + local reproduction + interpretation settled | **DONE** (commit 4c202e1) |
| WP-I (exit-code honesty) | CLI/worker gates + 20 contract tests + e2e evidence | **DONE** (commit 7d40f61 line-set; see §3) |
| WP-K (template class fix) | Template fixed + full sweep + 10-test contract suite | **DONE** (commit sequence §4) |
| NF-009A-02 (found in-window) | Campaign-node gate-order fix (NameError on deny path) | **FIXED** (AST-verified) |
| Exit gate additions A11–A13 | see §6 | **MET** |

## 2. WP-J — D-J root cause (NF-L0-01)

Full report: `deliverables/DJ_P7_ROOT_CAUSE_20261006.md`. Headlines:

- **Reproduced locally**, same command shape as the lab run:
  `hunt --target http://127.0.0.1:8977 --scope scope.yaml` against a
  synthetic local target with a local OpenAI-compatible LLM stand-in.
  Result: **EXIT_CODE=0**, `production_trace.complete=False`, 8 of 12
  required stages missing, **zero exceptions** on the path.
- **Interpretation B settled** (with the refinement recorded in D-J §4):
  the hunt surface is a DIRECT spine consumer
  (`hunter_runner.py:661-662`, `entrypoint="direct_invoke"`) that never
  enters the compiled-graph campaign lane — NF-M2-01's transport-death
  mechanism does not apply on this path. Nothing was swallowed: the
  defect is a **missing consumer-side completion gate**
  (`commands.py:1292-1293` printed the summary and returned 0; the trace
  was faithfully computed at `production_spine.py:294-307` and consulted
  by nobody).
- **Escalation (WP-J(c)):** missed production paths confirmed —
  `agents/hunter_runner.py` (hunt --target), `production/autonomous_recon.py`
  (scan --adapter-free), plus worker status honesty. The WP-I fix needs NO
  thaw beyond the conditional grant: the runners stay frozen, the gate
  reads what they already return.
- Evidence: `deliverables/m2a_evidence/p7/` (exit codes, logs, campaign
  summary trace block), harness mirrored at `scripts/m2a_p7_repro/`.

## 3. WP-I — exit-code honesty (fix + contract tests)

**Conditional thaw exercised (WP-I(c), exit-code-honesty changes ONLY):**
`src/webpent/cli/commands.py`, `src/webpent/workers/pentest_worker.py`.
The complete scoped diff is adjudicated in
`deliverables/m2a_dossiers/D3-A_WP_I_scoped_diff_review.md` (WP-H
scoped-file precedent).

Changes:

1. `_enforce_chain_honesty()` + call sites: `hunt --target` and
   `agent-hunt` exit **1** with a loud error naming the missing required
   stages and pointing at the trace when the resolver trace is incomplete
   — or absent (fail-closed).
2. `_chain_honesty_verdict()` + call site: the `scan` graph path gates on
   the research-campaign lane markers **before** the "Engagement
   Completed" success panel: skip marker or missing executed-marker →
   exit 1 with the reason (composes with WP-E operator visibility).
3. `scan --adapter-free` gates on no-executable-hypotheses / zero
   executed decisions / trace completeness.
4. Worker completed path: `_chain_short_circuit_reason()` + status flip
   to loud `completed_incomplete_chain` (findings still persisted first —
   evidence preservation).

Contract tests: `tests/team1_acceptance/test_m2a_exit_code_honesty.py`
(20 tests): direct gates (complete/incomplete/absent, message content),
CLI end-to-end through the real Typer app (hunt incomplete → non-zero;
hunt complete → 0; agent-hunt → non-zero; scan executed → 0; scan
skipped → non-zero; scan missing markers → non-zero), and the A12 sweep
pins (every chain-bearing operator path carries its gate; gate ordered
before the success panel; worker status strings present).

**End-to-end evidence (reopened harness):**

| Run | Pre-fix | Post-fix |
|---|---|---|
| `scan --skip-recon` (chain short-circuits) | exit 0 + "Engagement Completed" | **exit 1** — `SCAN FAILED — research chain short-circuited: research campaign did not execute` |
| `scan` full (no-llm; lane skips `no_hypotheses`) | exit 0, silent | **exit 1** — WP-E skip warning + `SCAN FAILED — … no_hypotheses` (one coherent honesty surface) |
| `hunt --target` (P7 shape) | exit 0 + `complete=false` | **exit 1** — `HUNT FAILED — production trace incomplete (missing required stages: …)` |
| CLI scan with executed chain (contract) | — | **exit 0** (no false-failure: `test_executed_chain_scan_exits_zero`) |

## 4. WP-K — template class fix (NF-L0-02, LCS-1 unblock)

- `credentials_template.json` stripped to loader-clean owner/foreign
  profiles: the `_readme` documentation string (the lab's
  `ValueError: profile '_readme' must be a JSON object.`) and the
  loader-alien `alias` / `_api_key_example` fields are gone; guidance
  moved to `docs/credentials_template_README.md` (documentation must not
  occupy machine-consumed profile slots).
- **Sweep result (WP-K(b)):** every shipped template round-tripped
  through its REAL consumer:
  - `credentials_template.json` → `webpent.cli.loaders.load_creds_file`
    (consumed by `scan --creds-file` and `hunt --credentials-file`) — PASS;
  - `scope_template.yaml` → `webpent.scope.parser.parse_scope_file` +
    `ScopeEnforcer` — PASS (v4 template already grammar-compliant);
  - `docs/target_adapter_review_packet_template_v1.json` →
    `shared.target_adapter_review.validate_target_adapter_review_packet`
    — PASS (draft placeholders explicitly supported);
  - `src/webpent/templates/reports/report.html.j2` and `html.j2` → their
    real Jinja `FileSystemLoader` environments (mirroring
    `reporter/export.py`) render end-to-end — PASS;
  - documented boundaries (no runtime consumer): `docs/templates/
    engagement_dashboard.html` (docs-only), `benchmarks/goed_v1_5/
    target_template.py` (Python module, not a data template).
- **Class closure:** `tests/team1_acceptance/test_template_contracts.py`
  (10 tests) pins the real-consumer round-trips, the negative loader
  contract (documentation slots and unsupported fields are rejected), the
  loader-supported API-key profile shape, and an INVENTORY GUARD: any new
  shipped template without a contract entry fails the suite.
- The stale v4-era pack-contract test (asserting the loader-alien
  `alias` field) was AMENDED to the real-loader contract (justified
  modification, C5): `tests/test_campaign_pack_contract.py`.

## 5. NF-009A-02 (found during WP-J re-verification, fixed)

`_research_campaign_node` (builder.py) ran the WP-F multi-principal flag
gate BEFORE `annotated_hyps` was bound — a flag-deny crashed the lane
with `NameError` instead of failing closed by filtering
advisory-intake-sourced candidates. Fixed by reordering canonicalization
before the gate (AST-verified: binding 1485 < gate 1512) and giving the
R7 skip path an honest, distinct reason
(`multi_principal_execution_flag_gated`). M2 transport/chain-gate suites
green after the fix (23 passed).

## 6. Acceptance (A11–A13) + standing exit criteria

- **A11** — D-J delivered; interpretation settled with evidence; the
  CLI/worker operator surface is covered by through-path contract tests
  (hunt/agent-hunt through the real Typer app; scan/worker verdicts
  unit-driven; the compiled-graph chain truth remains the WP-G exit-gate
  test, which stays green — 23 M2 tests).
- **A12** — exit-code honesty contract-tested (positive AND negative
  controls); the sweep pins prove no silent zero-exit path remains on the
  chain-bearing operator surface (hunt --target, agent-hunt, scan
  full-graph, scan --adapter-free, worker completed path). Non-chain
  commands (findings/report/graph/evidence/investigate/preflight/config)
  have no chain to lie about — documented in the sweep.
- **A13** — all shipped templates round-trip through real loaders under
  test; the credentials template passes the actual loader (LCS-1
  unblocked).

## 7. Window discipline (charter compliance)

- Every commit followed by `gate_frozen_delta_m2.py --phase reopened`
  **GREEN** (reopened-phase gate: v8/v9 anchors, amended thaw union,
  auth-map additions; the gate itself evolved only as authorized
  mechanics).
- **Full suite:** 3190 passed, 1 xfailed (documented strict xfail, B-06
  residual), 0 failed — floor 3132 live
  (`deliverables/full_suite_v9_20261006.txt`).
- **Integration battery:** 153 passed + RF-01 floor gate green
  (`deliverables/integration_battery_20261006_v9.txt`).
- **g02 direct-I/O inventory:** pure linedrift regen adjudicated
  (0 identity-level sites added/removed; 422 line shifts from the scoped
  WP-I edits; v4 linedrift lineage; reviewable script
  `scripts/regen_direct_io_inventory_m2a_20261006.py`).
- **v9 re-freeze:** `frozen_modules.sha256` regenerated (708 entries);
  delta vs v8 = EXACTLY the authorized set (`cli/commands.py`,
  `workers/pentest_worker.py` via the WP-I(c) conditional grant;
  `graph/builder.py` via NF-009A-02). Anchors: v9 manifest sha256
  `50881e0f…b987f` recorded in `scripts/m2a_anchor_record.json`; frozen
  gate, standing gates (manifest-vs-head, anchor) GREEN post-commit.

## 8. Commit chain (reopened window, baseline c61519a)

| Commit | Content |
|---|---|
| (reopen) | Gate reopened-phase mechanics + anchor record |
| (fix) | NF-009A-02 gate-order repair |
| (WP-K) | Template fix + README + 10-test contract suite |
| (WP-J) | D-J report + repro harness mirror + evidence |
| (WP-I) | Honesty gates + 20 contract tests + e2e evidence |
| 6e97c69 | v9 re-freeze + adjudications + battery/suite evidence |

## 9. Escalations to the Orchestrator

1. **Surface coverage (WP-J(c)):** the hunter (`hunt --target` /
   `agent-hunt`) and adapter-free-recon surfaces are production spine
   consumers outside the M1/M2/RED-2 audit-series coverage. The exit-code
   honesty is now enforced at the operator boundary; through-path chain
   coverage for THESE surfaces should be scoped into the verification
   cycle (the surfaces themselves remain frozen — no thaw was needed).
2. **Interpretation-B refinement:** the P0 was a missing completion gate,
   not an exception-swallowing wrapper; R7 honesty now extends to
   exit-code semantics across the operator surface (implemented).
3. LCS-0b B1 lab archive not requested — local reproduction succeeded.
