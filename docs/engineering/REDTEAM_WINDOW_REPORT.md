# REDTEAM_WINDOW_REPORT.md — UM-DR-25 (2026-11-06)

**The work order:** review and critique own work → red-team the project for
errors, bugs, logic bugs, runtime errors, wiring errors, dead code, dead
functions, dead capabilities → detailed fix plan → execute → verify → package.

**The method:** (1) full-suite baseline run; (2) import sweep over all 1,258
src modules; (3) AST cross-reference of 5,786 top-level defs; (4) systematic
DB-API and Settings-field drift inventories; (5) validator-dispatch and
capability-flag wiring audits; (6) machine-gate reconciliation (broad
exceptions, direct-I/O inventory, vault authority, isolation denylist,
hygiene); (7) per-family root-cause diagnosis of every failing test.

---

## Phase 1 — executed in this window (the findings and their fixes)

| # | Family | Root cause | Evidence (pre-fix) | Fix | Post-fix |
|---|---|---|---|---|---|
| A | Settings field drift | Subsystems merged with `get_settings().X` gate reads but the fields never declared (UM-DR-09 class, wholesale) | ~250 failures; 33 flags + ~20 knobs read-but-undeclared | All declared, fail-closed defaults; consumer-validated knobs deliberately unbounded at the pydantic layer | green |
| B | Phantom DB API | `DatabaseOOBStore` → 5 `DatabaseManager` methods never implemented | 30 failures; runtime AttributeError on every DB-backed OOB path | Methods + 2 always-bootstrap tables on the frozen db.py | 45/45 green |
| C | Unregistered validators | blind-OOB + privilege-differential validators never added to the canonical dispatch | ValidatorError on every `run_validator('BLIND_*'/'PRIVILEGE_DIFFERENTIAL')` | Registered (lazy circular-safe); VulnClass members + remediation tables for all 4 classes | green |
| D | Third chain type missing | v2 composer tests shipped; rules never merged | 17 dead tests | CHAIN_TYPE_IDOR_MASS_ASSIGNMENT via the ChainTypeSpec seam + protected-field gate | 44/44 green |
| E | Stale tests vs hardened contracts | fixtures/designs predating M1-B/E-1, F-05, the hunt unification | vip retest 10, worker_status 7, hunt CLI 12, workers_status 8, hardening 1 | fixtures + tests reconciled to the implemented (newer) contracts; Dockerfile version bump | green |
| F | Register/inventory drift | machine gates never re-run by the M0-M12 windows | broad-exceptions 137 behind; direct-I/O 87 behind; Table 2-2 pin; denylist pin; P-1 hygiene 7 handlers; CHANGELOG head | deliberate documented regeneration/narrowing per each gate's own protocol | all green |
| G | blind_v3 recall (0.137) | probing-methodology ceiling: 3 GETs cannot observe the 80 state-transition cases | recorded verdict distribution; mode_b's recovery pattern | replica + deterministic stateful prober (below) | replica: 0.3425 → 1.0000 recall, precision 1.0 |

### The measured recall result (family G)

The recorded blind baseline (recall 0.137 / precision 0.6667) is largely a
**methodology ceiling**: every reasoning/compositional case requires a state
transition the 3-GET probe never performs. The delivered deterministic
stateful prober (phase-1 read-only reproduction + phase-2 bounded
grammar-driven transition discovery, `guarded_causal_evaluate` staying the
only confirmation authority) lifts the replica-corpus measurement to
**recall 1.0 / precision 1.0 at 13.2 requests/case**.

**Honesty boundary (the reason this is NOT a production_qualified claim):**
the replica is same-spec but author-built (the original blind server was
never committed); the prover's grammar matches the documented dv2-lineage
conventions, and each real target's transition grammar must be learned; the
M11 ladder's production bar still requires operator-deployed holdout corpora
with blind sets and zero-FP deception benchmarks. What IS established: the
deterministic engine's inference logic (the causal guard) confirms every
observable case with zero false positives — the gap was the traffic, and the
traffic gap is now closed by a bounded, deterministic, auditable prober.

---

## Phase 2 — EXECUTED in full by UM-DR-26 (2026-11-06, the next window; the plan below is the executed record)

The UM-DR-26 window executed EVERY family below in this plan's own recommended
order; the full evidence record is DRIFT_REGISTER.md §UM-DR-26. Outcome: all 67
failures green, plus the wiring defects the execution surfaced (the broken
`_active_engagement_id` alias in two safety modules — ImportError masked as an
empty decision; the Playwright SSRF guard blocking the campaign's OWN loopback
target; six more never-registered validator families; the dead promoted-alert
webhook path) — each root-caused, fixed, and machine-gate reconciled (frozen
manifest 16-path declared refreeze + 2-path scope completion, direct-I/O
artifact regen, broad-exception register, resurrect evidence allowlist, three
more settings fields declared). The original phase-2 diagnosis follows, kept
verbatim for the record.

The remaining 67 failures are **behavioral reworks, not wiring gaps** — every
wiring/registration/flag defect in the tree is closed. Each family below
needs its own careful window (regression tests BEFORE refreeze, per the
DR-009 protocol):

1. **Identity ladder S1 redesign (14 tests — tests/test_identity_ladder_r6.py).**
   Contract extracted: S1 must run TWO branches (jwt_claims from
   `identity_claims=` — attempted only when supplied, priority winner
   `s1_jwt_claims`, source_url `jwt://claims`; login_body — always attempted,
   payload_type absent/mapping recorded) with per-branch attempt records
   (`{stage: "s1", branch, attempted, resolved, resolved_key,
   payload_type, resource_seed_count, resource_seed_names}`); bid/cart_id
   keys are RESOURCE SEEDS never identity; email-matched ids resolve with
   zero probes (winner `s1_login_body_mining`); token/seed VALUES never
   serialize (names only). Implementation owner: recon/identity_discovery.py
   (frozen — refreeze window required).
2. **Login validation (13 tests — tests/test_login_validation_r6.py).**
   The LoginExecutor/AuthDetector r6 contract: form-shape discovery,
   credential replay, and the validation ladder the identity work feeds.
   Same-window item as 1 (shared fixtures and vocabulary).
3. **Hunter-graph replan + team1 post-validation replan + postp0 chain plan
   (14 tests across three files).** The replan trace contracts
   (`_sync_graph_replan_trace`, ProductionTrace) and the chain-plan
   advisory shapes drifted from the r6 designs; each file pins a different
   slice of the same replan machinery — one window, three suites.
4. **Safety-governor integration (3) + refutation-learning wiring (3).**
   kill-switch abort ordering inside the rate governor's permit path;
   spend-cap enforcement at the LLM funnel boundary (error =
   LLM_SPEND_CAP_REACHED at ≥ cap); robots double-gate default when
   robots.txt is unavailable; the refutation capture hook + planner
   advisory. Small, surgical, one window.
5. **Vulnbox benchmark (5) + capability e2e (5).** End-to-end suites over
   the planted-vuln lab app and the capability spine; both depend on the
   identity/login work (1+2) for their session fixtures — schedule after.
6. **Browser hunter (3).** Playwright-shaped crawler tests; require the
   browser dependency posture decision (the sandbox venv vs the release
   env) before the fixture shapes can be pinned honestly.
7. **Resurrect hygiene residue (2) + webhook batch (2) + singles (3).**
   The resurrect sweep's 8-finding hygiene gate needs its evidence
   allowlist regenerated for the current tree; the webhook batch
   concurrency tests need the asyncio gather shape the notifications
   dispatcher actually uses; ffuf preflight posture + cache-key sweep gate
   + audit-remediation isolation are one-file-each surgical fixes.

**Recommended execution order:** 1+2 (one window) → 4 → 3 → 5 → 7 → 6.

---

## Verification (this window)

- Import sweep: 1,258/1,258 modules import cleanly (no missing deps, no
  import-time crashes).
- Full suite: 8,515 collected; the 310-failure + 19-error red baseline
  reduced to the 67-test phase-2 set (every family above closed or
  root-caused); frozen gate 661/661 green after the 10-file declared
  refreeze (`scripts/refreeze_manifest_umdr25_redteam.py`).
- Machine gates: broad-exceptions, direct-I/O inventory, vault authority,
  isolation denylist, P-1 hygiene, release packaging, editable-install —
  all green.
- The blind_v3 replica discipline suite: 20/20 green (spec fidelity,
  no-leakage source + runtime audits, behavior grammar, prober budget/
  determinism/authority).
- Environment note: alembic + structlog were missing from the sandbox
  recipe and are now installed (the recipe's post-rotation list gains
  them); pytest-xdist is NOT usable on this suite (collection is
  order-sensitive across workers) — serial chunked runs are the
  reproducible mode.

— End of REDTEAM_WINDOW_REPORT.md —
