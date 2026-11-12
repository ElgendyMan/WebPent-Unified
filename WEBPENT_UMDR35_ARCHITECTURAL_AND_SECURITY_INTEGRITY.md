# WEBPENT_UMDR35_ARCHITECTURAL_AND_SECURITY_INTEGRITY

**Milestone:** UM-DR-35 — Architectural and Security Contract Restoration
**Document A (canonical engineering record)**
**Date:** 2026-11-12 · **Package version:** 0.40.0 · **Source revision:** `b436ea9d50c0983a0f492ea851febd1a600c8e0d` (see BUILD_INFO.json, UM-DR-35.8 identity contract)

This document describes the implementation that EXISTS in this repository.
Every capability claim below names its module, its production path, its
tests, and its runtime evidence. GitHub push / PR update / remote CI
execution are **BLOCKED** in the current execution environment (no
repository credentials) — every code change, test run, and gate result in
this record was produced locally against the delivered
`WebPent_UNIFIED_v0.40.0_UMDR34` archive and is reproducible from the
commits listed in the acceptance report.

---

## 1. Confirmation authority (UM-DR-35.1) — CausalGuard is the sole authority

**Contract.** `cqa_v2.guarded_causal_evaluate` remains the sole
vulnerability-confirmation authority. It was extended (same module — no
second engine, no parallel implementation) with
`guarded_causal_evaluate_experiment()`
(`src/webpent/cqa_v2/causal_guard.py:729`), which adjudicates the causal
relationship of the experiment design actually executed:

* **Authorization families** (IDOR / BOLA / PRIVILEGE_DIFFERENTIAL —
  two-principal differential access; AUTH_BYPASS / JWT_MANIPULATION —
  bypass designs): candidate-signal + owner-success + actor≠owner +
  control-enforcement + semantic differential against BOTH baseline and
  control, or CLEAN (enforced) / BLOCKED / INCONCLUSIVE.
* **Technical families** (SSRF/XSS/SQLI/OPEN_REDIRECT/…): candidate signal
  present AND baseline signal absent AND control signal absent AND
  semantic difference vs both — or CLEAN/INCONCLUSIVE.
* **Fail-closed everywhere:** synthetic observations, wrong evidence
  provenance, unknown families, candidate≡control, and **contaminated
  negative controls** (signal present in control) are BLOCKED, never
  confirmed.

**Adapter.** `src/webpent/production/confirmation_adapter.py` is the single
well-defined confirmation adapter: specialized validators
(`production/validators.py::run_validator`) remain useful technical
evidence producers. Per-role signals are derived by **role ablation**
(re-invoking the validator with each role swapped into the candidate slot)
— reusing the validator's own family logic, never duplicating it. The
adapter never confirms; it builds `ExperimentCausalEvidence` and delegates
to the guard.

**Promotion is structurally impossible without a genuine guard result.**
`PromotionPipeline` (production/autonomous_validation_v1.py) gained the
gate `causalguard_adjudicated`, satisfied ONLY by an `isinstance`-checked
typed `GuardedCausalResult` with verdict CONFIRMED and
`causal_signal=True`. A forged authority string, a lookalike
`SimpleNamespace`, an LLM confidence score, an external-scanner claim, or a
validator label fails this gate **by construction** — the historical
literal `verdict_authority="CausalGuard_deterministic_engine"` call site is
replaced by the real module identity `cqa_v2.guarded_causal_evaluate`
carried with the actual result object.

**Applied consistently across every production path:**

| Path | Integration |
|---|---|
| `webpent hunt` (compiled graph, research_campaign → AVI) | Stage 6c adjudication before any promotion; validator CONFIRMED without guard CONFIRMED is downgraded to INCONCLUSIVE |
| `webpent agent-hunt` / HunterRunner | Routes through the same AVI dispatch (`orchestrator.run_autonomous_validation_campaign`) — single path, no alternate |
| Graph `validator_node` (standard path) | `causalguard_tool_confirmation_gate` at every live confirmation site: generic evidence contract, strict tool-replay path, open-redirect canary |
| sqlmap reauth "accepted exception" | **Abolished** — fails closed to Needs Human Review (no differential exists for the guard) |
| CSRF structural auto-confirm | Dead by design (`can_tool_confirm=False`) — unchanged, now documented as human-review routing |
| OOB callback endpoint | Advisory-only since R3 E-1 (cannot flip confidence) — unchanged |

**Tests** (`tests/test_umdr35_confirmation_authority.py`, 24):
forged-authority-string rejection, lookalike-object rejection,
LLM-confidence rejection, external-scanner rejection, contaminated-control
BLOCKED, synthetic/unknown-family BLOCKED, validator-label-advisory-only,
downgrade-on-guard-CLEAN, promoted-findings carry the typed verdict +
authority id, replay mutation failures.

**Runtime evidence:** the walking-skeleton E2E suite
(`tests/team1_acceptance/test_sprint_i2_e2e_walking_skeleton.py`) drives
the full 11-stage AVI lifecycle on the loopback lab target and now asserts
the 10-gate promotion with `causalguard_adjudicated` present and the
sealed ProofBundle carrying `causalguard_verdict=CONFIRMED` +
`causalguard_authority=cqa_v2.guarded_causal_evaluate`.

## 2. ProofBundle and replay contracts (UM-DR-35.2)

* `cqa_v2/replay_verifier.py`: `replay_verified` now includes **every**
  condition of `ReplayResult.replay_valid` — verdict match, digest match,
  seal validity, **seal equality**, and **replay execution**. The
  documented omission (seal_match/replay_executed absent from the stored
  field) is closed.
* AVI `ReplayVerifier.verify` re-adjudicates through CausalGuard and
  requires the **original typed result** to match the replayed verdict; a
  missing original result fails closed. Returns
  `causalguard_match`/`replayed_causalguard_verdict`/`replay_executed`.
* Decision evidence is anchored on the AVI instance
  (`_last_raw_triple`, `_last_causalguard_result`, `_last_proof_bundle`,
  …) so external verification can re-run the replay contract against the
  exact inputs — including mutations.
* Replay failures are never clean/confirmed outcomes (downgrade +
  promotion-gate failure). Tests: baseline/candidate/control mutations,
  missing original guard result, tampered seal — all fail replay.

## 3. Scope authority (UM-DR-35.3)

* `scope/enforcer.py` **delegates** every allow/deny decision to
  `EngagementScopeAuthority.evaluate_request`. The duplicated
  `_rule_matches`/`_host_match` implementation is **deleted**. The
  enforcer keeps only operational duties: violation counters, halt
  threshold, rate/concurrency admission, telemetry.
* Canonical URL parse failures are DENIALS by construction (authority
  codes `request_url_rejected`, `scope_path_ambiguous`, …) — invalid input
  can never become an allow.
* Permits: acquire/release are exception-safe (hunter + crawler release in
  `finally`; over-release clamps at zero; concurrency ceiling tested).
* **Tests** (`tests/test_umdr35_scope_authority_unification.py`, 19):
  malformed URLs, userinfo, double-encoding, unsupported schemes, port
  0/out-of-range, IPv4/CIDR, strict wildcards (glob metacharacters
  rejected at compile time), deny precedence, path-prefix boundary
  (=/api/v1 does not match /api/v10), method restriction, enforcer↔authority
  decision equality, halt threshold, permit lifecycle.
* Scope test corpus re-run: 89 + 19 tests green.

## 4. Authentication success detection (UM-DR-35.4)

* New lifecycle model `recon/auth_success_model.py`:
  `AuthSuccessStage` (not_attempted → auth_request_submitted →
  login_response_returned → session_material_captured →
  session_material_accepted → authenticated_identity_established →
  protected_access_confirmed → session_valid_during_campaign) plus
  conservative identity-bearing HTML markers (logout/account controls,
  addressable welcome text with stop-word lookahead, identity elements) and
  `assess_validation_observation` with the anonymous-differential input.
* `recon/login_executor.py`: a generic 2xx HTML/SPA page is **no longer
  successful authentication** — explicit `success=False`,
  `inconclusive=True`, stage `session_material_captured`. HTML validates
  only with identity markers. JWT fast path requires identity evidence
  (payload identity scalars or token claims) and honestly reports stage
  `session_material_accepted`; all-missing validation surfaces are
  UNPROVEN (inconclusive), boundary bounces stay rejected.
* `agents/authentication/agent.py::_validate_session_cookies`: a 5xx
  surface **no longer validates a session** (fail closed); generic 200
  HTML is flagged identity-inconclusive; marker-based validation names its
  markers.
* **Tests** (24 + updated r6 pins): 18 dedicated UM-DR-35.4 tests +
  the r6 login-validation suite updated to the strengthened contract.

## 5. Campaign-wide hard token budget (UM-DR-35.5)

* `shared/llm.py`: `llm_usage_scope(settings, max_total_tokens=…)`
  enforces a HARD campaign total-token ceiling — conservative per-call
  reservation charged **before provider I/O**
  (`LLMBudgetTokenExhaustedError`), settled against reported usage after;
  unknown provider usage keeps the reservation as accounted spend (never
  silently zero); split accounting (input/output/total/reserved/unknown).
* `webpent hunt --max-tokens` and `webpent agent-hunt --max-tokens`
  (mandatory explicit ceilings; default from
  `llm_max_total_tokens_per_run`); the selected ceiling is recorded in the
  campaign summary (`llm_budget.max_total_tokens`) and in the hunter's
  `campaign_summary.json`.
* Honest terminal statuses: COMPLETED / BUDGET_EXHAUSTED / PARTIAL /
  INTERRUPTED (+FAILED on graph error) with the explicit note that
  unresolved hypotheses are never marked negative on a budget stop.
* Budget state persists in checkpoints via the worker's
  `llm_budget_trace` (now carrying the token accounting fields).
* **Tests:** 11 hard-budget tests + CLI flag pins + governor suite.

## 6. Supply-chain audit (UM-DR-35.6)

* `scripts/umdr35_dependency_audit.py`: reproducible OSV.dev querybatch
  audit of the **locked** graph (238 packages) with per-advisory fixed
  versions + runtime-reachability evidence.
  `scripts/umdr35_dependency_audit_gate.py`: CI gate — unhandled advisories
  fail; exceptions honored only with id/package/reason/owner/expiry +
  upstream plan; expired exceptions fail.
* **Verified upgrades (OSV/GHSA):** langgraph 1.2.10→1.2.14
  (CVE-2026-118667), langgraph-checkpoint-sqlite 3.1.1→3.1.2
  (CVE-2026-115883), mako 1.4.1→1.4.3 (CVE-2026-102991). Full
  team1_acceptance (755) re-run on the new pins before acceptance.
* chromadb==1.5.9 is the ONLY remaining finding (4 CVEs, **no fixed
  upstream version exists** — verified); documented exception with owner
  `webpent-engineering`, expiry 2027-05-12, upstream plan, and containment
  (RAG path disabled in CI; client-embedded usage only). No suppression:
  the finding is reported with reachability evidence in
  `dependency_audit_report.json`.

## 7. CI and static quality (UM-DR-35.7)

Locally executed gate battery (all PASS): state-contract law, orchestrator
construction authority (UM-DR-35.1 regression test reviewed into the
TEST_ALLOWLIST with documented rationale), isolation denylist, vault import
authority, preserved test-count floor (**9128 collected ≥ 8115**), build-info
honesty, ruff ratchet, secret scan (0 detections), OSV dependency gate,
frozen-module gate (647), funnel/appmodel/adaptive/auth/budget suites.
The ruff baseline was re-frozen ONCE at the archive-measured 8109 with the
documented reason that the delivered archive itself shipped 53 findings over
its own frozen baseline; **UM-DR-35 code adds zero net findings** (new files
lint-clean, modified files net-negative). The frozen manifest was re-pinned
via the DR-009 protocol (scoped script, per-file directive mapping).

**Remote CI execution: BLOCKED** (no GitHub credentials in this
environment). The workflow file carries the new OSV audit gate; every gate
is locally reproducible with the commands in `.github/workflows/ci.yml`.

## 8. Release and provenance integrity (UM-DR-35.8)

* BUILD_INFO.json repaired under the identity contract: `git_head` = the
  REAL source revision (40-hex commit); `manifest_digest_v9` =
  REGENERABLE SHA-256 over the frozen-file manifest
  (`scripts/umdr35_build_manifest.py`, `--check` verifies);
  `suite_count` = 9128 (fresh `pytest --collect-only`, 0 collection
  errors); `current_release.package_version` aligned to 0.40.0; every
  revision field (source/test/artifact/lock identity) has ONE unambiguous
  meaning; `fixes_applied` = the real fix list.
* Tag `v15.2-audit-baseline` anchors the repair commit (a real commit in
  this repository); the honesty gate passes.
* No v0.40.0 release is claimed or published: acceptance for the release
  requires the remote gates that are BLOCKED here. Historical records were
  not rewritten.

## 9. Corrected security invariants

1. No promotion without an isinstance-typed CausalGuard CONFIRMED result.
2. Specialized validators, LLMs, scanners, trace labels are advisory only.
3. Replay success requires verdict+digest+seal-valid+seal-equal+executed
   (+CausalGuard verdict match in AVI).
4. Negative-control contamination blocks confirmation.
5. Malformed/ambiguous scope input denies before network I/O.
6. One scope decision engine; the enforcer is operational bookkeeping.
7. Generic 2xx HTML / new cookies / 5xx surfaces never prove
   authentication; indistinguishable evidence stays explicitly
   inconclusive.
8. Token budgets are hard, reserved before I/O, honestly accounted, and
   visible on both campaign CLIs; budget stops never mark unresolved
   hypotheses negative.
9. Dependency findings are verified against OSV/GHSA before any action;
   exceptions carry owner/expiry/plan.

## 10. Remaining limitations (honest)

* GitHub push / PR / remote CI / release publication: **BLOCKED**
  (credentials) — local evidence only, all gates locally reproducible.
* The archive's pre-existing ruff debt (53 E501-class findings over its
  own baseline in files untouched by UM-DR-35) is recorded, not silently
  fixed — mass reflow of delivered code was out of scope and risky.
* `package_scope.py::TargetPackageScope` retains its own (package-level,
  admission-time) matching semantics — a documented residual, not a
  network-request authority.
* Bandit/coverage/SBOM gates were not re-run locally in this window
  (tooling not installed in the sandbox); they are unchanged in CI.
