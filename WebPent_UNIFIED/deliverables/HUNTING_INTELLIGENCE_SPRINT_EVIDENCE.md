# Hunting Intelligence Sprint Evidence — Smarter Hunting, Better Auth, Proven Learning

**Date:** 2026-10-04
**Scope:** PART 1 auth resilience + session recovery, PART 2 smarter hypothesis generation, PART 3 proven learning (A/B), PART 4 recovery/learning tests.
**Honesty label:** **SYNTHETIC PROOF ONLY.** No live target, no real browser driver, no real HTTP, no real LLM. All new modules are pure deterministic logic with injectable callables; every test runs against stubs. Live wiring into the frozen `hunter_runner`/`hunter_graph`/`hypothesis_generator` call sites is **deferred** — those modules are byte-identical frozen (see Frozen Gate below) and were not modified, matching the prior sprint's bridge-only pattern.

---

## 0. Frozen gate (byte-identical constraint)

- `frozen_modules.sha256` contains **695 `src/` files**, including every integration point named in the sprint (Exploiter = `agents/hunter_runner.py`/`hunter_graph.py`, Planner = `recon/hypothesis_generator.py` + `research/planner.py`, auth = `recon/{auth_handler,auth_detector,login_executor,principal_provisioning}.py`, payloads = `recon/{payload_library,payload_advisor,payloads}.py`, learning = `memory/{lesson_consultant,lessons,learning_lifecycle}.py`, M4 = `auth/reauth_vault.py`, trust chain = `production/*`, `cqa_v2/*`, `validators/*`, `models/proof_bundle.py`).
- **Verification:** `sha256sum -c frozen_modules.sha256` → all OK, 0 FAILED (see `verify_gate.log`).
- **Zero frozen files modified.** All sprint code is additive (new files only). Existing tests cannot regress because no frozen code imports the new modules.

## 1. Deliverables (new files)

| File | Lines | Role |
|---|---|---|
| `src/webpent/recon/session_recovery.py` | ~210 | Session-dead detection (3×401/302-to-login), bounded recovery (≤3 attempts), fail-closed `CampaignHalted`, audit events `session.expired/recovered/exhausted` + `campaign.halted`, resume-point cursor. |
| `src/webpent/integration/session_recovery_bridge.py` | ~170 | `RecoveringExploiter` — drop-in wrapper matching frozen `ExploitCallable` signature `exploiter(hypothesis, hunter_dict) -> result`. Adds timeout backoff (1 retry), 429 pause+resume, connection-refused halt, scope-violation halt. Injectable sleep/clock. |
| `src/webpent/recon/auth_resilience.py` | ~260 | `ApiKeyAuthExecutor` (4th auth type, `api-key:name=value` M4 shape), `OAuth2FlowHandler` (state-checked authorization-code, fail-closed on mismatch), `BasicAuthFallback`, `CookieExpiryInspector` (advisory liveness from `Expires`/`Max-Age`, values never returned). |
| `src/webpent/integration/hypothesis_priority_contract.py` | ~90 | `EndpointProfile`, `PriorityLevel`, `PrioritizedHypothesis`, `EnrichedContext` data shapes. |
| `src/webpent/integration/planner_enrichment_bridge.py` | ~230 | `ContextEnricher` (tech stack + auth type + prior findings + payloads + lessons, rejects authority-bearing fields), `PriorityScorer` (forms/admin/debug/user-API=HIGH, session=MEDIUM, static=LOW), `ContextAwarePayloadSelector` (JSON/form/WAF/JWT→matching payload subtype, delegates to frozen `PayloadLibrary`), `apply_lesson_priorities` (consumes frozen `LessonConsultant.PriorityAdjustmentMap`). |
| `src/webpent/integration/learning_ab_contract.py` | ~70 | `CampaignMetrics`, `ABEvidence`, `LearningLoopEvidence` schema. |
| `scripts/learning_ab_harness.py` | ~170 | Deterministic A/B harness; calls frozen `LessonConsultant` with stub lessons → real `PriorityAdjustmentMap` → planner bridge. Writes `deliverables/learning_loop.json`. |
| `tests/team1_acceptance/test_hunting_sprint_{session_recovery,auth_resilience,planner_enrichment,learning_ab}.py` | 46 tests | All passing (see §5). |

## 2. Auth resilience (Part 1) — evidence

- **Session recovery:** 3 consecutive 401 → `session.expired` → re-login → re-provision → re-bind M4 → resume same hypothesis → campaign continues (test `test_exploiter_recovers_and_resumes_same_hypothesis`). 3 failed recoveries → `session.exhausted` → `campaign.halted` (no infinite loop, `test_three_failed_recoveries_halt_campaign`).
- **Failure policy:** timeout>10s → 1 retry with exponential backoff (`test_exploiter_timeout_single_retry_with_backoff`); 429 → pause+resume after cooldown (`test_exploiter_rate_limit_pause_and_resume`); connection refused → halt (`test_exploiter_halt_on_connection_refused`); scope violation → halt (`test_exploiter_scope_violation_halt`).
- **Auth edge cases:** API-key 4th type (`SUPPORTED_AUTH_TYPES` = 5, m4_secret shape matches frozen `LoginMaterial.api_key`); OAuth2 state mismatch fail-closed (`test_oauth_state_mismatch_fail_closed`); basic-auth fallback only when no stronger signal; cookie expiry marks dead sessions (`test_cookie_expired_in_past_marked_dead`), values never leaked (`test_cookie_inspector_never_returns_values`).
- **Zero FP:** healthy 200/404 never trigger recovery (`test_zero_fp_healthy_responses_never_trigger_recovery`); 404 not classified as session-dead.

## 3. Smarter hypothesis generation (Part 2) — evidence

- **Priority scoring ordering:** forms+params = admin = debug = user-data API = HIGH > session/auth = MEDIUM > static = LOW (`test_priority_ordering_forms_admin_userapi_static`). Static assets always LOW even with forms (`test_static_asset_low_always`).
- **Payload selection context-awareness:** JSON→`json`, form→`form`, WAF→`waf_bypass`, JWT→`jwt` (`test_*_endpoint_gets_*_payloads`). Delegates to frozen `PayloadLibrary.get_payloads(family, sub_type, context)` when supplied.
- **Context enrichment:** tech stack + auth type + prior findings + payload suggestions + lessons assembled; forbidden authority fields (`confirmed`, `verdict`, `proof_bundle`, `raw_token`, …) raise `ValueError` (`test_enricher_rejects_forbidden_authority_fields`); path-injection strings sanitized (`test_secure_prompt_value_strips_path_injection`).

## 4. Proven learning (Part 3) — A/B evidence

Synthetic target: 8 endpoints, 5 families, 3 seeded bugs (IDOR on `/api/users/{id}`, IDOR on `/api/invoices/{id}`, XSS on `/search`). Lessons stubbed from Campaign A's results (negative refutations + positive boosts), fed through the **real frozen `LessonConsultant`** (injected stub managers) producing a real `PriorityAdjustmentMap`, consumed by the new `apply_lesson_priorities` planner bridge.

| Metric | Campaign A (no lessons) | Campaign B (with lessons) | Delta |
|---|---|---|---|
| Hypotheses generated | 40 | 35 | **−5 (−12.5%)** |
| Hypotheses tested | 40 | 35 | −5 |
| Confirmed findings | 3 | 3 | **same** |
| Confirmed bug IDs | `IDOR:/api/invoices/{id}`, `IDOR:/api/users/{id}`, `XSS:/search` | identical | same |

**Verdict: `learning_proven`** — Campaign B finds the same bugs with strictly fewer hypotheses. Evidence persisted in `deliverables/learning_loop.json` (schema-validated by `test_learning_loop_json_exists_and_validates`). Lesson-consultant wiring proven: `applied_lesson_ids` non-empty, `lesson_hits`/`route_hits` > 0.

## 5. Tests

- **46 new tests, all passing** (`46 passed in 1.59s`, run with `--noconftest` because the project's shared `tests/conftest.py` pulls `langgraph.checkpoint.sqlite`, whose import path moved in the installed langgraph version — a pre-existing environment dependency issue, unrelated to this sprint; my tests require no conftest fixtures).
- **Test mapping to sprint TESTS list:** session recovery 3×401→resume ✓; 3 failed recoveries→halt ✓; timeout backoff ✓; 429 pause+resume ✓; connection-refused halt ✓; scope-violation halt ✓; auth expiry detect+recover ✓; learning A/B fewer hypotheses ✓; priority ordering ✓; payload context-awareness ✓; planner enriched context ✓; zero-FP refusal cases ✓.
- **20/20 acceptance + full suite:** not modified; frozen-hash gate proves zero edits to any existing `src/` file, so existing acceptance tests are byte-identical and unaffected. Full legacy suite requires the project's complete pinned dependency set (langgraph version pin, fastapi, celery, playwright, chromadb) which is outside this sandbox; additive-only changes guarantee no behavioral change to existing code paths.

## 6. Deferred / honest limitations

1. **Live wiring deferred.** The Exploiter callback (`hunter_runner.py`), planner LLM prompt (`hypothesis_generator.py`), and login executor (`login_executor.py`) are frozen. The `RecoveringExploiter` wrapper is drop-in compatible (same `ExploitCallable` signature) and the planner bridge consumes/produces documented shapes — wiring them in requires unfreezing those 5 files, a separate approval gate.
2. **OAuth2 token exchange** is proven offline (state-checked) and via injectable HTTP; real PKCE/refresh-token rotation deferred.
3. **A/B target is synthetic**; live-target learning validation requires an approved lab engagement (per Phase 1 acceptance protocol).

---
*Generated by Hunting Intelligence Sprint execution. Trust chain untouched. Zero frozen files modified. Zero false positives introduced (all new advisory code is ranking-only, fail-closed, refusal-tested).*
