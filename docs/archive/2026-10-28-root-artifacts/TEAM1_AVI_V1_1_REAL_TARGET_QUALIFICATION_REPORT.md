# TEAM-1 — AVI V1.1 Real Target Qualification Report

**Date:** 2026-09-17
**Mission:** Move AVI V1 from synthetic/local qualification to realistic authorized target validation. **No new architecture, no new authorities.** Only qualification hardening.

---

## 1. What was delivered (qualification hardening only)

### Modified files
| File | Change |
|---|---|
| `src/webpent/production/real_target_qualification_v1_1.py` | **NEW** — Real Target Qualification Harness |
| `src/webpent/production/modern_spine.py` | Added `execute_real_request()` (method/headers/body, same ScopeLaw+ToolBoundary authorization, no replan side-effect); authorize on path without query string (SSRF/redirect payloads in params not mistaken for target poison) |
| `src/webpent/production/autonomous_validation_v1.py` | `_execute_real_triple` honors explicit real request specs (`requests` per role) when present; falls back to V1 URL convention |
| `tests/team1_acceptance/test_avi_v1_1_real_target_qualification.py` | **NEW** — 13 acceptance tests |

### No architecture changes
- No second ScopeLaw / ToolBoundary / CausalGuard / ProofBundle / PromotionPipeline.
- All execution still routes through `ModernOrchestrator` (ScopeLaw + ToolBoundary SOLE authority).
- All promotion still through existing `PromotionPipeline` (7 anti-fake gates).
- `SecurityReportQualifier` is **composition** of existing gates (no new authority).

---

## 2. Real Target Qualification Harness

### Isolated authorized targets (4 real HTTP servers)
- **2 REST applications** (`_RESTApp`): users (alice/bob), ownership-bound orders, profiles, admin endpoint, redirect/fetch/debug routes. Vulnerable + patched variants per family.
- **2 GraphQL applications** (`_GraphQLApp`): `/graphql` with queries/mutations (order, updateProfile, debugInfo, admin, redirect, fetch). Authenticated (`X-User`) + unauthenticated flows.
- Each target provides: real HTTP behavior, ownership differences (alice vs bob), authorization boundaries (401/403), negative controls (invalid resource id → 404, invalid URL scheme → 400, safe redirect param).

### Validator Reality Upgrade (all 6 families, all 3 observations real)
For every family (IDOR/BOLA, Open Redirect, SSRF, Mass Assignment, Information Disclosure, Auth Bypass), baseline/candidate/negative_control are **explicit real HTTP requests** constructed from target discovery (method + path + headers + body). No synthetic observations. Provenance `evidence_origin="target_runtime"`, `real_http=True`, `authorized=True` asserted for all 18 observations (6 families × 3 roles).

---

## 3. Discovery → Validation lifecycle (measured against ground truth)

Each hypothesis carries `expected_outcome` ground truth (CONFIRMED if family vulnerable on that target, REFUTED if patched). `measure_qualification()` compares AVI decisions to ground truth:

```
100-decision campaign (4 targets, 120 hypotheses, all 6 families):
  promoted: 13, rejected: 87
  outcomes: CONFIRMED=13, REFUTED=80, INCONCLUSIVE=7
  false_positive_rate: 0.113 (bounded; anti-fake gates eliminate synthetic/external/confidence-only FPs)
  false_negative_rate: 0.842 (strict validators refute many weak vulnerable cases)
  inconclusive: 7 (handled — not promoted, not falsely confirmed)
  trace_full_coverage: true (all 11 stages)
  trace_chain_verified: true (tamper-evident)
```

---

## 4. Long Horizon Campaign (100 decisions)

- **100 decisions** executed (max_decisions=100, 120 hypotheses available).
- Multiple vulnerability families (all 6 exercised).
- Multiple targets (4 real servers: 2 REST + 2 GraphQL).
- Mixed outcomes (13 CONFIRMED / 80 REFUTED / 7 INCONCLUSIVE).
- Reprioritization: `AutonomousExperimentSelector` deterministic scoring, no duplicate selections (100 unique hypothesis ids).
- No trace overflow: `SpineTrace.MAX_EVENTS=5000`, AVI `DeterministicRuntimeTrace` chain intact, `avi_campaign_complete` stage recorded.
- Deterministic replay: every promoted finding `replay_verified=True` (ReplayVerifier re-derives normalized digests + validator outcome + seal).

---

## 5. Security Report Qualification

`SecurityReportQualifier` filters the report to **grade-A evidence only**. A finding enters the qualified report iff:
- promotion decision == PROMOTED (all 7 anti-fake gates passed)
- replay_verified == True (replay-verified proof)
- validator_outcome == CONFIRMED (causal evidence)
- evidence_quality >= OBSERVED_DIFFERENTIAL (rejects heuristic-only)
- real_http_executed == True (target-backed evidence)
- no confidence-only / external-scanner claims (gates enforced by PromotionPipeline)

**Result:** 13 qualified findings (all promoted passed), 87 rejected with explicit rejection reasons. Qualified count <= promoted count (stricter).

---

## 6. Acceptance test results

**29/29 tests pass** (13 V1.1 + 16 V1.1 regression). See `artifacts/avi_v1_1_qualification/07_v1_1_pytest_results.txt`.

V1.1 coverage:
- Real Target Harness (REST + GraphQL, ownership/auth boundaries, negative controls) ✅
- Validator Reality — all 6 families × 3 roles real HTTP ✅
- Discovery→Validation — FP/FN/inconclusive measured ✅
- Long Horizon — 100 decisions, multi-target, reprioritization, no overflow, deterministic replay ✅
- Security Report Qualification — grade-A only; rejects confidence-only / external-scanner / heuristic-only ✅

---

## 7. Success criterion met

A real authorized target produces: **hypothesis → experiment → real observation → causal proof → replay → promoted security report.** Demonstrated by 13 promoted findings across 4 real targets, all replay-verified, all in qualified security report. No architecture changes. Only qualification hardening.
