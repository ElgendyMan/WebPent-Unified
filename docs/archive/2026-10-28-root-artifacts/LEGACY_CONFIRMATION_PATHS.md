# LEGACY_CONFIRMATION_PATHS.md — TEAM-1 AVI V1.2 Trust Hardening Audit

**Date:** 2026-09-17
**Objective:** Identify every path that can create CONFIRMED / PROMOTED / SECURITY_REPORT. Expected: ONE production authority.

---

## 1. Production authority (ONE) — canonical path

```
CausalGuard (identity binding + causal validator)
  → ProofBundle (sealed, HMAC, semantic fields)
  → Replay (digest + outcome + semantic relationship)
  → PromotionPipeline (8 gates, fail-closed)
  → SecurityReport (promoted + seal + replay + semantic)
```

**Location:** `src/webpent/production/autonomous_validation_v1.py`
- `_compute_identity_binding()` — CausalGuard identity binding (actor/resource/auth/causal difference)
- `_build_and_seal_proof()` — ProofBundle with semantic fields in `causal_oracle` + `identity_context`
- `ReplayVerifier.verify()` — digest + outcome + seal + semantic_match
- `PromotionPipeline.evaluate()` — 8 gates including `semantic_identity_bound`
- `SecurityReport.add_promoted()` — requires promoted + replay + seal + semantic

This is the **only** path that produces a promoted security report in the production graph.

---

## 2. CONFIRMED producers (validator layer — advisory only)

| File | Producer | Status |
|---|---|---|
| `src/webpent/production/validators.py` | `validate_idor/open_redirect/ssrf/mass_assignment/info_disclosure/auth_bypass` | Advisory — CONFIRMED here is NOT promotion. Must pass identity binding + ProofBundle + Replay + PromotionPipeline. |
| `src/webpent/production/autonomous_validation_v1.py` | `_run_one_decision` downgrades CONFIRMED→INCONCLUSIVE if identity binding fails. | Production — gated. |
| `src/webpent/cqa_v2/causal_guard.py` | CausalGuard v2 | Legacy — not wired to production SecurityReport. |
| `src/webpent/shared/proof_oracles.py`, `proof_engine.py` | Proof oracles | Legacy/advisory — not on production path. |
| `src/webpent/llm_researcher/causal_feedback_bridge.py` | LLM causal feedback | Advisory only — no promotion authority. |
| `src/webpent/agents/*/agent.py` (many) | LLM agents may emit "confirmed" | Advisory only — cannot create SecurityReport. |
| `src/webpent/production/external_observation_adapter.py` | External scanner adapter | Advisory only — `EXTERNAL_SCANNER_AUTHORITIES` rejected by PromotionPipeline. |

**Conclusion:** CONFIRMED from validators is necessary but NOT sufficient. Only the production PromotionPipeline (with identity binding) can promote.

---

## 3. PROMOTED producers

| File | Producer | Status |
|---|---|---|
| `src/webpent/production/autonomous_validation_v1.py` `PromotionPipeline.evaluate()` | SOLE promotion authority | Production — 8 gates, fail-closed. |
| `src/webpent/abhc/contracts.py`, `abhie_v6/contracts.py`, `abhip/contracts.py`, `abhip/loop.py` | Legacy ABHC promotion contracts | Not wired to production SecurityReport. Disabled on production path. |
| `src/webpent/agents/access_control/agent.py` | Agent may claim promotion | Advisory — no authority. |

**Conclusion:** One production promotion authority. Legacy contracts exist in code but are not reachable from the production graph (`build_graph()` → research_campaign → AVI → PromotionPipeline).

---

## 4. SECURITY_REPORT producers

| File | Producer | Status |
|---|---|---|
| `src/webpent/production/autonomous_validation_v1.py` `SecurityReport` | SOLE report authority | Production — requires promoted + seal + replay + semantic. |
| `src/webpent/production/modern_spine.py` | Exposes AVI security_report | Delegates to AVI — no independent report generation. |
| `src/webpent/graph/builder.py` | Surfaces AVI report in graph state | Pass-through — no independent generation. |
| `src/webpent/api/app.py` | API may serve report | Read-only — cannot create. |

**Conclusion:** One production SecurityReport authority. No report from raw decision dictionaries.

---

## 5. Removed / disabled fake promotion paths (V1.2)

- ✅ Legacy validator confirmation alone → cannot promote (identity binding required).
- ✅ Inline confirmation paths in `run_research_campaign` → removed in V1 (delegates to AVI).
- ✅ Test-only promotion paths → none on production path.
- ✅ External scanners → advisory only, rejected by `no_external_scanner_authority` gate.
- ✅ Confidence-only → rejected by `causal_validator_confirmed` gate.
- ✅ Response-difference-only → rejected by `semantic_identity_bound` gate.

---

## 6. Verification

- Source check: `ScopeLaw(`, `ToolBoundary(` do NOT appear in `autonomous_validation_v1.py` (AVI composes orchestrator's authorities).
- `PromotionPipeline` class appears exactly once.
- All 8 promotion gates must pass for PROMOTED.
- SecurityReport.add_promoted fail-closed on missing semantic/replay/seal.
