# GOED v1 — Phase 1: Discovery Knowledge Inventory
**Date:** 2026-09-03
**Objective:** Audit all current discovery heuristics and classify knowledge items.

## Classification Schema

| Class | Description |
|-------|-------------|
| **A. Generic discovery logic** | Truly generic, target-independent discovery algorithms |
| **B. Target-independent heuristic** | Useful heuristic that doesn't encode specific target semantics |
| **C. Target-specific knowledge** | Encodes specific routes, IDs, tenants, or organizations from benchmarks |
| **D. Benchmark leakage risk** | Files/definitions that must be ISOLATED from the generative engine |

---

## Summary

| Class | Count |
|-------|-------|
| A_generic_discovery | 1 |
| B_target_independent | 52 |
| C_target_specific | 28 |
| D_benchmark_leakage_risk | 47 |

---

## Detailed Inventory


### A_generic_discovery

**`src/webpent/api/app.py`**
- Line 801: `hardcoded_route` = `/api/v1/scans`


### B_target_independent

**`src/webpent/adapters/crapi/option_b.py`**
- Line 81: `probe_pattern_def` = `route_pattern`
- Line 98: `probe_pattern_def` = `route_pattern`
- Line 118: `probe_pattern_def` = `route_pattern`
- Line 138: `probe_pattern_def` = `route_pattern`

**`src/webpent/adapters/local_causal_lab/option_b_contract.py`**
- Line 76: `probe_pattern_def` = `route_pattern`
- Line 151: `probe_pattern_def` = `route_pattern`

**`src/webpent/adapters/webgoat/option_b.py`**
- Line 46: `probe_pattern_def` = `route_pattern`
- Line 65: `probe_pattern_def` = `route_pattern`

**`src/webpent/agents/api_testing/agent.py`**
- Line 39: `hardcoded_route` = `/api/v1/user`
- Line 98: `hardcoded_route` = `/api/graphql`
- Line 101: `hardcoded_route` = `/api/query`
- Line 260: `hardcoded_route` = `/api/v1/me`
- Line 261: `hardcoded_route` = `/api/v1/user`
- ... and 6 more

**`src/webpent/agents/smart_campaigns/agent.py`**
- Line 77: `probe_pattern_def` = `ROUTE_PATTERN`
- Line 94: `probe_pattern_def` = `ROUTE_PATTERN`

**`src/webpent/agents/validator/structural_checks.py`**
- Line 117: `hardcoded_route` = `/api/v1/user`

**`src/webpent/api/app.py`**
- Line 795: `hardcoded_route` = `/api/v1/me`

**`src/webpent/cqa_v2/autonomous_loop.py`**
- Line 48: `hardcoded_route` = `/api/health`
- Line 117: `hardcoded_route` = `/api/admin/users`
- Line 119: `hardcoded_route` = `/api/admin/settings`
- Line 133: `hardcoded_route` = `/api/self/profile`
- Line 135: `hardcoded_route` = `/api/team/dashboard`
- ... and 2 more

**`src/webpent/rta/discovery.py`**
- Line 114: `hardcoded_route` = `/api/openapi-lite`
- Line 144: `hardcoded_route` = `/api/openapi-lite`

**`src/webpent/rta/harness.py`**
- Line 85: `hardcoded_route` = `/api/me`
- Line 87: `hardcoded_route` = `/api/admin/reports`
- Line 91: `hardcoded_route` = `/api/admin/privilege-preview`
- Line 140: `hardcoded_route` = `/api/me`
- Line 140: `hardcoded_route` = `/api/documents/doc-a-1`
- ... and 9 more

**`src/webpent/rta/validation.py`**
- Line 15: `hardcoded_route` = `/api/documents/doc-a-2`
- Line 16: `hardcoded_route` = `/api/admin/reports`
- Line 31: `hardcoded_route` = `/api/admin/privilege-preview`
- Line 37: `hardcoded_route` = `/api/orders/order-a-1/summary`
- Line 206: `hardcoded_route` = `/api/me`
- ... and 1 more


### C_target_specific

**`src/webpent/dcvu/engine.py`**
- Line 72: `hardcoded_id` = `tenant-a`
- Line 93: `hardcoded_id` = `tenant-a`
- Line 105: `hardcoded_id` = `tenant-a`

**`src/webpent/dcvu/fixtures.py`**
- Line 173: `hardcoded_id` = `tenant-a`
- Line 174: `hardcoded_id` = `tenant-a`
- Line 175: `hardcoded_id` = `tenant-a`
- Line 176: `hardcoded_id` = `tenant-b`

**`src/webpent/dcvu/ground_truth.py`**
- Line 107: `hardcoded_id` = `tenant-a`

**`src/webpent/irta/generator/generator.py`**
- Line 100: `hardcoded_route` = `/api/admin/audit`

**`src/webpent/rta/harness.py`**
- Line 141: `hardcoded_route` = `/api/workflows/wf-a-1/preview`
- Line 38: `hardcoded_id` = `tenant-a`
- Line 41: `hardcoded_id` = `tenant-a`
- Line 44: `hardcoded_id` = `tenant-a`
- Line 49: `hardcoded_id` = `tenant-b`
- ... and 7 more

**`src/webpent/rta/validation.py`**
- Line 19: `hardcoded_route` = `/api/tenant/tenant-b/documents/doc-b-1`
- Line 25: `hardcoded_route` = `/api/workflows/wf-a-1/preview`
- Line 43: `hardcoded_route` = `/api/tenant/tenant-b/billing-summary`
- Line 94: `hardcoded_id` = `tenant-a`
- Line 97: `hardcoded_id` = `tenant-a`
- ... and 2 more


### D_benchmark_leakage_risk

**`benchmarks/__init__.py`**
- Line ?: `benchmark_definition` = `__init__.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/abhc_v3_controlled.py`**
- Line ?: `benchmark_definition` = `abhc_v3_controlled.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/abhie_v4_controlled.py`**
- Line ?: `benchmark_definition` = `abhie_v4_controlled.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/abhie_v4_quality.py`**
- Line ?: `benchmark_definition` = `abhie_v4_quality.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/abhie_v6_controlled.py`**
- Line ?: `benchmark_definition` = `abhie_v6_controlled.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/abhie_v6_scorecard.py`**
- Line ?: `benchmark_definition` = `abhie_v6_scorecard.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/abhip_v4_controlled.py`**
- Line ?: `benchmark_definition` = `abhip_v4_controlled.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/abhip_v4_metrics.py`**
- Line ?: `benchmark_definition` = `abhip_v4_metrics.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/adi_multistep_controlled.py`**
- Line ?: `benchmark_definition` = `adi_multistep_controlled.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/avde_multiclass_controlled.py`**
- Line ?: `benchmark_definition` = `avde_multiclass_controlled.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/avrip_deep_controlled.py`**
- Line ?: `benchmark_definition` = `avrip_deep_controlled.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/avrp_multiclass_controlled.py`**
- Line ?: `benchmark_definition` = `avrp_multiclass_controlled.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/failure_matrix.py`**
- Line ?: `benchmark_definition` = `failure_matrix.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/metrics.py`**
- Line ?: `benchmark_definition` = `metrics.py` — Benchmark definitions — must NOT be accessible to generative engine

**`benchmarks/run_dcvu_v1.py`**
- Line ?: `benchmark_definition` = `run_dcvu_v1.py` — Benchmark definitions — must NOT be accessible to generative engine


*... plus items in 32 more files. See JSON for complete inventory.*

---

## Key Findings

### 🔴 Critical: Benchmark Knowledge Boundary

The following MUST be strictly isolated from the generative discovery engine:
- All files in `benchmarks/` (route definitions, ground truth)
- All files in `vip_qualification/` (qualification artifacts)
- Hardcoded route patterns that match benchmark targets
- Hardcoded IDs (u001-u005, tenant-a/b, wf-001, etc.)

### 🟡 Concern: Target-Specific Heuristics

Some discovery logic encodes specific route patterns that match our synthetic targets.
In open-world mode, these must be DISABLED — routes must be discovered from target evidence.

### 🟢 Strength: Generic Logic Preserved

Core CQA v2 causal evaluation, ProofBundle, and Smart memory are GENERIC and target-neutral.
These form the solid foundation for GOED v1.

---

## Recommendations for Phase 2+

1. **Isolation Layer:** Create a strict boundary between generative engine and benchmark knowledge
2. **Open-World Mode:** Add a mode where no route/ID knowledge is pre-supplied
3. **Generative Contract:** Define `GenerativeResearchOpportunity` as the new output primitive
4. **Discovery-from-Evidence:** Routes must be derived from HTTP observations, not dictionaries
5. **Hypothesis Competition:** Multiple competing hypotheses per observation, not single selection

---

*Inventory complete. Classification preserved. No items deleted.*
