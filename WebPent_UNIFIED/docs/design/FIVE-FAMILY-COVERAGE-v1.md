# FIVE-FAMILY COVERAGE v1 — Gap-Closure Design

**Sprint:** gap-closure-final (five high-level logic families)
**Families added:** `business_logic`, `race_condition`, `multi_step_auth_bypass`, `tenant_isolation`, `exploit_chain`
**Policy:** additive only — no existing CQA/RTA/IRTA/GOED behavior modified. All five families are confirmed by stateful/differential replay, NOT by payload injection; deliberately kept outside `EXPLOITABLE_CLASSES` (same policy as `race_condition` / `mass_assignment`).

## 1. Foundation (Phase 0)

### `src/webpent/models/findings.py` — `VulnClass` enum
Added 4 members (32 → 36). `race_condition` already existed (V9 P1 fix).
```
BUSINESS_LOGIC        = "business_logic"
MULTI_STEP_AUTH_BYPASS= "multi_step_auth_bypass"
TENANT_ISOLATION      = "tenant_isolation"
EXPLOIT_CHAIN         = "exploit_chain"
```
All four are outside `EXPLOITABLE_CLASSES` — they are structural/stateful and confirmed by their own deterministic mechanism, never routed through `payload_generator`.

### `src/webpent/agents/validator/registry.py`
All five registered in `_IMPLEMENTED_VALIDATORS` (status=`tested`, evidence_mode=`deterministic`) and in `_ALL_CLASSES`. `coverage_gap()` now returns a deterministic validator id for each.

## 2. Shared contract (Phase 1) — `src/webpent/families/`
`base.py` defines the cross-family contract (mirrors `webpent.business_logic` passive style):
- `FamilyId` enum (5 members)
- `ScenarioSpec` — one testable scenario: preconditions, discriminator experiment, expected signal, negative control, evidence requirements. `extra="forbid"`.
- `FamilyCandidate` — candidate-only (`promotion_status="candidate_only"`), never a Finding.
- `FamilyAnalysis` — per-target aggregate with `coverage_gaps`.
- `FamilyAnalyzer` ABC with `applicable_scenarios()` and `coverage_gaps_for()`.

Invariant: analyzers do NO I/O and NEVER promote. Execution lives in the deterministic validator behind scope policy.

## 3. Family core packages (Phase 1)

| Package | Scenarios | Analyzers |
|---|---|---|
| `race_conditions/` | 5 (double-spend, coupon reuse, TOCTOU upload, rate-limit burst, reset/OTP race) | `BurstPatternDetector`, `IdempotencyInvariant` |
| `tenant_isolation/` | 6 (cross-tenant IDOR, tenant-header spoof, subdomain confusion, shared-resource leak, invite/transfer, admin scope escalation) | `TenantBoundaryDetector`, `CrossTenantAccessMatrix` |
| `multi_step_auth/` | 6 (step-skip, step-token tamper, partial-auth escalation, step-order reorder, MFA response manipulation, reset cross-account) | `AuthStateMachineAnalyzer` |
| `chained_exploits/` | 7 (info-disclosure→ATO, open-redirect→OAuth theft, SSRF→metadata, mass-assign→privesc, race→OTP brute, CORS→exfil, stored-XSS→CSRF theft) | `PreconditionGraphBuilder`, `ChainImpactAmplifier` |
| `business_logic/` (additive) | +6 (price manipulation, workflow step bypass, limit/quota bypass, refund abuse, inconsistent authz matrix, numeric boundary) | existing 4 analyzers + `BUSINESS_LOGIC_SCENARIOS` export |

Total scenarios added: **30** (5+6+6+7+6).

## 4. GOED v1 strategies (Phase 2) — `src/webpent/goed_v1/family_strategies.py`
Mirrors `business_logic_strategies.py`: `BaseFamilyStrategy` + one subclass per family + `ALL_FAMILY_STRATEGIES` + `FAMILY_STRATEGY_REGISTRY` + `generate_all_family_hypotheses()` / `generate_all_family_goed_hypotheses()` (bridges to native GOED `Hypothesis`). `FIVE_FAMILY_GOVERNANCE` enforces hypotheses-from-evidence-only and causal-guard-mandatory.

## 5. Deterministic validators (Phase 3) — `src/webpent/agents/validator/family_checks.py`
Mirrors `active_checks.py`: consumes already-collected `Replay` objects (no I/O), returns explicit `FamilyVerdict` (CONFIRMED / NOT_CONFIRMED / NEEDS_HUMAN_REVIEW / NOT_SCANNED). Five validators + `FAMILY_VALIDATORS` dispatch map. Evidence stores digests only.

## 6. Optional agent layer (Phase 4)
- `agents/tenant_isolation/` — `TenantIsolationHunter` (LangGraph node)
- `agents/multi_step_auth/` — `MultiStepAuthHunter`
- `agents/chain_planner/` — `ChainPlanner`
Each wraps the passive analyzer and delegates replay execution to the validator. Existing `agents/business_logic_fuzzer` (race + state abuse) remains the race/business execution surface.

## 7. Tests (Phase 5) — `tests/test_five_families.py`
33 tests covering enum, registry, all 4 scenario catalogs, all 6 analyzers, GOED strategies, all 5 validators (confirmed/not-confirmed/not-scanned/needs-review paths), and all 3 hunter agents. **33/33 pass.**

## 8. Scenario coverage matrix

| Family | Scenario IDs |
|---|---|
| race_condition | RACE-001..RACE-005 |
| tenant_isolation | TENANT-001..TENANT-006 |
| multi_step_auth_bypass | MSAUTH-001..MSAUTH-006 |
| exploit_chain | CHAIN-001..CHAIN-007 |
| business_logic | BIZ-001..BIZ-006 |

## 9. Items NOT done (policy decisions, not code)
1. Wiring the three new hunter agents into `graph/builder.py` as LangGraph nodes — requires a routing policy decision (which profiles/environments enable them). The agents are import-ready.
2. Live burst execution for race conditions — `validate_race_condition` consumes replays; the actual synchronized-burst HTTP client is a policy/scope decision (unsafe in production).
3. Promoting `business_logic` findings from candidate-only — same gate as existing business-logic passive analyzers.
4. `business_logic/__init__.py` still requires the optional langchain layer (pre-existing); `business_logic.scenarios` is importable standalone via try/except in `family_strategies.py`.
