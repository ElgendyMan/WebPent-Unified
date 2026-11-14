# UM-DR-35/36 Corrective Baseline — Repository Audit

**Date:** 2026-11-12 · **Auditor window:** UM-DR-37 readiness mission (Phase 0) · **Package:** WebPent v0.40.0 (UNIFIED)

## 0. Repository identity at audit time

- **Branch:** `features/v0.39.0-umdr33` (the preferred working branch; all UM-DR-34 and UM-DR-35/36 corrective work continued on it, as instructed — no new corrective branch was needed).
- **HEAD at audit start:** the UMDR-34 baseline snapshot commit.
- **Uncommitted work at audit start:** the full UM-DR-35/36 implementation surface (20 changed files + 5 untracked: `confirmation_adapter.py`, `appmodel_nodes.py`, two charter test suites, the inventory-regen script) — committed during this mission window.
- **Remote state:** no remote configured for push in this environment; local work only. Remote CI: not run (see §Remote).
- **Source of the prior acceptance materials:** the UMDR-34-era `deliverables/2026-11-10/` set and `BUILD_INFO.json` claiming 0.40.0 / suite 9056 — verified against the actual tree, not trusted as-is.

## 1. Verified defects (found by tracing runtime paths, not names)

| # | Defect | Severity | Execution path affected | Evidence at audit |
| --- | --- | --- | --- | --- |
| D1 | **SQLi session-reauth promotion bypass** — a sqlmap-positive marker + a recorded re-auth fact could mark a finding `Tool-Confirmed` with NO differential replay, NO ProofBundle, NO CausalGuard adjudication | Critical | `agents/validator/agent.py` → Finding persistence | `tests/test_m1b_llm_charter_guard.py` pinned the bypass as expected behavior |
| D2 | **Split confirmation authority** — graph validators called `verify_replay_evidence` with caller-asserted booleans; the AVI production path adjudicated nothing (validator CONFIRMED alone could promote) | Critical | `production/autonomous_validation_v1.py` promotion gates | No `causal_guard_adjudicated` gate existed; gate count was 9 |
| D3 | **Content-differential families could never legitimately confirm** — the guard demanded an authorization differential (or path analogy) for every class, so XSS/SSRF/info-disclosure/listing/race re-probes were structurally INCONCLUSIVE or CLEAN | High | `cqa_v2/causal_guard.py` confirmation branches; cloud/ES re-probe validators | family-expansion + arsenal promotion tests failing |
| D4 | **JWT weak-secret offline verification blocked** — the offline-crypto observations lacked the `semantic_digest` completeness channel and the adapter dropped `experiment_domain`/`crypto_verified`, so a fully-recorded offline HMAC replay was BLOCKED as incomplete | High | `agents/api_testing/agent.py` → `production/confirmation_adapter.py` → guard | `test_v13_jwt_advisory.py` promotion test failing |
| D5 | **Cloud/ES listing re-probes recorded an empty differential** — the same fresh GET was passed as BOTH baseline and candidate; the control (marker-free sibling) was never used as the recorded baseline | High | `agents/validator/postp0_checks.py` | Guard ruled CLEAN on a genuinely vulnerable differential |
| D6 | **Discovery funnel rewarded unconfirmed findings as confirmed** — `confirmed_findings = _count(findings)` with zero chain decomposition; no guard/bundle/replay/promoted stages; no appmodel semantic stages | High | `production/discovery_funnel.py` → campaign summary/reporter | `test_umdr33_discovery_funnel.py::test_confirmed_findings` asserted `== 2` for plain unconfirmed findings |
| D7 | **Campaign artifact gap** — no machine-readable integrated campaign result existed at the prompt-required path `artifacts/umdr35_36_integrated_campaign_result.json`; the prior E2E campaign drove `ModernOrchestrator` directly, not the production entrypoint | High | Phase 6 mission contract | `artifacts/` did not exist |

## 2. Already-correct issues (verified present at audit, preserved)

- CausalGuard core adjudication (`guarded_causal_evaluate`) with the 7-condition authorization contract — sound, kept as the sole authority.
- `verify_replay_evidence` proof-bundle sealing, HMAC audit trail, replay digest verification — sound mechanics, kept.
- AppModel library (`appmodel/models.py`, `builder.py`): typed, provenance-carrying entities/relations (8 relation kinds incl. `owns`; 7 entity kinds), evidence-disciplined construction — preserved untouched.
- Scope authority stack (UM-DR-34): canonical `EngagementScopeAuthority`, fail-closed boundaries, atomic engagement context — preserved.
- Frozen-module manifest + DR-009 refreeze protocol, direct-I/O inventory, broad-exception gates — preserved and extended.

## 3. Partially implemented capabilities (closed by this window)

- AppModel graph wiring existed (`SURFACE_SIZING → APPMODEL → HYPOTHESIS` edge, advisory hints channel) but consumer integration and the influence proof were incomplete → closed by `test_umdr36_appmodel_influence.py` (12 tests) and the funnel semantic stages.
- The confirmation adapter existed as a new module with role ablation, but the AVI/verifier/validator convergence was incomplete → closed by the universal boundary work (D1–D5).

## 4. Unverified claims in prior acceptance materials (corrected)

- Prior materials claimed confirmation-authority unification was "complete" while D1–D5 above were executable defects. The prior E2E campaign result (4/4 promoted) was real but drove the orchestrator directly rather than the production entrypoint, and its artifact path/naming did not match the Phase 6.5 contract. Both corrected in this window (integrated campaign through `run_unified_hunt` + `verify_replay_evidence` chain on the authorized IDOR lab, artifact at the required path).

## 5. External blockers (recorded honestly)

- **Remote push / GitHub Actions / release publication:** unavailable in this environment (no remote write access) — local work only; remote CI not run and not claimed.
- **Playwright/browser CI leg:** the pinned-runner change required by Phase 7.1 cannot be validated without remote CI; recorded as not executed.
- **M10 holdout benchmark / Northstar Hub:** out of scope by the mission's own instruction.

## 6. Required corrective actions (→ executed in Phases 1–6)

1. Universal confirmation boundary converging every finding-producing route (D1, D2).
2. Class-aware content-differential confirmation branch + offline-crypto domain + independent-control variant (D3, D4).
3. Evidence-grounded baselines for listing re-probes (D5).
4. Funnel chain decomposition + semantic stages + invariants (D6).
5. Integrated production campaign through the real entrypoint with the same-finding invariant (D7).
