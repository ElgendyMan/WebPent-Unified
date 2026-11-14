# Generalization Sprint — Changelog

## Phase 2: untouched baseline

- Ran the existing HTTPX + Planner/Exploiter/Validator path against official CrAPI, DVWA, and WebGoat.
- Preserved raw sanitized per-target results under `docs/generalization_evidence/phase2_raw/`.
- Made no WebPent source changes during the baseline run.

## Phase 3: diagnosis

- Recorded the redirect/form/auth/M4/trace/budget gaps in `GENERALIZATION_PHASE3_DIAGNOSIS.md`.
- Classified issues as systemic, partially generic, or unproven rather than labeling them target-specific without evidence.

## Phase 4: systemic fixes

- Added bounded same-origin redirect traversal and redirect structural evidence.
- Added generic HTML form and login-signal modeling.
- Added session-cookie names to structural surface data without retaining cookie values.
- Added explicit authorized-assessment robots override; default robots enforcement remains unchanged.
- Added vault-bound session-cookie attachment in M4; forged caller headers are discarded.
- Added clean LLM-budget halt routing.
- Synchronized observed AVI stages into the report projection without fabricating missing stages.
- Kept non-login POST forms advisory-only after the regression review; login POST and GET forms remain eligible under the existing bounded rules.

## Phase 5: fixed rerun

- Ran fresh processes for CrAPI, DVWA, Juice Shop, and WebGoat.
- Used unique engagement IDs and a unique evidence root to prevent finalized audit-chain collisions.
- Captured 48 real live LLM calls and token-derived costs.
- Verified each target audit chain independently.
- Preserved the honest result: 0 promoted, 23 inconclusive, 2 refuted.

## Validation

- Focused systemic tests: 11 passed.
- Acceptance: 3/3 rounds passed.
- Security gates: 5/5 passed.
- Frozen manifest: 13/13 passed.
- Full suite: 2104/2112 passed; 8 unrelated async-runtime/Playwright/OOB/webhook failures remain and are recorded in the report.
