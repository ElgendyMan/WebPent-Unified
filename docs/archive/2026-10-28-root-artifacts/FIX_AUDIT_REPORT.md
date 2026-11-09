# FIX REPORT — Hostile-Audit Defects Remediated

**Scope:** Remediation of P0/P1/P2/P3 defects found in hostile self-audit of the
behavioral-validator refactor. Changes confined to `src/webpent/production/validators.py`
and `tests/team1_acceptance/test_behavioral_validator_refactor.py`.

## Frozen-modules verification
695 source modules (all except validators.py) re-hashed after fixes:
`diff frozen_modules.sha256 /tmp/frozen_after.sha256` → **identical (byte-identical CONFIRMED)**.
`VALIDATORS` registry and `run_validator` chain: byte-identical to original.

## Defects fixed (with evidence)

| id | sev | defect | fix | post-fix evidence |
|----|-----|--------|-----|-------------------|
| D1 | P0 | `responses_similar` returned True for empty/single-char bodies → false IDOR CONFIRM | Fail-closed: empty token sets → False; require ≥2 shared distinctive (len≥4) tokens + ≥1 shared digit-bearing resource identifier (generic anti-boilerplate) | `validate_idor(200,'',200,'',404)` → INCONCLUSIVE (was CONFIRMED); boilerplate-heavy different pages → not similar |
| D2 | P1 | SSRF `control_rejected` accepted a 200 merely-different control | Removed `or response_differs(c,nc)`; control must be 4xx/5xx or carry error signature | `validate_ssrf(..., nc=200 'other page')` → INCONCLUSIVE (was CONFIRMED) |
| D4 | P2 | XSS confirmed in `application/json` / missing content-type | 3-class content-type: executable (html/xml/svg/plain/missing) → proceed; ambiguous (json/javascript) → INCONCLUSIVE; binary → INCONCLUSIVE | XSS in application/json → INCONCLUSIVE (was CONFIRMED) |
| D5 | P2 | Info disclosure: 5xx + one 'error' word added a full indicator class | Require 5xx + ≥2 error-pattern matches + material difference from baseline | 500 "An error occurred." → REFUTED (no confirm) |
| D6 | P2 | Boilerplate-heavy pages could be "similar" (Jaccard ≥60%) | min_overlap raised 0.60→0.70 + distinctive-token + digit-bearing-resource-id guards | 50× navlink/footer boilerplate, different resources → not similar |
| D7 | P3 | `marker_reflected` dead code (`raw_positions` unused) | Removed | — |

## Honest evidence labeling (Phase 3 — no overclaim)
- **Juice Shop "regression"**: synthetic JSON unit tests only. **No actual Juice Shop
  campaign was run.** Campaign run requires full runtime environment (docker-compose
  targets) — marked PENDING / UNVERIFIED.
- **WebGoat "generalization"**: synthetic HTML/plain-text/XML unit responses only.
  **No actual WebGoat campaign was run.** Marked PENDING / UNVERIFIED.
- **20/20 acceptance (PART 4.4)**: referenced in docs; not run in this sandbox. UNVERIFIED.
- **Full suite (PART 4.5)**: 2014/2201 passed in this dependency-degraded sandbox
  (bcrypt/celery/torch/sqlmap/browser missing); all 180 failures are import-time
  `ModuleNotFoundError`, none reach validator logic. The full 2201 pass is UNVERIFIED
  here and requires the complete CI environment.

## Post-fix test results
- Validator unit tests: **69/69 pass** (22 existing + 47 new, incl. 7 hostile-audit
  regression guards). 5 integration tests fail identically before/after (need heavy deps).
- All 8 hostile-attack cases re-validated: PASS (P0/P1/P2 non-confirm; generalization
  and regression still confirm; foreign-denied still REFUTED).

## Scope decision (D8 — explicit)
PART 3 of the task lists exactly 6 validators (idor/bola, xss, ssrf, open_redirect,
info_disclosure). The remaining four (Mass Assignment, Business Logic, File Upload,
JWT Manipulation) retain their hard-coded English/Unix-string checks and are
**explicitly OUT OF SCOPE for this sprint** — tracked as a follow-up item. No
target-specific code was added.

## Remaining before a true PASS (unchanged from audit checklist)
1. Run actual Juice Shop + WebGoat campaigns (or keep UNVERIFIED label).
2. Run full 2201 suite in CI with all deps (or keep 2014/2201 honest label).
3. Run 20/20 acceptance rounds (or keep UNVERIFIED).
4. Decide whether the four out-of-scope validators are a separate sprint.
