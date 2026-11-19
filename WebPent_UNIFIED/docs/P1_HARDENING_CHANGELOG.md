# WebPent P1 Hardening Sprint — Changelog

## Scope

This sprint completed the P1 hardening requirements for XSS/SQLi evaluation, lifecycle webhooks, exception cleanup, and machine-generated test evidence.

## File-level changes

| File | Change |
|---|---|
| `src/webpent/production/validators.py` | Added fail-closed XSS and SQLi validators and registry exports; preserved existing validator semantics. |
| `src/webpent/production/experiment_fabric.py` | Registered canonical XSS and SQLi experiments for automatic fabric dispatch. |
| `src/webpent/production/autonomous_validation_v1.py` | Added same-principal XSS/SQLi identity-binding branches and explicit runtime payload evidence. Narrowed promotion-path exception handling. |
| `src/webpent/recon/hypothesis_generator.py` | Added executable XSS/SQLi templates while preserving request locations; POST-body hypotheses are explicitly deferred where the governed executor cannot transport bodies. |
| `src/webpent/config/settings.py` | Added lifecycle webhook flags with safe defaults and environment aliases. |
| `src/webpent/models/findings.py` | Added optional campaign and route metadata for redacted lifecycle events. |
| `src/webpent/integrations/webhook.py` | Extended signed lifecycle payloads with event, campaign, vulnerability type, route, and severity context. |
| `src/webpent/service/cost_alerts.py` | Added idempotent promoted/refuted/completed lifecycle webhook dispatch through the existing hardened path. |
| `src/webpent/service/facade.py` | Enabled lifecycle webhook configuration and one-time campaign completion emission. |
| `src/webpent/shared/http.py` | Added typed transport-error alias and preserved untrusted-response attachment. |
| `src/webpent/production/modern_spine.py` | Replaced broad request fallbacks with typed HTTP boundary catches. |
| `src/webpent/agents/validator/agent.py` | Replaced broad catches with explicit expected error tuples, including the canonical HTTP transport alias. |
| `src/webpent/auth/reauth_vault.py`, `src/webpent/production/context_authority.py`, `src/webpent/shared/untrusted_content.py`, `src/webpent/graph/builder.py` | Removed broad `except Exception` handlers from the audited trust-sensitive paths. |
| `.github/workflows/ci.yml` | Runs all required gates and full-suite evidence through `uv run`; uploads complete evidence. |
| `scripts/run_tests_with_evidence.py` | Captures full pytest output, extracts counts, compares against baseline, and fails on new failures. |
| `scripts/check_test_evidence.py` | Fails closed when complete machine-generated evidence is absent. |
| `tests/test_p1_xss_sqli.py` | Focused validator, registry, identity-binding, and hypothesis tests. |
| `tests/test_p1_webhook_lifecycle.py` | Promoted/refuted/idempotency lifecycle webhook tests. |
| `tests/test_p1_exception_hygiene.py` | AST regression for the audited critical files and frozen ToolBoundary identity. |
| `docs/FULL_SUITE_EVIDENCE.txt` | Machine-generated complete-suite evidence. |
| `docs/P1_ACCEPTANCE_EVIDENCE.txt` | Three reproducibility rounds with reliable exit markers. |
| `docs/P1_GATES_EVIDENCE.txt` | All five gates plus frozen-manifest verifier, executed with the locked interpreter. |

## Validation

- Full suite: **2072 passed, 0 failed, 0 skipped, 0 errors**.
- New failures versus baseline: **0**.
- Acceptance rounds: **20 passed / 0 failed** in each of rounds 1, 2, and 3; each recorded exit code is `0`.
- Security gates: all five exit `0`.
- Frozen manifest: `FROZEN MANIFEST: OK (13 files)`.
- Evidence gate: exit `0`.
- Direct-I/O inventory: **4 passed**, with the reviewed gap count preserved at 20.
- Previously failing regression groups: **36 passed** after typed HTTP fallback correction.

## Runtime limitation

A real Juice Shop XSS/SQLi E2E was **not marked as passed**. The local Juice Shop process could not start because Node `v22.22.3` was not installed in the active environment. The unit and integration contracts are green; the real-target E2E remains an explicit follow-up, not a fabricated result.

> Attach `docs/FULL_SUITE_EVIDENCE.txt` to any review or release record. Numbers in this changelog are copied from machine-generated evidence, not handwritten test output.
