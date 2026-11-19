# WebPent VIP Audit Delivery Notes

> **Historical delivery record:** This file records the earlier audit/remediation release. It is retained for audit history and is not the current v72 source of truth. For the current state, see [`v72_plan_compliance_audit.md`](v72_plan_compliance_audit.md) and [`v72_release_notes.md`](v72_release_notes.md).

## Verification

This historical release was checked locally on 2026-08-18. The v72 follow-up verification is recorded separately and supersedes the numbers below where they differ.

| Gate | Result |
|---|---|
| Historical full pytest suite | 576 passed, 66 warnings |
| Historical preserved test-function verifier | 537 functions, minimum 498 |
| Ruff on remediation files | Passed |
| Local WAPTLab regression | 20/20 dispositions; 13 inconclusive, 7 missing-validator; target-free |
| WAPTLab source tree | Not modified |

## Included remediation

The release includes the VIP authorization and deployment hardening, shared token revocation, atomic resume consumption, transactional HTTP/WebSocket/Playwright SSRF protection, tenant-aware authorization, login-specific throttling, bounded re-auth vault sweeping, raw request deadlines and byte budgets, centralized subprocess manifest enforcement, structured deserialization flag validation, opaque secret references, recursive checkpoint and metadata redaction, coverage ledger and fixed-top-N removal, Surface Evidence Graph identity/workflow enrichment, deterministic campaign planner and hypothesis DAG, validator capability registry, offline evidence/oracle/cleanup adapters for the seven unsupported campaign classes, redaction-safe Evidence Ledger, approval-gated Proof Engine with causal/cleanup/confidence transitions, target-free WAPTLab regression harness, and deployment/CI contract tests.

## Honest limitations

The historical compliance matrix at `docs/vip_audit_compliance_matrix.md` is retained as an audit record. The current v72 status is in `docs/v72_plan_compliance_audit.md`. WebPent still does not claim that every WAPTLab class has a complete validator or that any local synthetic case is a confirmed vulnerability. The v72 dependency upgrade and strict pip-audit verification are complete; worker/Docker qualification and live WAPTLab qualification remain blocked and are not hidden by this historical note.

Before production exposure, set strong random values for `AUDIT_SECRET_KEY` and `CELERY_PAYLOAD_KEY`, use TLS Redis, configure trusted proxies correctly, and perform an authorized deployment smoke test.
