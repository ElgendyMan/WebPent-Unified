# Sprint A Remediation Completion Report

**Date:** 2026-10-03  
**Workspace:** `/tmp/webpent_vuln_arsenal`  
**Scope:** Remediation of the hostile-audit findings carried into Sprint A.

## 1. Implemented fixes

### M4-only identity discovery

- `IdentityDiscoverer` no longer accepts or attaches raw login material.
- Identity/resource discovery requires a governed `request_callback`; no callback fails closed.
- `PrincipalProvisioner` seals and verifies the principal through M4 before using the callback.
- Added regression coverage for the missing-callback failure and the absence of a raw credential attachment surface.

### Chaining Engine authority and execution

- Chain eligibility now requires a promoted, sealed/authentic ProofBundle and verified replay metadata.
- Forged promoted metadata without a valid ProofBundle is rejected.
- Chain execution uses the sealed source identifier from step 1 only when it is consumed by an existing governed candidate request.
- No route, method, principal, control request, or new execution path is invented by the chain layer.
- Chain reports remain read-only and do not alter the individual finding lifecycle.

### Persona behavior

- Persona profiles are carried into Planner state and prompts.
- Preferred-family focus affects bounded candidate ordering while the same AVI/M4/PromotionPipeline authority remains in force.
- Personas are therefore behavioral advisory profiles, not labels only.

### Learning loop

- `--client-id` is available on `hunt` and `agent-hunt`.
- When supplied, lesson consultation occurs after recon and before hypothesis ranking.
- Campaign lessons are extracted from actual exploitation decisions and persisted with sanitized audit events.
- Learning remains advisory: it can change ranking only; it cannot create candidates, bypass M4, alter validation, or promote findings.

### Inventory and regression hygiene

- Removed a direct-I/O scanner false positive caused by a local variable named `requests`.
- Regenerated `docs/direct_io_inventory.json` and `docs/direct_io_inventory.md` from the canonical scanner.
- The known pinned unapproved transport set remains visible and unchanged at 20 records.

## 2. Verification results

| Check | Result |
|---|---:|
| Full pytest suite | **2180 passed**, 0 failed |
| Acceptance round 1 | **20 passed** |
| Acceptance round 2 | **20 passed** |
| Acceptance round 3 | **20 passed** |
| Reproducibility | **YES — 20/20 × 3** |
| Frozen manifest | **OK — 13/13 files** |
| State-contract gate | **PASS** |
| Orchestrator-construction authority gate | **PASS** |
| Isolation denylist gate | **PASS** |
| Vault-import authority gate | **PASS** |
| Test-count gate | **PASS — 2180 collected, floor 1940** |
| Direct-I/O inventory contract | **4 passed** |

The full suite emitted 10 warnings (dependency deprecations and intentional dev-mode insecure-key warnings); no test failed.

## 3. Live authorized campaigns

### CrAPI

- Target: local authorized gateway on port 8888.
- Campaign: `arsenal-crapi-chain-20261003-r2`.
- Routes crawled: 32.
- Candidates generated/executable: 14 / 10.
- Validation counts: 2 confirmed, 3 blocked, 0 refuted, 0 inconclusive.
- Confirmed findings: **2 IDOR results**.
- LLM usage: 11 calls; observed cost `$0.04169575` using the configured gpt-5-mini pricing trace.
- Learning: 7 sanitized lessons saved from actual campaign decisions.
- Audit chain: **verified**; 25 events.
- Combined chains: 0 discovered. This is reported as observed; no synthetic chain was fabricated.

### Juice Shop regression

- Target: local authorized Juice Shop on port 3000.
- Campaign: `arsenal-juice-chain-20261003-r2`.
- Routes crawled: 35.
- Candidates generated/executable: 14 / 10.
- Validation counts: 3 confirmed, 2 blocked, 0 refuted, 0 inconclusive.
- Confirmed findings: **3 access-control results** (BOLA/IDOR families).
- LLM usage: 11 calls; observed cost `$0.0450005` using the configured gpt-5-mini pricing trace.
- Learning: 9 sanitized lessons saved from actual campaign decisions.
- Audit chain: **verified**; 25 events.
- Combined chains: 0 discovered. No chain was claimed without an eligible multi-step source/result.

All live credentials remained runtime-only and were not placed in project artifacts or the final package. The live campaign artifact directories were kept outside the project package.

## 4. Security boundary conclusion

The corrected flow is:

> operator runtime credentials → M4 seal/authorize/resolve/attach → governed callback/AVI → sanitized observation → validator → ProofBundle/replay → PromotionPipeline.

The learning and chaining layers are advisory/reporting additions around this spine. They do not mint credentials, execute direct target requests, or create promotion decisions.

## 5. Remaining limitations

- The full suite is green, but the project still reports the existing 20 pinned direct-I/O gaps; they were not silently approved.
- The live campaigns produced individual promotions, but no eligible multi-step combined chain was observed in these two runs. The chain engine’s strict proof/source-input behavior is covered by focused tests rather than being claimed as a live chain promotion.
- The test suite still emits dependency/deprecation warnings that should be handled in a later maintenance sprint.
