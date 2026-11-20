# Chaining Engine Sprint — Completion Report

**Date:** 2026-10-03  
**Workspace:** `/tmp/webpent_gap_closure_fixed/webpent`

## Executive result

The additive Chaining Engine implementation is complete and verified. It supports typed chain patterns, same-target discovery, bounded execution callbacks, M4/AVI authority integration, chain audit events, combined severity/report generation, and dashboard metrics.

The live acceptance result is intentionally **PARTIAL**: both authorized campaigns produced real promoted individual findings, but neither produced two compatible findings for one of the five declared chain patterns. Therefore the engine discovered zero eligible chains and performed zero chain executions. No Critical upgrade was fabricated.

## Implementation

The new `src/webpent/agents/chain_engine.py` defines five bounded patterns:

- `info_disclosure_to_idor`
- `idor_to_account_takeover`
- `ssrf_to_internal_access`
- `xss_to_csrf_bypass`
- `idor_to_privilege_escalation`

The engine requires promoted/confirmed inputs, same target and engagement, compatible capability metadata, and supporting evidence. It caps discovery and execution at five chains per campaign. A caller must supply the governed executor; otherwise a candidate is recorded as `chain_blocked` and cannot become reportable.

The hunter runner invokes the engine only after individual graph validation completes. Chain requests are delegated through the existing `ModernOrchestrator` and AVI callback. The engine does not perform direct HTTP, does not attach credentials, and does not change individual findings. Confirmed chains receive redacted combined reports and audit events; failed chains are `chain_refuted` or `chain_blocked`.

The product dashboard and authenticated API dashboard now expose read-only chain metrics: discovered, confirmed, and combined severity upgrades.

## Live Juice Shop campaign

Campaign: `juice-chain-20261003-r1`

| Metric | Result |
|---|---:|
| Individual confirmed findings | 3 |
| Individual blocked validations | 2 |
| Chains discovered | 0 |
| Chains confirmed | 0 |
| Combined severity upgrades | 0 |
| LLM calls | 11 |
| Observed cost | `$0.04033950` |
| Audit chain | Verified |

The individual findings were IDOR/BOLA-family findings. The declared patterns require another compatible family or capability, such as INFO_DISCLOSURE, AUTH_BYPASS, SSRF, or XSS. The engine correctly returned no eligible chain rather than treating IDOR plus BOLA as an undeclared pattern.

Campaign redaction checks found no runtime credential values, tokens, or raw target bodies in the campaign artifacts.

## Live CrAPI campaign

Campaign: `crapi-chain-20261003-r1`

| Metric | Result |
|---|---:|
| Individual confirmed findings | 2 |
| Individual blocked validations | 3 |
| Chains discovered | 0 |
| Chains confirmed | 0 |
| Combined severity upgrades | 0 |
| LLM calls | 11 |
| Observed cost | `$0.04597475` |
| Audit chain | Verified |

CrAPI supplied a real promoted BOLA finding on the workshop surface, but no second compatible finding or declared AUTH_BYPASS/INFO_DISCLOSURE prerequisite was available. The engine therefore recorded no candidate and did not execute an unsupported chain.

## Focused and regression tests

- Chain-focused, principal, graph, and dashboard tests: **31 passed**.
- Full suite: **2137 passed, 0 failed**.
- Acceptance suite: **20/20 in round 1, 20/20 in round 2, 20/20 in round 3**.
- Direct-I/O inventory contract: **4 passed**.
- Test-count gate: **2137 collected**, floor **1940**.
- Changed modules compiled successfully.

## Security gates

| Gate | Result |
|---|---|
| Frozen manifest | `13/13 OK` |
| State contract | PASS |
| Orchestrator construction authority | PASS |
| Isolation denylist | PASS; 0 violations |
| Vault import authority | PASS |
| Direct-I/O inventory | PASS |
| Test-count floor | PASS |

The frozen manifest remained unchanged. No frozen trust-spine module was modified.

## Honest acceptance assessment

| Requirement | Result |
|---|---|
| Chain patterns implemented | PASS |
| Discovery compatibility checks | PASS |
| Bounded chain execution callback | PASS |
| M4/AVI execution boundary preserved | PASS |
| Combined severity/report model | PASS |
| Dashboard chain metrics | PASS |
| Juice Shop chain confirmed | NOT MET — no eligible compatible pair observed |
| CrAPI chain confirmed | NOT MET — no eligible compatible pair observed |
| Full suite and acceptance regression | PASS |
| No fabricated chain or severity upgrade | PASS |

**Final verdict: IMPLEMENTATION PASS / LIVE CHAIN ACCEPTANCE PARTIAL.**
