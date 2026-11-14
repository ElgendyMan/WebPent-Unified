# VIP Autonomous Vertical Slice v1 — Architecture and Design

## Purpose

This vertical slice provides a bounded, transport-agnostic campaign orchestrator for authorized local loopback work. It is designed to improve the product’s autonomous lifecycle without opening Official P10, Bug Bounty, external targets, credentials, state mutation, or qualification claims.

The implementation is centered in `src/webpent/shared/vip_vertical_slice.py`. Target-specific behavior is injected through `TargetSpec`, capability/readiness providers, and an observation handler. The core does not perform HTTP or browser navigation itself; callers provide a bounded handler, while `ActionAuthority` and `CampaignExecutor` remain the execution boundary.

## Layer boundaries

| Layer | Responsibility | Explicit non-responsibilities |
|---|---|---|
| `TargetSpec` | Canonical loopback origin, scope, read-only method policy, budget, redirect policy, expiry, authorization reference | Credentials, wildcard origins, external scope, mutation |
| `CaseContract` | Causal predicate, safe preconditions, capability, proof and negative-control contract | Hostname-driven case selection, route reachability as proof |
| `VIPAutonomousVerticalSlice` | Ordered lifecycle, selection, baseline/candidate/control, central oracle, improvement cycle, report | Autonomous escalation, qualification, official-run authorization |
| `ActionAuthority` | Central authorization and budget/idempotency enforcement | Bypass by LLM, RAG, adapter, or handler |
| `CampaignExecutor` | Executes authorized bounded tasks and records redacted metadata | Raw body/header/cookie persistence |
| Central verifier | Requires baseline, causal semantic match, and independent negative control | HTTP 200/source presence/route reachability as confirmation |
| `ProofBundle` | Common build, seal, verify-seal, replay, and promotion-readiness semantics | Hand-built adapter proof |
| Owner Decision Packet | Describes gated changes and approval request without granting approval | Silent approval or human-signoff fabrication |

## Safety posture

Every campaign starts with `TargetSpec.validate()`. The current implementation requires a valid HTTP(S) loopback origin, rejects embedded credentials and wildcard origins, restricts methods to `GET`, `HEAD`, or `OPTIONS`, bounds the request budget, requires a fail-closed redirect policy, requires an authorization reference, and requires a future expiry.

Each task is constructed with anonymous identity context, read-only risk, no-mutation cleanup, metadata-only rollback, a bounded probe family, and the central verifier identifier. The report explicitly records that no credentials, raw bodies, raw headers, payloads, external contact, or state mutation were used.

## Proof and confirmation semantics

A case is `confirmed` only when all of the following hold:

1. The baseline observation has the expected baseline role.
2. The candidate or retest observation matches the contract’s causal predicate and semantic match.
3. The candidate semantic oracle is ready.
4. The independent negative control is complete and does not match.
5. The central verifier accepts the result.
6. The common `ProofBundle` seals, verifies, replays, and is promotion-ready.

An ordinary Juice Shop GET observation is deliberately non-scoring when it lacks a causal vulnerability predicate. It remains `inconclusive` or `observation_only` at the target profile level and does not become TP, FP, FN, or a scoring case.

## Self-improvement semantics

For a non-confirmed case, the orchestrator records diagnosis, creates an improvement proposal, classifies the change as target-local or generic-candidate-requires-review, and then applies the following rules:

- A target-local safe change may be injected only through the explicitly supplied `safe_change_handler`.
- A successful regression is required before same-condition retest.
- The retest uses the same target, baseline, negative control, contract, and bounded execution path.
- A new proof is built only from the retest evidence and must pass the same seal/replay/promotion checks.
- Before/after comparison is always recorded.
- `scoring_promotion` is always `false`; this vertical slice never modifies the approved scoring set.
- A generic or non-local change produces a pending Owner Decision Packet and remains blocked.

## Explicit governance invariants

The generated reports and tests preserve these values:

```text
official_isolated_p10_runs_authorized = false
human_independent_signoff_obtained = false
P10 = NOT_QUALIFIED
P9 = NOT_QUALIFIED
VIP = NOT_QUALIFIED
Bug Bounty = BLOCKED
scoring_promotion = false
```

This is an implementation and evidence artifact for the local vertical slice. It is not an Official P10 run, a qualification decision, or a human independent review.

## Rollback

Rollback is isolated and reversible: revert the vertical-slice commit(s), remove the generated local campaign artifact, and leave frozen Ground Truth, governance packet, approved scoring set, Generic Core contracts, and official-run gates unchanged.

## Source files

- `src/webpent/shared/vip_vertical_slice.py`
- `scripts/run_vip_vertical_slice_local.py`
- `tests/test_vip_vertical_slice.py`
- `reports/evaluation/vip_vertical_slice/VIP-AUTONOMOUS-VERTICAL-SLICE-LOCAL-E2E-v1.json`

The local runner uses a deterministic fixture path for the full proof/improvement lifecycle and a passive GET-only Juice Shop path for loopback validation. No raw response content is persisted.

_End of architecture/design record._

# Quranic principle

> **"وَلَا تَعْتَدُوا ۚ إِنَّ اللَّهَ لَا يُحِبُّ الْمُعْتَدِينَ"** — البقرة: 190

The engineering equivalent here is strict scope control: do not cross authorization or safety boundaries merely to increase coverage numbers.
