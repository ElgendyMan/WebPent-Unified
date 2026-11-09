# IRTA v2 — Autonomous Research Hardening Report

## Executive status

IRTA v2 was implemented as an additive local validation layer on top of the RTA v1 and Generic Core architecture. The upgrade reduces fixture overfitting by generating deterministic independent target specifications and applying adversarial auth/response mutations. It also adds a bounded research-loop facade, negative intelligence, stateful business-logic fixtures, difficulty tiers, and explicit learning measurements.

The project remains **NOT_QUALIFIED**. `official_isolated_p10_runs_authorized` remains `false`; no external target, real credential, destructive action, or qualification promotion was performed.

## What changed

| Area | Additive capability | Safety boundary |
|---|---|---|
| Independent targets | Seeded roles, tenants, identities, objects, and read-only routes | Data contracts only; no sockets or requests |
| Adversarial mutation | Empty-success denial, same-status semantic denial, permission aliases, partial disclosure | Immutable target copies; no ground-truth edits |
| Research loop | Discover → hypothesize → plan → validate → review contracts | Explicit stop conditions for missing causal evidence and scope violations |
| Negative intelligence | CleanReasonBundle and conservative suppression | Blocked/inconclusive never become FN, clean, or confirmed |
| Business logic | Disposable approval/payment/coupon workflow fixture | In-memory snapshot/restore; no HTTP or credentials |
| Benchmark | Ten-target and four-tier benchmark builder | Unexecuted cases are recorded as blocked, not scored |
| Learning | Baseline/later recall delta measurement | Reports observed scores only; no fabricated observations |

## Verification

The new IRTA suite contains 13 focused tests. It passes pytest, Ruff, and compileall. The full repository run recorded 2,270 passed and 7 pre-existing failures. The failures are retained as legacy/local-lab blockers and were not altered to improve the IRTA score.

The baseline before IRTA changes recorded 2,257 passed and 7 failures, with Ruff and compileall passing. The baseline artifacts are preserved under `reports/baseline/irta_v2_start/`.

## Metrics and interpretation

The benchmark can construct 10 independent generated targets, 4 difficulty tiers, and 160 planned case slots. Because this implementation does not fabricate live candidate/control observations, the benchmark score is `0 evaluated`, `40 blocked` at the target-tier planning level. This is the correct fail-closed result, not a detection-quality claim.

The existing RTA evidence remains historical local evidence. It is not an independent official run and does not close the governance gate. No TP/FN/precision/recall promotion is made from blocked or observation-only cases.

## What was not changed

Existing validators, frozen ground truth, qualification thresholds, official-run authorization, RTA transport boundaries, and target-specific adapters were not modified. No legacy feature was deleted. The new modules are isolated under `src/webpent/irta/` and use existing execution layers only by future composition.

## Known limitations and remaining gaps

The generated targets are executable specifications rather than live HTTP applications. A future authorized local campaign adapter must translate them into disposable loopback fixtures while retaining independent ground truth and negative controls. The mutation engine models adversarial semantics but does not yet prove live detector quality against every mutation. The full repository still has seven legacy/local-lab blockers, including WebGoat/crAPI attestation and source-inventory environment prerequisites. These remain outside the IRTA additive change set.

The project therefore does not yet satisfy the VIP evidence bar of independently validated multi-target causal quality, official isolated runs, human signoff, or external portability.

## Reproduction

```bash
cd /tmp/webpent-work
PYTHONPATH=src pytest -q tests/irta
ruff check src/webpent/irta tests/irta
python3 -m compileall -q src/webpent/irta tests/irta
PYTHONPATH=src python3 -c "from webpent.irta.metrics import IrtaBenchmark; print(IrtaBenchmark().build(tuple(range(10))))"
```

## Governance status

`NOT_QUALIFIED` remains authoritative. `official_isolated_p10_runs_authorized=false`, P10/P9/VIP remain closed, Bug Bounty remains blocked, and no Owner Decision Packet was silently bypassed.
