# Claim Validation Report

The audit reviewed the current README, IRTA report, RTA/DCVU reports, metrics, and research-core documentation. Claims are classified by evidence level rather than by implementation intent.

| Claim | Level | Evidence | Audit decision |
|---|---|---|---|
| The repository has a deterministic IRTA target generator | A — Proven | Source, 4 generator tests, reproducible seeded output | Retain |
| The repository has adversarial auth/response mutation contracts | A — Proven | Source, mutation tests, immutable/fail-closed checks | Retain with contract scope |
| The bounded research loop exists | A — Proven | Source, focused tests, deterministic stage plan | Retain as bounded facade |
| Negative evidence cannot silently become a finding | A — Proven | `CleanReasonBundle` tests and conservative scoring | Retain |
| Stateful approval/payment/coupon fixture exists | A — Proven | Source and workflow role/invariant tests | Retain as disposable fixture |
| IRTA benchmark covers 10 targets and 4 tiers | A — Proven | Benchmark builder, 10-seed test, metrics artifact | Retain as planned benchmark capacity |
| IRTA proves live detection quality across 10 targets | C — Unsupported | No live candidate/control observations or independent proof bundles | Downgrade to future work |
| Memory learning improves future detection | B — Implemented but not proven | Recall-delta measurement primitive; no longitudinal detector experiment | Label as unverified |
| RTA proves local lifecycle portability | A — Proven within scope | RTA report, real local HTTP harness, regression | Keep bounded wording |
| WebPent is VIP Smart Autonomous Bug Hunter | C — Unsupported | Governance and official-quality gates remain closed | Keep only as project goal; not a current capability claim |
| ProofBundle replay is universally proven | B — Implemented but not case-universally proven | Generic contracts and historical artifacts exist; accepted case-specific replay is incomplete | Downgrade to partial |
| External/bug-bounty readiness | C — Unsupported | No authorized external execution and gate remains closed | Do not claim |

No historical artifact was deleted. Unsupported claims are explicitly downgraded or marked as future work.
