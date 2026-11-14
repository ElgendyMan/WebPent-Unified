# EGAIE 11 — Real-HTTP Benchmark Results (v0.13.0)

Date: 2026-10-21. Ground truth: `http-v1` (6 cases). Transport:
`action_executor` (the production path; no raw HTTP execution exists in
the experiment port). Results below are from an actual run of
`run_http_comparison(target, max_rounds=14, repetitions=3)` against the
controlled loopback target, recorded verbatim.

## What was actually measured

Adaptive loop (InformationGainSelector + FollowUpProposer) vs fixed-order
baseline, same target version, same request budget (200 actions), same
CausalGuard validation and sealed-bundle replay for both.

| metric | adaptive | baseline |
|---|---|---|
| confirmed | 4 / 4 positives | 3 / 4 |
| recall | 1.0 | 0.75 |
| false positives | 0 | 0 |
| requests made | 21 | 18 |
| requests per confirmed | 5.25 | 6.0 |
| replay-valid confirmations | 4 of 4 | 3 of 3 |
| terminal reason | objectives_complete | round_budget_exhausted |

Per-case (adaptive): pos-idor-1 confirmed, pos-bola-1 confirmed,
pos-authbypass-1 confirmed, neg-record-1 clean, neg-file-1 clean, and
pos-multi-1 confirmed via its stage-2 follow-up (its stage-1 experiment
stays honestly marked inconclusive; the confirmation belongs to
`e-pos-multi-1-stage2` under the same hypothesis).

## Thresholds (declared before evaluation, docs/egaie/10)

recall >= 0.6: pass (1.0). False positives == 0: pass (both loops).
Every confirmed finding replay-valid: pass (4/4, 3/3). Adaptive
confirmations > baseline at identical budgets: pass (4 > 3). Reproducible
across 3 repeated adaptive runs: pass (identical confirmed sets).
Interrupt/resume: pass (confirmed set only grows after reload; no
repetition of completed work). Overall: thresholds_pass = true.

## What the multi-step case proves

pos-multi-1's archive response deliberately carries no resource-owner
context, so a single observation cannot distinguish defect from policy.
The adaptive loop's proposer emitted a stage-2 experiment against the
stored note path revealed in the stage-1 body, compared it against the
attacker's own note as baseline and the enforced control route, and
CausalGuard confirmed only after the full triple satisfied the
authorization-mismatch contract, with a sealed, replay-valid bundle.
The baseline loop ran out of round budget before following up.

## Proof-contract integrity

Every bundle records `runtime_provenance =
{"mode": "controlled_local_http_target", "offline": False,
"transport": "action_executor"}` — the bundle says exactly what
happened. Every bundle-verification outcome (pass or fail) is persisted
in `InvestigationState.proof_bundles_verified` before the replay gate,
so a failed or inconclusive proof is visible in state and can never be
silently converted into a confirmation to improve scores.

## What remains unqualified (honest scope)

Do not read this milestone as "WebPent is an Ultimate Autonomous Bug
Hunter." What the real-HTTP evidence establishes: the existing EGAIE
architecture executes through the production authorized path, detects
IDOR/BOLA/auth-bypass/multi-step-stored-input defects over real HTTP,
refrains from confirming enforced controls, and beats a fixed baseline
at equal budgets on this target. What it does not establish:

1. **Surface breadth.** Six hand-built routes on one synthetic loopback
   app. No CMS, no framework, no real-world response diversity, no
   JavaScript rendering, no sessions/cookies/JWT, no POST mutations.
2. **Discovery.** The paths probed were given by versioned ground truth.
   Nothing here qualifies autonomous path discovery, crawling, or
   parameter mining; the loop selects among seeded experiments.
3. **Families.** Three authorization families only. No injection,
   SSRF, access-control across tenants/roles beyond owner checks, no
   business-logic defects.
4. **Adversarial targets.** The target never rate-limits, never returns
   ambiguous errors, never mutates state (all routes are GET).
5. **Scale and time.** 21 requests in ~0.5 s. No long-horizon
   engagement, no partial-progress economics under tight budgets.

Next milestone candidates (not started): ground-truth v2 with sessions
and state mutation, seeded-but-earned paths (discovery from a single
root URL), and a second family set.

## Regression status

Full suite: 4,379 passed (baseline 4,369 + 10 new HTTP tests; monotonic).
Construction-authority gate: PASS. Seals d10783ec422b... and
30fd86c61156...: unchanged. Direct-I/O inventory: deliberately
regenerated (+2 approved safe_boundary_call records, reviewed diff).
