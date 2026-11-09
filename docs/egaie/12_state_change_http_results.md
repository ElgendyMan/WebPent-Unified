# EGAIE 12 — State-Changing HTTP Results (v0.14.0)

Date: 2026-10-22. Ground truth: `http-v2` (4 cases, POST families).
Transport: `action_executor` (the production path; every mutating
request travels as a CampaignTask through RuntimeFactory-built
ActionAuthority + ActionExecutor with the G-02 smart_http adapter).
Results below are from an actual run of
`run_http_comparison(target, max_rounds=14, repetitions=2,
cases=HTTP_GROUND_TRUTH_V2)` against the controlled loopback target,
recorded verbatim.

## What was actually measured

The v2 ground truth adds state-changing (POST) probes on the same
controlled target: a defective payment route that applies a cross-owner
payment (mutating IDOR), its enforced wire sibling, and a multi-step
charge route whose generic receipt carries no ownership context so a
single observation cannot confirm the defect — the effect is only
observable through a follow-up GET on the invoice resource. Every POST
runs under the production contract for active actions:
`ScanMode.AUTHORIZED_ACTIVE` plus explicit per-task human approval
(`human_approved` metadata), family `form_submit`, risk tier `ACTIVE`,
capability `http_write` declared in the port manifest. Without that
mode or approval the authority denies the write fail-closed and the
target state is provably unchanged.

| metric | adaptive | baseline |
|---|---|---|
| confirmed | 2 / 2 positives | 1 / 2 |
| recall | 1.0 | 0.5 |
| false positives | 0 | 0 |
| requests made | 18 | 12 |
| requests per confirmed | 9.0 | 12.0 |
| replay-valid confirmations | 2 of 2 | 1 of 1 |
| terminal reason | objectives_complete | round_budget_exhausted |

Per-case (adaptive): pos-mutid-1 confirmed, neg-mutid-1 clean,
neg-mutmulti-1 clean via its stage-2 follow-up, and pos-mutmulti-1
confirmed via its stage-2 follow-up (its stage-1 experiment stays
honestly marked inconclusive; the confirmation belongs to
`e-pos-mutmulti-1-stage2` under the same hypothesis). The strict
comparison threshold holds because the baseline loop has no follow-up
proposer and runs out of round budget before resolving the multi-step
mutation cases — the same structural advantage v0.13.0 demonstrated on
read-only families, now on state-changing ones.

## Application-level idempotency (resume safety)

Mutating probes are non-idempotent by nature, so the target applies
each mutation at most once per (family, resource, idempotency-token)
key, and the port derives the token deterministically from the task
key (sha256[:16]). A resumed or replayed investigation re-emits the
same token and therefore can never double-apply a completed mutation.
The resume test proves it: interrupt mid-run, persist, reload, resume —
`applied_count_for_family("payment", "inv-1") == 1` and
`applied_count_for_family("charge", "inv-1") == 1` after the full
resumed investigation. GET-side effects remain observable through real
follow-up GETs (the invoice body carries `paid`).

## Fail-closed denial without active authorization

Under `ScanMode.SAFE_SMART` (the port's read-only posture), the
authority denies every POST before any handler runs:
`production_actions == 0`, `denied_actions >= 1`, all three
observations are placeholders with `status_code is None`, and a
follow-up GET proves the victim invoice was never paid. The write
capability exists in the manifest but is unusable outside the
production active-action contract.

## Thresholds (declared before evaluation, docs/egaie/10)

recall >= 0.6: pass (1.0). False positives == 0: pass (both loops).
Every confirmed finding replay-valid: pass (2/2, 1/1). Adaptive
confirmations > baseline at identical budgets: pass (2 > 1).
Reproducible across repeated adaptive runs: pass (identical confirmed
sets). Interrupt/resume: pass (confirmed set only grows after reload;
no mutation applied twice). Overall: thresholds_pass = true. Ground
truth version `http-v2` is reported on the run itself and results are
never pooled with `http-v1`.

## Proof-contract integrity

Every bundle records `runtime_provenance =
{"mode": "controlled_local_http_target", "offline": False,
"transport": "action_executor"}` — the bundle says exactly what
happened, including for state-changing requests. Bundle verification
outcomes are persisted before the replay gate, so a failed or
inconclusive proof can never be silently converted into a confirmation.

## Honest scope of this result

Same controlled-target limits as EGAIE 11: the target is deliberately
built with the defects, paths are pre-known to the benchmark fixture,
one mutation defect family (cross-owner payment/charge with an enforced
wire/control sibling) on a loopback app, no live third-party target
evidence. What v0.14.0 adds is the write path itself: authorization
gated, idempotency-safe, replay-valid state-changing probing through
the production ActionExecutor, with the adaptive-vs-baseline comparison
repeated on it.
