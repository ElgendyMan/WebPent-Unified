# Logic Breaker L0-L3 — Price Integrity Results (http-v3)

Date: 2026-10-22. Baseline: WebPent v0.14.0. This document records the
first complete Logic Breaker capability on EGAIE: family
`PRICE_INTEGRITY`, ground-truth version `http-v3`, against the
controlled loopback target. Advisory only: nothing here is submitted
anywhere, and no live network was used from the core.

## What was delivered (L0→L3, one commit each)

- **L0 (`tests/egaie/test_logic_price_integrity.py`, 11 tests):** the
  red-first mission contract — deterministic pricing routes, generic
  coupon receipt, fail-closed SAFE_SMART writes, invariant-oracle
  verdict discipline, sealed-bundle tamper/identity rejection,
  resume-without-double-apply, benchmark thresholds, finding bridge.
- **L1 (target + ground truth):** `http_target.py` price-integrity
  surface (defective checkout with client-controlled price, enforcing
  till sibling, defective cross-owner multi-step coupon with a generic
  receipt, order observation GET, `/control` routes, server-authoritative
  price exposed on invoices), `http_ground_truth.py`
  `HTTP_GROUND_TRUTH_V3` (4 cases: pos-price-1, pos-coupon-1,
  neg-till-1, neg-coupon-1 — 2 multi-step), direct-I/O inventory
  regenerated with a reviewable diff (line shifts only, no new
  transport sites).
- **L2 (`logic_port.py`):** `LogicExperimentPort` (subclass of the
  production `HTTPExperimentPort`: only the http-v3 case mapping and
  documented per-case probe parameters are new; execution rides the
  inherited RuntimeFactory ActionAuthority + G-02 smart_http adapter
  path unchanged), `InvariantValidationPort` (documented predicates
  `amount_mismatch` and `unauthorized_discount`; fail-closed verdicts),
  `LogicProofBundlePort` + `LogicProofBundle` (seal covers identity,
  case, evidence digests and verdict; verify reloads the recorded
  observations, independently re-runs the same oracle, and compares
  verdict, digests, seal and target identity — replay never re-issues
  HTTP), `LogicFollowUpProposer` (advisory, polarity-blind stage-2),
  deterministic per-task idempotency tokens, and version-aware runner
  wiring (v1/v2 keep the CausalGuard path untouched).
- **L3 (`finding_bridge.py`):** `logic_findings_from_state` promotes
  only replay-valid sealed confirmed results to `Finding`
  (vuln_class `UNKNOWN` = explicit business-logic/price-integrity
  typing, never `auth_bypass`, after the L4 finding-semantics audit;
  severity high, url = the controlled target); invalid-bundle /
  invalid-replay / inconclusive / blocked results are rejected.
  `findings.py` untouched.

## Verbatim benchmark output (`scripts/logic_benchmark_snapshot.py`)

```text
{
  "adaptive": {
    "confirmed_case_ids": [
      "pos-coupon-1",
      "pos-price-1"
    ],
    "confirmed_count": 2,
    "false_positive_case_ids": [],
    "false_positives": 0,
    "ground_truth_version": "http-v3",
    "per_case": {
      "neg-coupon-1": "inconclusive",
      "neg-till-1": "clean",
      "pos-coupon-1": "inconclusive",
      "pos-price-1": "confirmed"
    },
    "recall": 1.0,
    "replay_valid_confirmed": 2,
    "requests_made": 18,
    "requests_per_confirmed": 9.0,
    "terminal_reason": "objectives_complete",
    "transport": "action_executor",
    "wall_time_s": 0.3042
  },
  "baseline": {
    "confirmed_case_ids": [
      "pos-price-1"
    ],
    "confirmed_count": 1,
    "false_positive_case_ids": [],
    "false_positives": 0,
    "ground_truth_version": "http-v3",
    "per_case": {
      "neg-coupon-1": "inconclusive",
      "neg-till-1": "clean",
      "pos-coupon-1": "inconclusive",
      "pos-price-1": "confirmed"
    },
    "recall": 0.5,
    "replay_valid_confirmed": 1,
    "requests_made": 12,
    "requests_per_confirmed": 12.0,
    "terminal_reason": "round_budget_exhausted",
    "transport": "action_executor",
    "wall_time_s": 0.1445
  },
  "ground_truth_version": "http-v3",
  "reproducible": true,
  "resume_correct": true,
  "thresholds": {
    "comparison": "adaptive confirmations > fixed-order baseline under identical budgets and validation",
    "max_false_positives": 0,
    "min_recall": 0.6,
    "replay_valid": "every confirmed finding must pass sealed-bundle replay"
  },
  "thresholds_pass": true
}
CONFUSION_MATRIX
{
  "false_negatives": [],
  "false_positives": [],
  "true_negatives": [
    "neg-coupon-1",
    "neg-till-1"
  ],
  "true_positives": [
    "pos-coupon-1",
    "pos-price-1"
```

## Confusion matrix (adaptive loop, ground-truth polarity)

|                 | confirmed | not confirmed |
|-----------------|-----------|---------------|
| positive (pos-) | 2 (pos-coupon-1, pos-price-1) | 0 |
| negative (neg-) | 0 | 2 (neg-coupon-1, neg-till-1) |

True positives 2, false positives 0, false negatives 0, true negatives
2. Recall 1.0 against the fixed-order baseline's 0.5, with 9.0
requests per confirmed finding (baseline 12.0). Every confirmed
finding carries a replay-valid sealed bundle (`replay_valid_confirmed`
== `confirmed_count` == 2).

## Verification battery (before → after)

- `/usr/bin/python3 -m pytest tests/`: **4388 → 4399 passed, 0 failed**
  (4388 baseline + 11 new Logic Breaker tests; suite count monotonic).
- `ruff check` on all new/changed files: clean.
- `scripts/check_orchestrator_construction_authority.py`: exit 0.
- Frozen-manifest seals: unmoved (modern_spine.py
  d10783ec422b…, profile.py 30fd86c61156…; no touch points used).
- Zero `getattr`/`hasattr` and zero broad `except Exception` in the
  new modules (`logic_port.py`, `finding_bridge.py`).
- Direct-I/O inventory: regenerated via
  `scripts/regenerate_direct_io_inventory.py` (reviewable diff, line
  shifts only).

## What works / what remains blocked / what is untested

**Works (proven by the battery above):** the full loop on the
controlled target — active-mode execution through the production
ActionExecutor path, fail-closed denial in SAFE_SMART, independent
invariant-oracle confirmation, sealed replay-valid bundles, tamper and
identity rejection, resume without double-applied mutations,
reproducible adaptive-vs-baseline benchmark with 0 false positives,
and finding promotion restricted to replay-valid confirmed results.

**Blocked by design (not defects):** the invariant oracle is
family-specific (`PRICE_INTEGRITY`); logic verdicts are not
authorization verdicts and are never relabelled through CausalGuard —
they run in their own proof contract; nothing is auto-exploited or
submitted anywhere.

**Untested against live targets:** everything here is fixture-local
(loopback, deterministic routes, no sessions, no JS, no WAF). Real
price-integrity testing on an authorized production target requires
written engagement authorization and its own qualification; the
ground-truth-seeded paths also mean no autonomous path discovery is
exercised.
