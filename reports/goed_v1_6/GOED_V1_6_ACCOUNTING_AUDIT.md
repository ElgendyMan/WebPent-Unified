# GOED v1.6 — Phase 1: Canonical Accounting Audit
**Date:** 2026-09-03T07:04:29.564377+00:00

## Canonical States (Mutually Exclusive)

| State | Count |
|-------|-------|
| EXECUTED_CONFIRMED | 37 |
| EXECUTED_CLEAN | 45 |
| EXECUTED_INCONCLUSIVE | 28 |
| BLOCKED | 10 |
| ERROR | 0 |

**Invariant 1:** sum(canonical) = 120 == total_cases = 120 → ✅ PASS

## Confusion Matrix (from eligible scored cases)

| Label | Count |
|-------|-------|
| TP | 0 |
| FP | 0 |
| FN | 0 |
| TN | 20 |

## Dimension Separation

Each case has:
- **canonical_state** (EXCLUSIVE: exactly one per case)
- **scoring_label** (SEPARATE: TP/FP/FN/TN/UNCLASSIFIED)
- **proof_valid** (SEPARATE: boolean)
- **replay_valid** (SEPARATE: boolean)
- **discovery_success** (SEPARATE: boolean)

INCONCLUSIVE cases that are vulnerable are scored as FN. This is EXPLICIT and SEPARATE from the canonical execution state. No case is "simultaneously FN and INCONCLUSIVE and BLOCKED" in the same dimension.
