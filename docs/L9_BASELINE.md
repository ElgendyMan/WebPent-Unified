# L9 Baseline — L8 release reproduction (§1)

Everything in L9 is measured against the L8 release state, reproduced
at the start of this mission.

## Release verification

Commit `48eb45b` (`docs: L8 release manifest and final gate log`),
ZIP `webpent_l8.zip` SHA-256
`435c0e32e2b6a0ff1a2c78139c8a912b43b4026ac8584594ab94fceb34650734`
verified against the published digest at session start.

## Baseline gate

Full `make ci` at `adc6a39` (the L8 release commit plus the L9 plan
document; no code changed): **4491 passed, coverage 61.64% (floor
35%), lint all checks passed, Bandit high-severity clean, GATE_OK**
(both authority gates). Log:
`docs/l9_gate_logs/gate_baseline_adc6a39_20261026T171521Z.log`.

## Discovery-matrix reproduction

`scripts/l8_discovery_matrix.py` re-run for both blocks at the
baseline state (before any L9 code):

- DEV block: 160 runs regenerated, `docs/l8_discovery_dev.json`
  compared field-by-field against the committed L8 artifact — every
  field outside wall-clock seconds identical (0 differing fields).
- HELD-OUT block: 160 runs regenerated, `docs/
  l8_discovery_heldout.json` — identical (0 differing fields).

The reproduced artifacts were byte-identical outside wall-clock and
were restored to the committed versions; nothing in L9 uses the
re-run outputs for tuning.

## Exact held-out result (recorded once, never tuned against)

L8 held-out block (ticketflow, slots), budget-matched unique
TP/FP/FN summed over the 4 instances, all four strategies:

| budget | adaptive | indep-fixed | adapt-no-sel | obs-baseline |
|---|---|---|---|---|
| 2, 4, 8, 16, 32 (identical) | 2/0/4 | 2/0/4 | 2/0/4 | 2/0/4 |

Observation-baseline matched adaptive at lower cost (req/TP 54 vs
98): no adaptive advantage on held-out. The WORKFLOW_IDENTITY
false-negative mechanism (identity checked before order; the probe
never drives the required source state; the 409 from the edge table
reads as enforcement) is documented in
`docs/L8_FAILURE_ANALYSIS.md` and becomes the L9 §4 development
case on a NEW dev application — the L8 held-out set itself is never
used for L9 implementation or tuning, and its instances are excluded
from the fresh L9 held-out block.
