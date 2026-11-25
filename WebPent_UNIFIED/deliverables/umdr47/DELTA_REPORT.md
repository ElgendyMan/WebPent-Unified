# UM-DR-47 — DELTA REPORT (47 wired vs 46 baseline)

> Generated from MEASUREMENT_METRICS.json — every number is
> computed by code from the machine records, never hand-written.

## What changed

The 46 baseline ran the identical six-family battery with the
brain engine OFF (advisory-only). The 47 measurement ran the
same battery with the wiring ACTIVE. Same labs, same ground
truth, same entrypoint, same attribution rules.

| Metric | 46 baseline | 47 measured | delta |
|---|---|---|---|
| campaigns_total | 36 | 36 | 0 |
| campaigns_completed | 36 | 36 | 0 |
| tp | 6 | 6 | 0 |
| fp | 0 | 0 | 0 |
| fn | 18 | 18 | 0 |
| declared_defects_total | 7 | 7 | 0 |
| precision | 1.0 | 1.0 | 0.0 |
| recall | 0.25 | 0.25 | 0.0 |
| replay_success_pct | 100.0 | 100.0 | 0.0 |

## Reading the delta honestly

- Precision 100.0% and recall 25.0% are the
  47 numbers against the declared ground truth.
- The wiring counters: 24/36 campaigns had W4 coverage-gap
  research tasks in the live pool; 180 W4
  tasks and 0 W5 chain steps total.
- A delta of 0 on a metric is reported as 0 (parity is a fact,
  not a failure — but by law 47-3 parity is NOT proof; the
  behavioral difference evidence is the WIRING_PROOF gate).
