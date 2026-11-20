# Axis 2/12 — REDUNDANCY (what is built twice?)

Question: which functionality exists in more than one place, and is
each duplicate justified? Depths: (a) module inventory, (b) behavioral
overlap, (c) consolidation cost.

## Shallow (inventory)

Dashboard renderers: 8 (oracle, prism, econ, apex, jc,
remediation/priority, forge/payload, campaign/warroom). CLI surfaces:
forge/payload_cli, campaign/warroom/cli, plus the top-level cli/
package. SQLite indexers: forge/indexer.py and forge/outcome_tracker.py
both own their own SQLite files with their own schema and idempotent
writers.

## Medium (behavioral overlap)

The eight dashboards are not behavioral duplicates: each renders a
different artifact (brief, ledger, priority list, payload corpus,
econ ledger). They are *pattern* duplicates — every one is a
render-to-text class with the same shape and the same test style.
Consolidating them would mean cross-package churn for zero behavioral
gain; the duplication is in idiom, not logic. → documented, not a
defect (**F-05 LOW**).

forge/indexer.py vs forge/outcome_tracker.py: the indexer stores
per-payload outcomes (success-rate arithmetic), the outcome tracker
stores per-phase/campaign outcome records. Overlapping mission
(payload effectiveness history), different granularity and different
files. The overlap is real but shallow; merging them would touch the
FORGE core mid-review. → documented in the plan as a candidate, not
executed (part of **F-05**).

## Deep (consolidation cost)

Any consolidation crosses package boundaries (oracle/prism/econ/apex/jc
are separate layers with their own laws). Cost: high. Benefit: idiom
uniformity only. Verdict: keep; record in the roadmap under "idiom
alignment" if a future round touches these files anyway.

## Verdict for this axis

One LOW finding (F-05), documented rather than fixed: no behavioral
duplication found.
