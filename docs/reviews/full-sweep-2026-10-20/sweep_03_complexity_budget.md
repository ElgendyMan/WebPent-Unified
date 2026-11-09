# Axis 3/12 — COMPLEXITY BUDGET (is every part earning its keep?)

Question: is the codebase's size justified by behavior, and are the
recent layers proportionate to their specs? Depths: (a) file/module
sizes, (b) abstraction count vs behavior, (c) dead-weight check.

## Shallow (sizes)

The recent layers are proportionate: forge 20 modules / 2,919 LOC,
deep 16 / 3,008, campaign 2,853, prism 3,171. No single module is an
outlier (largest recent files stay in the low hundreds of lines).
The heavyweight mass of the tree (shared 48k, agents 32k) predates
this review's scope and was audited in earlier rounds.

## Medium (abstractions per behavior)

The recent layers use frozen dataclasses + plain functions; no
metaclass, no plugin registry, no event bus introduced. Every
converter in deep/bridge.py and forge/integration.py maps one
documented input type to one documented output type — abstraction
count matches behavior count. The campaign storage layer (CampaignStore)
is reused by CampaignMemory rather than duplicated — the right
reuse.

## Deep (dead weight)

One candidate: forge/payload_dashboard.py and payload_cli.py are
thin surfaces over the corpus that no other package consumes; they
earn their keep as the operator's inspection surface (FORGE spec's
U-FORGE-16/17), verified by their own test files. Nothing found that
exists with no consumer and no spec mandate.

## Verdict for this axis

No findings. Complexity budget respected.
