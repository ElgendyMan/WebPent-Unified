# UM-DR-40 — Engineering Design (Research & Discovery Intelligence Evolution)

Generated 2026-11-18 — mission branch from published main `ca4ae448`.
Statuses are per-item and honest: what is implemented in this window
is marked IMPLEMENTED with its tests and evidence; what is designed
but not implemented is marked DESIGNED_NOT_IMPLEMENTED and carries
its acceptance criteria for the next window.

## Scope decision for this window

The 39 register's RC-4 and RC-5 are the two follow-ups whose value
survives every alternative trajectory: RC-4 lights up an already
complete, already tested identity-reasoning stack (the highest
ratio of capability-per-risk in the register), and RC-5 removes a
pool-hygiene defect that every other research improvement would
otherwise sit on top of. RC-6/RC-7 (measured information gain,
experiment alternatives) are research-loop economics changes that
deserve their own window with their own before/after campaigns;
RC-8..RC-10 are assessments/consolidations whose honest first step
is the audit below.

## RC-4 — Identity-aware research activation: IMPLEMENTED

### The three defects (from the 39 register, re-verified on this
branch)

1. **The router bypass**: `_research_route_redirects` (the composed
   UM-DR-31/32 advisory redirect) existed but was never invoked by
   graph construction — the hypothesis router's `HYPOTHESIS_PATH_MAP`
   was passed raw, so strategist-bound branches could never reach the
   identity_workflow node, regardless of flags.
2. **Dark by default**: the four capability flags
   (`enable_object_identity`, `enable_alias_resolution`,
   `enable_multi_identity_reasoning`, `enable_composite_workflows`)
   are fail-closed OFF, and enabling them is a product decision, not
   a wiring bug.
3. **No per-campaign mechanism**: nothing recorded what a campaign
   ran with, or what enabling the stack cost.

### The design

* **Wiring fix** (builder.py, the ruling-authorized delta file):
  the router's path map now flows through
  `_research_route_redirects`. Flags OFF → the mapping is returned
  byte-identically (default graph shape unchanged — pinned by
  contract tests). Any flag ON → strategist-bound branches run
  `identity_workflow` first, which forwards to research-loop /
  strategist exactly as before.
* **Per-campaign activation** (production/identity_activation.py,
  NEW): `identity_campaign_activation` — a reversible context
  manager over the four flags (environment + settings-cache clear on
  entry and exit; restoration even on exceptions; unknown
  capabilities rejected fail-closed). `activation_snapshot` records
  the run's provenance; `budget_impact_record` derives the measured
  request/time/finding deltas and the identity counts from the
  campaign records' own vocabulary.
* **The proof** (scripts/umdr40_identity_campaigns.py, NEW): the
  SAME production entrypoint (`run_campaign` →
  `run_unified_hunt`, identical lab, identical configuration) twice
  per arm — baseline (all OFF) vs enabled (all ON) — emitting the
  RC-4 verdict: identity output > 0 from the registered node in the
  enabled arm, identity channels empty in the baseline, guard
  verdicts unchanged (advisory-only contract).

### Why the activation is a context manager and not a new flag

A fifth "master" flag would fork the settings surface and invite
drift with the four documented capabilities. The context manager
composes with the existing fail-closed flags, is scoped to exactly
one campaign, and leaves the shipped default untouched.

## RC-5 — Generation-time semantic hypothesis dedup: IMPLEMENTED

### The defect (39 register RC-5, re-verified)

Per-batch generation compared `(url, vuln_class)` TEXTUALLY; the
state reducer `merge_hypotheses` upserts by `id`; every generation
site produced a fresh random `uuid4` — so identical content
re-entered the pool as a NEW id on every pass. The semantic
fingerprint existed but only behind the adaptive-research flag.

### The design (and the frozen-gate constraint)

The frozen-modules regime (719 pinned files, byte-identity gate)
pins `models/hypothesis.py` (the model), `agents/hypothesis_analyzer/
agent.py` (the generator) and `state/reducers.py` (the reducer). The
window's authorized delta file is `graph/builder.py` — exactly where
node registration happens. Therefore:

* NEW `production/hypothesis_dedup.py`: `hypothesis_content_
  fingerprint` (deterministic sha256 over canonical normalized
  (target URL, vuln class) — the exact semantic pair the generator's
  own per-batch check compared) and `deterministic_hypothesis_id`
  (uuid5, the workflow-understanding convention).
* `builder.py` registers `deduplicated_hypothesis_node`: the wrapper
  runs the untouched generator, then replaces the emitted
  hypotheses' random ids with their deterministic content ids —
  fingerprinting at GENERATION time, boundary-enforced.
* The existing (frozen, already-correct) upsert-by-id reducer then
  absorbs cross-pass re-entries with no reducer change.

Fingerprint scope note: it covers exactly (normalized URL, vuln
class). A different class or target always differs (security-
relevant differences never merge); richer fields (principals,
preconditions) are the adaptive-research fingerprint's job and stay
flag-gated there.

## RC-6 — Measured information gain: DESIGNED_NOT_IMPLEMENTED

Register acceptance: compute per-experiment gain from the
before/after information state (which hypotheses the experiment
distinguished; which preconditions it resolved), recorded in the
decision log with alternatives — adapted INTO the strategist, not a
parallel orchestrator.

Design sketch (for the next window): the strategist's experiment
step already sees the hypothesis pool before and after each pass;
with RC-5's deterministic ids, "which hypotheses did this experiment
distinguish" becomes a stable set-difference (resolved/abandoned/
promoted ids per experiment step) instead of a content-guess. The
decision-log record gains `information_gain: {distinguished:
[id…], resolved_preconditions: [key…], pool_before/pool_after}`
computed in-strategist; the prior-based `info_gain` weight stays as
the tie-breaker until two windows of measured data exist. Deferred:
this changes the strategist's scheduling economics and needs its own
baseline/after campaigns to be honest about.

## RC-7 — Experiment alternatives: DESIGNED_NOT_IMPLEMENTED

Register acceptance: the decision log records the alternatives
considered per experiment decision. Design sketch: the strategist's
candidate ranking already enumerates alternatives internally; the
change is to record the top-K alternatives with their scores at the
moment of choice (bounded, no new network calls). Deferred with
RC-6: the two share the decision-log schema change and the
before/after measurement.

## RC-8 — Rabbit-hole stopping: ASSESSED, PARTIALLY COVERED, REMAINS

The Prism rabbit-hole checker (`rabbit-holes-check`, the hole-signal
anomaly types) is present and the identity layer's advisory hints
now reach the strategist through the wired path — but the
register's acceptance (a measured stop-decision at a measured cost
threshold, demonstrated in a campaign) is not implemented in this
window. Status: REMAINS_OPEN, no claim of coverage.

## RC-9 — Knowledge consolidation audit: ASSESSED

The consolidation surfaces (`docs/history`, the dated archives, the
mission lifecycle register from the repository-rationalization
phase) now have a machine-readable index (REPOSITORY_INVENTORY +
MISSION_LIFECYCLE). The register's deeper ask — consolidating
LEARNING artifacts (lessons/prisms) into a single queryable surface
— is a data-modeling change on the learning subsystem; deferred
with its own acceptance criteria (single consolidated view, zero
loss, per-mission provenance preserved).

## RC-10 — Autonomous-stack assessment: ASSESSED, NOT REOPENED

The mission charter is explicit: no expansion of autonomous
execution scope in this mission. The honest status of the stack: the
bounded-autonomy contract, the CausalGuard sole-authority rule, and
the fail-closed flags remain the controlling invariants; the RC-4
work deliberately adds REASONING (advisory) inside those invariants,
not execution. No new autonomous capability was added; none is
claimed.

## Test and gate posture

* RC-4: 7 router contract cases + 7 activation unit cases
  (incl. the wired-router integration inside the context).
* RC-5: 4 contract cases incl. the acceptance case (two
  registered-node passes; merged pool has each (url, class) once).
* Frozen gate: 650 passed, 1 ruling-authorized skip (builder.py
  delta-mode) — no frozen module is byte-modified; builder.py is
  re-pinned at window close per the refreeze convention.
* Full suite: run at the window head (see IMPLEMENTATION_LOG and the
  evidence chain).
