# Mission L7 Implementation Plan

## Step 1 — Reproduce L6 (DONE)
- HEAD `87f00ca` verified; archive SHA-256 matches the reported digest.
- All gates re-run green; G-02 inventory regenerates clean.
- Full L6 evaluation re-run: per-instance TP/FP/FN, confirmed sets, request
  counts, and repeatability blocks all identical; only wall-clock seconds
  differ. Saved as `docs/l6_reproduction_run.json`; committed
  `docs/l6_evaluation.json` untouched.

## Step 2 — Instrument the equal-budget question
- 2a. Add `proposal_log` to InvestigationState: one entry per propose call
  ({round, experiment_ids}); serialized in to_dict/from_dict,
  backwards compatible (`.get` default). Orchestrator appends after each
  propose loop.
- 2b. New `src/webpent/egaie/benchmark/instrumentation.py`: derive a
  machine-readable trace per run (candidate pool, execution order, rounds
  used, terminal reason, budget binding, duplicate signatures, outcome
  tally) and pairwise strategy comparison (executed-set overlap, order
  divergence).
- 2c. Red-first tests: proposal_log populated and round-tagged; adaptive
  and fixed share one candidate pool and one executed set at non-binding
  budget; ablation produces an empty pool and zero executed rounds.
- Deliverable §2: the tie is structural — same proposer, same pool,
  order-independent outcomes, non-binding budget; the ablation disables ALL
  candidate generation (proposer=None → zero pending → immediate
  objectives_complete), so it is an invalid baseline, not a fair one.

## Step 3 — Independent lab corpus (`src/webpent/labsuite/`)
No reuse of `eval_instances` generation logic; own loopback HTTP plumbing;
labels and evaluator live in `labsuite`, outside `webpent.egaie`.
- 3a. `lab_target.py`: index publishes each deployment's own schema block
  (the engine already derives SurfaceBindings from observation via
  `SurfaceBindings.from_schema`). Families, each with ≥2 implementations of
  the same invariant:
  - F1 records-ownership (identity boundary): actor-scoped impl, ACL impl.
  - F2 cart-totals (price integrity): client-total impl; recompute-with-
    client-base impl (ambiguous: needs two observations); signed recompute
    (secured).
  - F3 approval-chain (workflow identity/order): any-approver impl;
    approve-before-submit impl; secured variants.
  - F4 spend-cap (boundary limit): unenforced; per-request-only (cumulative
    cap needs multiple observations); enforced.
  - F5 grant-replay (NEW held-out family — single-use consumable
    authorization): replayable impl; consumed-on-first-use impl; windowed
    variant (ambiguous).
  Randomized per seed: routes, identifiers, field names, state
  representations (counter/enum/timestamp), ownership relationships.
- 3b. `labsuite/evaluator.py`: ground truth, per-family scoring, causal
  failures, leakage scan. Ground truth applied only after investigation.
- 3c. `labsuite/corpus.py`: DEV 101-104; HELD-OUT blocks 201-203, 211-213;
  negatives 301-302 (secured lookalikes). Shared-dependency inventory in
  the deliverables doc.
- 3d. Red-first tests: no import overlap with `eval_instances`; the lab's
  vocabulary disjoint from the L6 canonical set; blind investigations find
  F1-F4 defects and confirm nothing on secured lookalikes; evaluator
  isolation by subprocess import.

## Step 4 — Four fair configurations (`egaie/benchmark/strategies.py`)
- A adaptive (unchanged). B IndependentProposer: own candidate generation
  from observations, deterministic order — executed through the same port
  so ActionAuthority/G-02 stay shared. C adaptive minus the gain selector
  (ranked proposer + insertion selector). D ObservationDrivenBaseline:
  explicit invariant tests (cross-actor, numeric tamper, over-limit,
  consume-replay) with fixed rules.
- Equivalent initial observations: every strategy starts from the same
  recon snapshot. Budgets: rounds 16/48/96.
- Metrics per instance×family×strategy: TP/FP/FN, precision/recall,
  confirmed count, requests and seconds per confirmed finding, hypotheses
  generated/investigated/falsified/inconclusive, duplicate experiments and
  mutations, seal+replay validity, cross-strategy overlap and order
  divergence. Multiple runs of one instance are never counted as
  independent applications.
- 4 tests: every strategy generates AND executes candidates; no strategy
  state carries labels; B and D produce their own experiment ids.

## Step 5 — Provenance (`egaie/benchmark/provenance.py`)
- One machine-readable record per confirmed finding: initial observations,
  hypothesis + origin, evidence for/against, selected experiment +
  alternatives considered, authoritative invariant, verdict +
  classification (attached post-investigation by the evaluator),
  ProofBundle identity + replay result, fixture-influence flag.
- Test: records complete; classification added only post-run; subprocess
  isolation of labsuite from the engine.

## Step 6 — Failure-driven improvement
- Run A-D on the DEV lab corpus; classify FN causes (observations /
  relationship inference / hypothesis generation / selection /
  interpretation / classification-proof).
- Implement only demonstrated-failure fixes (expected: a grant-replay
  hypothesis generator for the L6 engine). Held-out stays untouched; if it
  ever informs a change, a fresh evaluation set is generated first.

## Step 7 — Gates, deliverables, release
- Full suite + every canonical gate; `docs/L7_DELIVERABLES.md`; commit
  inventory; release manifest; fresh ZIP + SHA-256. No real-world
  generalization claims.
