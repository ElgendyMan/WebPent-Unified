# EGAIE Minimal Implementation Plan (Phase 1–3, smallest complete increment)

Principle: build ONE small package (`src/webpent/egaie/`) that composes existing
capabilities through narrow ports. We recreate nothing that exists; every
verdict flows through the existing CausalGuard/ProofBundle/Replay stack, and no
existing module is modified.

## New package layout

```
src/webpent/egaie/
  schemas.py        InvestigationState: hypotheses (status: PROPOSED/SUPPORTED/
                    CONTRADICTED/CONFIRMED/REFUTED), evidence items (supporting/
                    contradicting), unknowns, proposed experiments, observations,
                    DecisionRecords (deterministic, rationale per round),
                    to_dict/from_dict checkpoint-resume.
  selection.py      InformationGainSelector: score = w_gain*gain + w_relevance
                    − w_cost*cost − w_risk*risk − repetition_penalty; entropy
                    reduction over hypothesis priors; deterministic tie-breaks.
  repetition.py     Uninformative-repeat detection (same family+target signature
                    with ≥2 INCONCLUSIVE outcomes → strategy switch / terminate).
  orchestrator.py   InvestigationOrchestrator over injected Ports (Protocols):
                    run loop = select → scope-validate → authorized execute →
                    normalize observation → CausalGuard → (CONFIRMED only)
                    CompleteProofBundle + verify_replay → state/world-model/
                    attack-graph update → repetition check → next decision.
                    LLM proposer is advisory-only; it cannot confirm anything.
  causal_adapter.py Wraps cqa_v2 guarded_causal_evaluate + CompleteProofBundle
                    seal + verify_replay (imports, zero modification).
  seeds.py          forge PayloadBundle → ProposedExperiment; deep findings →
                    campaign Hypothesis via deep.bridge.findings_to_hypotheses
                    → egaie HypothesisRecord.
  persistence.py    JSON state file: save/load/resume (skips completed rounds).
  benchmark/
    fixture.py      ControlledFixtureTarget: in-process transport (no sockets)
                    emitting the X-* header contract CausalGuard requires;
                    positive AND negative cases; multi-step.
    baseline.py     FixedOrderBaseline: same ports, fixed family order, ignores
                    evidence — the comparison control.
    runner.py       run_comparison(): both engines on the same ground truth and
                    budget; metrics = precision, recall, FN rate, FP rate,
                    inconclusive rate, experiments-per-confirmed, reproducibility
                    (run twice, compare). Acceptance thresholds defined BEFORE
                    the run (below).
```

## Ports (no modification of existing code)

- ExperimentPort: performs scope validation (target must be the fixture's
  loopback identity) and authorized execution; returns the three-observation
  set (baseline/candidate/control) CausalGuard requires.
- ValidationPort: `guarded_causal_evaluate` (existing, unmodified).
- ProofPort: `CompleteProofBundle` + `verify_replay` (existing, unmodified).
- ModelPort: records world-model/attack-graph deltas as inspectable ledger
  entries (advisory projection, no mutation of asros objects).

## Non-negotiables honored

- No component promotes an unverified hypothesis: CONFIRMED requires
  CausalGuard CONFIRMED + sealed bundle + replay_valid; anything else stays
  PROPOSED/SUPPORTED/CONTRADICTED/UNKNOWN.
- Zero network: the fixture transport is in-process. No sockets, no HTTP.
- No getattr in the new package; no broad `except Exception`; no live
  exploitation; verdict/emulator/rehearsal/modern_spine/profile untouched.

## Acceptance thresholds (defined before the benchmark run)

- Adaptive recall ≥ 0.6 on positives; false-positive rate = 0 (negative
  controls must remain negative).
- Adaptive recall > baseline recall at the same budget, or equal recall with
  strictly fewer experiments per confirmed finding.
- Reproducibility: two identical runs → identical confirmed-finding sets.
- Existing suite stays green and monotonic.

## Tests (red-first, tests/egaie/)

test_schemas (roundtrip/resume), test_selection (gain ordering, repetition
penalty, determinism), test_repetition, test_orchestrator (end-to-end on
fixture, no unverified promotion, termination, decision records), 
test_causal_wiring (replay failure blocks confirmation), test_benchmark
(comparison + thresholds + reproducibility).

## Definition of Done mapping

1→ orchestrator runs on fixture; 2→ state + decision log JSON inspectable;
3→ confirmed ⇒ sealed replay-valid bundle; 4→ negatives stay negative;
5→ adaptive vs fixed baseline; 6→ suite green, unrelated failures documented
(none expected); 7→ regression report + benchmark results + architecture
summary + ZIP; 8→ blockers + next milestone in NEXT_STEPS.md.