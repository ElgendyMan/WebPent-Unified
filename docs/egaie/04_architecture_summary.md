# EGAIE Architecture Summary

The Evidence-Grounded Autonomous Investigation Engine: a minimal
closed-loop investigation orchestrator composed on top of the existing
cqa_v2 validation stack, unmodified.

## Package layout

src/webpent/egaie/
- schemas.py: explicit, JSON-round-trippable investigation state
  (HypothesisRecord, ProposedExperiment, EvidenceItem, DecisionRecord,
  InvestigationState) plus the enums they carry. Every hypothesis,
  experiment, decision, and observation is a first-class persisted
  record, inspectable after a run.
- selection.py: InformationGainSelector. score = gain_estimate
  + family bonus for unresolved families - cost - risk - repetition
  penalty; exhausted signatures score -1000. Deterministic: ties break
  by experiment_id. Returns SELECT, STRATEGY_SWITCH (all candidates
  exhausted), or TERMINATE (nothing pending).
- repetition.py: RepetitionRegister. Inconclusive and blocked outcomes
  are uninformative; a signature exhausted after 2 of them forces a
  strategy switch instead of a third blind retry.
- orchestrator.py: InvestigationOrchestrator. One round: propose
  (advisory only) -> information-gain select -> record a deterministic
  decision -> execute -> normalize observations -> CausalGuard ->
  (on confirmed) seal a CompleteProofBundle and replay-verify -> apply
  verdict -> update world model / attack graph -> repetition register.
  run() works on a snapshot copy, so save/interrupt/resume replays
  deterministically.
- persistence.py: save_state / load_state (plain JSON).
- causal_adapter.py: the only place EGAIE touches cqa_v2, through
  ports. CausalValidationPort.validate calls
  guarded_causal_evaluate; ProofBundlePort.build calls
  build_complete_proof_bundle with runtime provenance pinned to
  controlled-local/offline; ProofBundlePort.verify calls
  verify_replay.
- seeds.py: benchmark seeding only (one hypothesis + one stage1
  experiment per ground-truth case, explicit hypothesis binding).
- benchmark/: controlled local benchmark. fixture.py (in-process
  target whose observation triples implement the CausalGuard
  observation contract: status_code, semantic_digest, X-headers for
  actor/resource context), ground_truth.py (4 positive incl. one
  multi-step IDOR, 2 negative controls), baseline.py (fixed insertion
  order, same validated pipeline), runner.py (metrics, pre-declared
  thresholds, adaptive-vs-baseline comparison, reproducibility check).

## Ports (the LLM boundary)

model_port.propose may add hypotheses and experiments; model_port.update
may add world-model and attack-graph annotations. The LLM is strictly
advisory: it can widen the candidate set, never confirm anything.
Every promotion flows through CausalGuard and a sealed, replay-verified
CompleteProofBundle.

## Promotion discipline (the one rule)

A hypothesis reaches CONFIRMED only when CausalGuard returns verdict
"confirmed" AND the sealed bundle's replay is valid
(replay_valid = verdict match + digest match + seal valid + seal match
+ replay executed). A "clean" verdict contradicts the bound hypothesis
with contradicting evidence. Blocked/inconclusive outcomes leave
status untouched and feed the repetition register; two uninformative
outcomes on one signature force a strategy switch. No component may
promote an unverified hypothesis into a confirmed vulnerability. Scope
denial is fail-closed: nothing executes, nothing is observed.

## Verdict binding

Each experiment carries the hypothesis_id it probes. _update_hypothesis
binds explicitly first; family matching is only a fallback for
unbound experiments. This is what keeps a verdict from leaking onto a
different case's same-family hypothesis (the negative-control leak
found and fixed at eba6c2f).

## What cqa_v2 keeps

CausalGuard (fail-closed, semantic candidate-vs-baseline difference,
path-analogous positive control, authorization differential),
CompleteProofBundle (auto-sealed by identity+digest hash), and
verify_replay are used exactly as shipped. EGAIE adds orchestration
around them, nothing inside them.

## How to run

- Full loop demo: tests/egaie/test_orchestrator.py,
  test_causal_wiring.py.
- Benchmark: `from webpent.egaie.benchmark.runner import
  run_comparison; run_comparison(max_rounds=14, repetitions=2)` ->
  docs/egaie/02_benchmark_results.json. Adaptive: recall 1.0, FP 0,
  7 experiments for 4 confirmed (multi-step via the follow-up
  proposer). Baseline: recall 0.75, FP 0, 6 experiments. Reproducible
  across repeated adaptive runs.
