# EGAIE: Blockers and Next Milestone

## Blockers (deliberate, not defects)

1. The benchmark is fixture-only. ControlledFixtureTarget speaks the
   CausalGuard observation contract in-process; there is no HTTP
   transport, no real request/response, and no live target. Wiring the
   same ports to a real controlled local target (a self-hosted
   deliberately-vulnerable app spun up per run) is the next
   integration step and needs its own transport port + provenance
   layer. Out of scope for this increment by the mission's own
   constraints (no live network, controlled local fixtures only).
2. The benchmark's ground truth is six hand-declared cases. A
   meaningful adaptive-vs-baseline claim needs a larger case set with
   families where information-gain ordering actually differs from
   insertion order at scale; the current set already shows the gap
   (multi-step recall: adaptive 1.0 vs baseline 0.75) but is small.
3. The FollowUpProposer is a scripted stand-in for model-driven
   follow-up. It proves the multi-step mechanism (stage1 inconclusive
   -> stage2 experiment -> confirmed); replacing it with a real
   model_port proposer changes nothing in the orchestrator contract.
4. World-model / attack-graph updates are recorded as opaque
   annotation dicts from model_port.update. A structured world model
   (entities, edges, auth relationships) with graph-level queries is
   the natural Phase 4.

## Next milestone

EGAIE Phase 4: transport port + controlled self-hosted target. One
ExperimentTransport port (execute over real HTTP against a
locally-spawned fixture app), one provenance layer that records raw
request/response pairs into the proof bundle's runtime provenance,
and a larger ground-truth set (20+ cases across families, negative
controls included). Acceptance: the same orchestrator, unchanged, runs
end-to-end over HTTP; negative controls stay negative; bundles replay
against the recorded raw evidence; adaptive beats baseline on
experiments-per-confirmed at equal recall.

After that: model-driven proposer behind the existing advisory
boundary, then a structured world model with graph queries feeding
selection gain estimates.
