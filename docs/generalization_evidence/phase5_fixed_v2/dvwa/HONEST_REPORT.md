# Agent Evolution Sprint — Honest Campaign Report

- Campaign: `generalization-phase5-fixed-dvwa`
- Target: `http://127.0.0.1:8081`
- Persona: `stok`
- Runtime: `15.498s`

## Observed result

The live run crawled 1 routes, produced 0 structural curiosity flags, and executed 1 real guarded LLM calls at an actual calculated cost of $0.00232150.
Validator outcomes were: {"confirmed": 0, "inconclusive": 0, "refuted": 0}. Confirmed/promoted findings observed: 0.

## Agent loop evidence

- Planner, Exploiter, and Validator nodes were exercised and recorded in `graph_trace.json`.
- Exploiter delegated candidate execution to `ModernOrchestrator/ScopeLaw/AVI`; it did not use a raw HTTP bypass.
- Validator decisions remained governed by the existing deterministic validator, ProofBundle, replay, and promotion chain.
- Target content and credentials were not returned to LLM prompts or evidence.

## Acceptance verdict

- **IDOR + BOLA promoted findings: NOT DEMONSTRATED.** The observed run produced no confirmed/promoted finding.
- **False-positive control: PASS for this run.** No finding was promoted without a sealed ProofBundle and replay evidence.
- **Audit chain: PASS.** The campaign lifecycle chain was finalized and independently verified.
- **Bounty reports: NONE.** No promoted finding existed, so no submission-ready report was generated.

## Limitations

The governed decision trace recorded identity binding as unbound and real HTTP execution as false for these candidates; the trust chain therefore correctly stopped at INCONCLUSIVE/REJECTED semantics instead of manufacturing a finding. The production trace also reports an incomplete direct-invoke stage set; this is preserved as evidence rather than hidden.

Audit root: `632a0728169a54e43bbefe8b43b0057e0142b321cf4bb3a7b58d730b388d8e78`.
