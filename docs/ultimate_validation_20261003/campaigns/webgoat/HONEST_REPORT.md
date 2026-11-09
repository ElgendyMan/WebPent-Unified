# Agent Evolution Sprint — Honest Campaign Report

- Campaign: `ultimate-webgoat-20261003`
- Target: `http://127.0.0.1:8082/WebGoat`
- Persona: `all`
- Runtime: `8.113s`

## Observed result

The live run crawled 1 routes, produced 0 structural curiosity flags, and executed 1 real guarded LLM calls at an actual calculated cost of $0.00109650.
Validator outcomes were: {"blocked": 0, "confirmed": 0, "inconclusive": 0, "refuted": 0}. Confirmed/promoted findings observed: 0.
The chaining engine discovered 0 candidates and confirmed 0 combined chains.

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

Audit root: `5a2523ce76c8dd08a883ea1ac751a66944748d9f681753b0fd760f4f1f74f78b`.
