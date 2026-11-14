# Agent Evolution Sprint — Honest Campaign Report

- Campaign: `regression-juice-live-v4-20261003`
- Target: `http://127.0.0.1:3000`
- Persona: `all`
- Runtime: `179.13s`

## Observed result

The live run crawled 35 routes, produced 30 structural curiosity flags, and executed 7 real guarded LLM calls at an actual calculated cost of $0.03197775.
Validator outcomes were: {"blocked": 0, "confirmed": 3, "inconclusive": 0, "refuted": 0}. Confirmed/promoted findings observed: 3.
The chaining engine discovered 0 candidates and confirmed 0 combined chains.

## Agent loop evidence

- Planner, Exploiter, and Validator nodes were exercised and recorded in `graph_trace.json`.
- Exploiter delegated candidate execution to `ModernOrchestrator/ScopeLaw/AVI`; it did not use a raw HTTP bypass.
- Validator decisions remained governed by the existing deterministic validator, ProofBundle, replay, and promotion chain.
- Target content and credentials were not returned to LLM prompts or evidence.

## Acceptance verdict

- **Promoted findings: 3.** ProofBundle references recorded: 3; each must remain sealed and replay-verified.
- **False-positive control: PASS for this run.** The campaign summary records promotion only after the governed ProofBundle/replay path.
- **Audit chain: PASS.** The campaign lifecycle chain was finalized and independently verified.
- **Bounty reports: blocked until a CVSS score and justification are present.** The live hunter projection does not invent CVSS data; the strict reporter must refuse incomplete findings.

## Limitations

Only redacted metadata is emitted here. Raw target bodies, headers, credentials, and tokens are not copied into campaign artifacts. A promoted reference without a CVSS-backed Finding remains non-reportable by design.

Audit root: `24dd27397e85e3b9d4abb29c0d4dc67211d4179f7c5b18c110b6314f985775aa`.
