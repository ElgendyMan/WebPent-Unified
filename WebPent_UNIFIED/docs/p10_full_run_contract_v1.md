# P10 Full-Run Contract v1

This contract governs any live Juice Shop benchmark run. It is not a qualification decision.

## Scope

The only permitted target origin is `http://127.0.0.1:3000`. The run must set the engagement target host and exact origin policy before any request. Only `GET` navigation and the existing allowlisted `juice-shop-mat-search` typed-search workflow are permitted. Redirects to another origin, credentials, cookies, account forms, authentication, MFA/OTP, external destinations, and state-changing methods are forbidden.

## Isolation

Every run must have a unique `run_id`, `workspace_id`, and `artifact_namespace`. The run must record target-integrity measurement and clean up temporary browser resources. No raw response bodies, request bodies, headers, cookies, probes, tokens, or screenshots may be retained.

## Case accounting

`executed_case_ids` must list every approved case attempted in the run. A case is only placed in `candidate_case_ids` after its bounded adapter returns a target-backed redacted observation. A case is only placed in `proof_case_ids` and `replay_case_ids` after a central sealed `ProofBundle` passes `verify_seal()`, structural validation, promotion validation, and replay against the same redacted evidence.

## Oracle semantics

An HTTP status or endpoint existence is an observation, not a vulnerability finding. A confirmed case requires the approved ground-truth mapping, the frozen oracle contract, a target-backed causal signal, and an independent negative control. If the adapter cannot establish these conditions, the case is recorded as `inconclusive` or `blocked_by_precondition`; it is not counted as TP or FN.

## Qualification gate

P10 metrics remain withheld unless three isolated runs exist, every run exercises the complete approved case set, target integrity is measured, all findings are live and proof-backed, and the evaluator's mapping-review validation passes. This contract never authorizes a P10 or VIP claim by itself.
