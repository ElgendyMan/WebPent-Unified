# P10 Candidate 02 — SQL Injection Read-Only Probe

## Scope

This candidate is a proposed Juice Shop target-local expansion track. It is not a Generic Core change, not an approval record, and not an authorization to send injection payloads.

## Diagnosis

A meaningful SQL-injection finding requires evidence that attacker-controlled input changes query semantics or causes a defined database-side effect. A normal GET request, an error page, a reflected value, or a route being reachable cannot establish that predicate.

The current authorized local contract is bounded read-only activity with no crafted injection payloads, no destructive actions, no account or credential use, and no raw response persistence. Under those conditions, the causal signal cannot be established safely or reproducibly.

## Proposed oracle contract

A future contract would need an explicitly authorized isolated lab and a non-destructive, pre-approved test input set. It would require:

1. A target-local source-to-route mapping for the exact input sink and query path.
2. A safe precondition proving that the test cannot mutate business state or expose secrets.
3. Baseline input and candidate input observations with a deterministic semantic difference.
4. An independent negative control that reaches the same path without the injection condition.
5. A central verifier that evaluates a causal predicate rather than a generic error/status.
6. Redacted sealed ProofBundles with successful `verify_seal()` and replay.
7. Independent governance approval before any live payload execution.

No live oracle or adapter is implemented because the required payload authorization and safe causal contract are absent.

## Scope and safety review

Running crafted SQL/UNION input against the local target would exceed the current no-payload read-only scope. It could also create ambiguous error-based evidence and would not be acceptable as an Official P10 operation without a separate approved lab contract. No bypass, mutation, credential use, or external callback is permitted.

## Decision

`BLOCKED_NO_SAFE_CONTRACT`

`counts_now=false`

The candidate must not enter the approved set, scoring denominator, or Official P10 Runs.

## Required next evidence

- Explicit authorization for a controlled non-destructive payload set.
- Exact source-to-runtime sink mapping.
- Safety proof and reset/cleanup rule.
- Baseline/candidate/control data with no sensitive raw persistence.
- Semantic verifier, sealed/replayable ProofBundle, regression tests, and independent review.

## Before/after status

No implementation or live candidate probe was performed. Therefore no before/after improvement or metrics claim exists.

## Provenance

- Juice Shop source: `1618a611b173b4bf114028e6e02549950606e29d`.
- WebPent release provenance is defined by the release manifest included in the reviewer packet.
- This document leaves frozen Ground Truth, Generic Core, and Official P10 authorization unchanged.

## Reviewer decision field

`PENDING_INDEPENDENT_GOVERNANCE_REVIEW`

A real independent human reviewer must approve or reject the proposed scope before any future payload-based work.

---

**Status:** blocked; no scoring impact.
