# P10 Candidate 03 — Broken Access Control State Boundary

## Scope

This is a proposed Juice Shop target-local expansion track. It is not a Generic Core modification, not an approval record, and not permission to bypass authentication or create real user accounts.

## Diagnosis

A broken-access-control finding requires a controlled comparison between an authorized subject and an unauthorized subject, or a precisely defined ownership/state boundary. The current local scope does not provide a governed second-user identity, credential fixture, authorization transition, or safe state-changing workflow for this candidate.

Route reachability by an anonymous client is not enough to prove an authorization failure. Using authentication bypass, real credentials, cross-user data, or state mutation would violate the current scope and would make the result unsuitable for a fail-closed benchmark.

## Proposed oracle contract

A future contract would require a dedicated authorized fixture or lab with synthetic identities and deterministic reset. It must include:

1. Source-to-runtime mapping for the protected resource and authorization decision.
2. Two controlled identities or equivalent ownership fixtures created without real credentials.
3. A safe precondition and reset rule that prevents durable or destructive mutation.
4. Baseline authorized observation and candidate unauthorized observation.
5. An independent negative control using a resource owned by the requesting identity or a public control resource.
6. A semantic causal predicate evaluated by the central verifier.
7. Redacted ProofBundles with successful sealing, `verify_seal()`, and replay.
8. Independent governance approval for the identity and state model.

No adapter, oracle, or live test is implemented because the required identity/state precondition is not present.

## Scope and safety review

The current phase forbids auth bypass, use of credentials, cross-user access attempts, and state mutation. A synthetic identity fixture could be considered later only after separate authorization and a target-local contract review. Generic Core and frozen Ground Truth must remain unchanged.

## Decision

`BLOCKED_PRECONDITION_OR_MUTATION`

`counts_now=false`

The candidate must not enter the approved set, scoring denominator, or Official P10 Runs.

## Required next evidence

- Authorized synthetic identity/ownership fixture.
- Exact protected-resource and authorization-decision mapping.
- Non-destructive baseline/candidate/control comparison.
- Reset and cleanup proof.
- Central verifier, sealed/replayable ProofBundle, regression tests, and independent review.

## Before/after status

No implementation or live cross-user test was performed. There is no before/after result or metrics claim.

## Provenance

- Juice Shop source: `1618a611b173b4bf114028e6e02549950606e29d`.
- WebPent release provenance is defined by the release manifest included in the reviewer packet.
- This document leaves frozen Ground Truth, Generic Core, and Official P10 authorization unchanged.

## Reviewer decision field

`PENDING_INDEPENDENT_GOVERNANCE_REVIEW`

A real independent human reviewer must approve the identity/state model before any future implementation.

---

**Status:** blocked; no scoring impact.
