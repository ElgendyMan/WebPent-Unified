# P10 Candidate 01 — Vulnerable Components

## Scope

This candidate is target-local to Juice Shop 20.2.0 and is evaluated only against the loopback-only local instance. It is not a Generic Core change and it is not an approval record.

## Diagnosis

The candidate track identifies a possible frontend static dependency/component surface. Source metadata and challenge references are not sufficient to establish that an exact vulnerable asset is served by the running target. The current evidence does not establish a stable source-to-runtime asset mapping, a semantic vulnerability predicate stronger than asset existence, a safe candidate transition, or an independent negative control.

A bounded GET inventory may show that a resource exists, but resource reachability alone does not prove vulnerable-component behavior. No payload, submission, state mutation, external callback, or raw response persistence is permitted under the current local contract.

## Proposed oracle contract

The only acceptable future contract would require all of the following:

1. A target-local source proof that names the exact served asset and its version/integrity identity.
2. A bounded read-only baseline and candidate observation that differ on the intended vulnerability property, not merely on HTTP reachability.
3. A semantic causal predicate that can be evaluated by the central verifier.
4. An independent negative control using a non-vulnerable/control asset under the same observation conditions.
5. A redacted ProofBundle with seal verification and replay success.

No oracle implementation is proposed at this time because the required asset exactness and causal predicate are not established.

## Scope and safety review

The candidate can remain read-only only if the exact asset mapping is proven without adding payloads, modifying target state, contacting external infrastructure, or storing cookies, credentials, raw bodies, or tokens. Generic Core must remain unchanged.

## Decision

`BLOCKED_NEEDS_PROFILE_SOURCE_PROOF`

`counts_now=false`

The candidate must not enter the approved set, the scoring denominator, or an Official P10 Run until an independent reviewer approves the mapping and oracle contract after the required evidence exists.

## Required next evidence

- Exact source-to-runtime asset mapping.
- Stable identity/hash distinction for source and served artifact.
- Semantic causal predicate.
- Baseline/candidate/control observations.
- Central verification, sealing, replay, regression, and independent governance decision.

## Before/after status

No implementation was performed, so there is no before/after improvement claim. The correct before/after result is `not_applicable — prerequisite evidence absent`.

## Provenance

- Juice Shop source: `1618a611b173b4bf114028e6e02549950606e29d`.
- WebPent repository revision must be read from the release manifest at packet assembly time.
- This document does not alter frozen Ground Truth, the oracle-approved set, or Official P10 authorization.

## Reviewer decision field

`PENDING_INDEPENDENT_GOVERNANCE_REVIEW`

Reviewer identity, date, signature, and reviewed hashes must be supplied by a real independent human reviewer.

---

**Status:** blocked; no scoring impact.
