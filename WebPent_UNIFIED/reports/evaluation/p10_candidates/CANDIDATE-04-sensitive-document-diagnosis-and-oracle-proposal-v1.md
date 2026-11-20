# P10 Candidate 04 — Sensitive Document Static Resource

## Scope

This is a proposed Juice Shop target-local expansion track. It is not a Generic Core change, not a Ground Truth amendment, and not an approval to retrieve or persist sensitive document contents.

## Diagnosis

A static document being present in source or reachable at a public path does not by itself prove a vulnerability. The candidate needs an exact source-to-runtime mapping, a policy or exposure predicate that is demonstrably unsafe, and an independent control showing that the result is not ordinary intended public content.

Current source inspection and the existing bounded inventory do not establish all of those conditions for a new scoring case. The current workflow also forbids persisting raw bodies, secrets, cookies, credentials, or tokens. A filename, status code, or route existence is insufficient as causal evidence.

## Proposed oracle contract

A future contract would require:

1. Exact mapping from the target source/resource to the served runtime asset.
2. A documented sensitivity predicate that can be evaluated without storing the document body.
3. A safe anonymous-read precondition, if anonymous exposure is the intended condition, with no filter bypass or authentication bypass.
4. Baseline resource/control-resource comparison under the same read-only workflow.
5. An independent negative control that is intentionally public or non-sensitive.
6. A central verifier that evaluates the semantic exposure predicate, not only reachability or status.
7. Redacted ProofBundle creation, successful sealing, `verify_seal()`, and replay.
8. Independent governance approval of the mapping, sensitivity model, and scoring class.

No adapter or oracle is implemented because the exact mapping and semantic predicate are not yet approved or proved.

## Scope and safety review

The candidate may be considered only through metadata-level or explicitly redacted observations. It must not use authentication bypass, path traversal, filter bypass, external callbacks, destructive actions, or raw document persistence. Any future implementation must remain inside the Juice Shop adapter/profile.

## Decision

`BLOCKED_NEEDS_TARGET_MAPPING_AND_ORACLE_REVIEW`

`counts_now=false`

This candidate cannot enter the approved set or scoring denominator and cannot authorize an Official P10 Run.

## Required next evidence

- Exact runtime mapping and source provenance.
- Sensitivity predicate and control-resource definition.
- Safe anonymous-read precondition without bypass.
- Baseline/candidate/negative-control observations.
- Central verification, sealed/replayable ProofBundle, regression tests, and independent review.

## Before/after status

No implementation or raw document retrieval was performed. Therefore no before/after improvement or metrics claim exists.

## Provenance

- Juice Shop source: `1618a611b173b4bf114028e6e02549950606e29d`.
- WebPent release provenance is defined by the release manifest included in the reviewer packet.
- This document leaves frozen Ground Truth, Generic Core, and Official P10 authorization unchanged.

## Reviewer decision field

`PENDING_INDEPENDENT_GOVERNANCE_REVIEW`

A real independent human reviewer must approve the mapping and exposure predicate before any future implementation.

---

**Status:** blocked; no scoring impact.
