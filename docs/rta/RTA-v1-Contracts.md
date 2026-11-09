# RTA v1 — Realistic Target Assessment Contracts

## Scope

RTA v1 upgrades DCVU from in-process observations to real HTTP observations against explicitly owned, disposable loopback applications. The harness is designed for local engineering validation only. It does not authorize external targets, real credentials, login to user accounts, destructive actions, state-changing requests, finding creation, or qualification.

Synthetic identities and session handles are test data. They are not credentials and must never be exchanged with an external service. RTA execution is limited to read-only HTTP methods (`GET`, `HEAD`, and `OPTIONS`) until a separate owner-approved decision packet authorizes a narrowly defined local action.

## Observation contract

Each HTTP observation records a redacted response digest, bounded status code, request method/path, and semantic facts. Raw secrets, cookies, authorization headers, response bodies, and tokens are excluded from the contract. A status code alone is never a vulnerability signal; causal evaluation must compare baseline, candidate, and independent negative-control behavior.

## Discovery contract

Discovery starts from loopback HTTP behavior rather than synthetic surface facts. The snapshot may include endpoint templates, parameter names, authentication requirements, relation hints, and baseline observations. Target-specific semantics belong in an adapter/profile and must not leak into the Generic Core.

## Measurement boundary

RTA metrics are fixture-backed local engineering evidence. A case may enter the scored set only when its ground-truth record, causal oracle, independent negative control, and redacted replayable evidence are all valid. Blocked, observation-only, inconclusive, or out-of-scope cases are excluded from TP/FP/FN/TN denominators.

RTA results do not change `P10`, `P9`, `VIP`, Bug Bounty, or any official qualification state. The official isolated-run gate remains closed.

## References

The contracts reuse the existing DCVU verdict and evidence model while adding explicit loopback HTTP and synthetic authentication boundaries. They are intended to be exercised by the local RTA harness and audited through the project's existing safety, direct-I/O, neutrality, secret, and provenance validators.
