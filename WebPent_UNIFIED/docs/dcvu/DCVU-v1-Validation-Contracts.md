# Detection Capability Validation Upgrade v1

## Scope

DCVU v1 is a **controlled local benchmark** for measuring whether WebPent can discover and confirm vulnerabilities in realistic disposable target fixtures. It is not an Official P10 run, a bug bounty campaign, or a VIP qualification decision.

The first implementation is deliberately offline and in-process. Target fixtures model authentication relationships, roles, ownership, tenant boundaries, workflows, and authorization semantics without contacting an application over the network. This keeps the initial validation reversible and avoids real credentials, login sessions, tokens, external callbacks, and state-changing target actions.

## Accepted case contract

An accepted scoring case must have an immutable target profile, source/fixture digest, independently reviewed ground truth, semantic location fingerprint, expected impact, causal oracle, independent negative control, redacted observations, and replayable proof. A case that requires credentials, login, mutation, external callbacks, or an unapproved privilege boundary is not accepted in this phase.

The six initial vulnerability classes are:

| Class | Required semantic relationship |
|---|---|
| IDOR / BOLA | An object identifier must be bound to its owner or authorized subject. |
| Privilege escalation | A lower-privilege subject must not obtain a higher-privilege capability. |
| Broken function-level authorization | A function must enforce role/capability requirements independently of route reachability. |
| Business logic abuse | A workflow transition must enforce its business invariant and actor authorization. |
| Tenant isolation | A subject must not cross a tenant boundary to read or act on another tenant's object. |
| Workflow authorization | A state transition must require the correct actor and predecessor state. |

## Measurement rules

A **true positive** requires a detector decision that matches an `exists=true` ground-truth record and has complete candidate/control evidence plus proof seal and replay verification. A **false positive** is a detector decision for a case whose independent ground truth says `exists=false`, provided the case was fully observable and the oracle/control contract was valid. A **false negative** is counted only for an accepted, fully executable, fully observable case with `exists=true` where the detector fails to produce a valid finding decision. Blocked, inconclusive, observation-only, and out-of-scope cases are excluded from the denominator and are reported separately.

Precision, recall, and F1 are emitted only when the target has a valid admitted case set and all scored cases have valid observation contracts. Class coverage is computed against the admitted target-local class set, not against the six-class aspiration list. Offline fixture metrics are benchmark evidence and do not alter P10/VIP gates.

## Safety invariants

| Invariant | Required value |
|---|---:|
| External target scope | `false` |
| Real credentials/login/tokens | `false` |
| Target state mutation | `false` in the initial offline phase |
| Official isolated P10 authorization | `false` |
| Qualification effect | `false` |
| Raw secret/payload retention | `false`; evidence is redacted |

## Phase gates

Phase 1 is complete when these contracts and invariants are represented in typed code and regression tests. Phase 2 may add only disposable local fixtures. Any move to HTTP requests, login, credential use, token creation, or target mutation requires a separate owner decision packet and explicit approval before execution.
