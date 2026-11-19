# Juice Shop Additional Candidate Analysis v1

> AI Independent Technical Review completed within the stated scope. This is a non-human attributable technical review and is not a human signature, human countersign, or independent human governance approval.

## Decision summary

A bounded source-only review identified two technically meaningful surfaces that are worth preserving as future proposals: permissive CORS/security middleware configuration and the redirect allowlist boundary. It also re-reviewed the existing input/state surfaces represented by the Ground Truth. None can be promoted under the current local contract because the required semantic causal evidence would need credentials, crafted input, an external destination, state mutation, or a new frozen mapping/oracle decision. No adapter, oracle, case, class, scoring count, Ground Truth artifact, or run gate was changed.

| Candidate surface | Potential class | Source evidence | Safe current action | Decision | Counts now |
|---|---|---|---|---|---:|
| Permissive CORS and limited security middleware | Security Misconfiguration | Juice Shop `build/server.js` source snapshot: `cors()` is applied globally and `helmet.noSniff()`/`helmet.frameguard()` are applied; exact security impact depends on response sensitivity and browser credential context | Record source diagnosis only; do not send credentialed cross-origin requests | Blocked pending a target-backed causal predicate and authorized synthetic identity/control model | No |
| Redirect allowlist boundary | Unvalidated Redirects | Juice Shop `build/routes/redirect.js`: `query.to` is checked by `isRedirectAllowed()` and then redirected; the challenge logic distinguishes intended allowlisted destinations from unintended redirects | No external destination and no redirect probe is executed; source semantics only | Blocked under current no-external-destination scope | No |
| Negative-order / improper input validation | Improper Input Validation | Ground Truth maps `juice.negative_order.v1` to an out-of-scope mapping and the behavior requires an order/business-state transition | No state-changing request | Blocked by mutation gate; remains non-scoring | No |
| Login-admin / NoSQL command injection | Injection | Ground Truth maps `juice.login_admin.v1` and `juice.nosql_command.v1` out of scope; meaningful proof needs crafted input and/or authentication boundary behavior | No payload, bypass, or credential use | Blocked by safe-scope contract; remains non-scoring | No |
| Reflected/persisted XSS variants | XSS | Ground Truth maps the variants out of scope; causal proof requires payload execution and, for persisted behavior, a state-changing write | No payload or write | Blocked by no-payload/no-mutation scope; no duplicate promotion | No |

## Contract gate assessment

The two source-derived surfaces fail closed at the contract stage, not at the detection stage. A future promotion would require an exact source-to-runtime mapping, an approved semantic vulnerability predicate, a safe reproducible precondition, a baseline, a candidate observation, an independent negative control, central verification, a redacted sealed ProofBundle, successful `verify_seal()`, replay, target-local implementation, regression coverage, and governance approval. A source comment, route existence, an HTTP success status, a permissive-looking header, or a redirect implementation is not sufficient by itself.

For the CORS surface, a valid predicate would need to demonstrate an unauthorized cross-origin read of a sensitive response under a controlled, authorized identity model. The current policy forbids credentials and external destinations, and no safe local contract currently proves that semantic delta. The security-header surface has the same limitation: a missing or weak header must be tied to a concrete security-relevant browser behavior, not merely to a header inventory.

For the redirect surface, a valid predicate would need to establish an unintended redirect to a destination outside the intended allowlist. The current policy forbids external-target interaction and outbound destinations, so running that proof would cross a gated boundary. The source implementation is therefore a diagnosis, not a finding.

The input and identity surfaces remain blocked for the already documented reasons: meaningful confirmation requires crafted payloads, credentials or cross-user state, bypass behavior, or mutation. They must not be counted as FN, added to the scoring denominator, or used to close the numerical gap.

## Outcome and next gate

The candidate-analysis phase is complete with governed blockers. The current proposed scoring set remains **3 cases / 3 classes**, the theoretical gap remains **7 cases / 3 classes**, and no candidate is approved for implementation. Official P10 Runs remain unauthorized and must not start. Any future attempt to open a credential, external-destination, mutation, frozen-artifact, or qualification path requires a separate Owner Decision Packet and explicit owner approval.

## References

| Ref. | Internal source | Purpose |
|---|---|---|
| [1] | [`docs/juice_shop_p10_ground_truth_v1.json`](../../docs/juice_shop_p10_ground_truth_v1.json) | Frozen case mapping and expected dispositions |
| [2] | [`docs/juice_shop_p10_expansion_plan_v1.json`](../../docs/juice_shop_p10_expansion_plan_v1.json) | Thresholds, candidate tracks, and promotion gates |
| [3] | [`docs/juice_shop_governance_decision_v1.json`](../../docs/juice_shop_governance_decision_v1.json) | Current governance status and non-scoring dispositions |
| [4] | Juice Shop source snapshot `1618a611b173b4bf114028e6e02549950606e29d`, `build/server.js` | CORS and security middleware source evidence |
| [5] | Juice Shop source snapshot `1618a611b173b4bf114028e6e02549950606e29d`, `build/routes/redirect.js` | Redirect allowlist source evidence |
