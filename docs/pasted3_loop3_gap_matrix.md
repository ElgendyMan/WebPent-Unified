# pasted_content_3 — loop 3 gap matrix

## Scope

This audit compares `pasted_content_3.txt` with the current source, tests, graph topology, and local runtime artifacts. WAPTLab and Juice Shop remain explicitly excluded.

| Requirement | Current classification | Evidence / gap |
|---|---|---|
| Identity provisioning contracts and redacted records | Implemented and runtime-proven locally | `identity_provisioning.py` and focused tests prove scope blocking, budget blocking, correlation mismatch handling, timeout as inconclusive, and raw verification material rejection. |
| A.3 crawler/javascript → SignupFormDetected producer | Implemented and runtime-proven locally | Crawler and JavaScript intelligence both use the deterministic producer; only registration-like actions become redacted `signup_forms_detected` projections and raw values are rejected. |
| Identity node before authentication | Implemented and runtime-proven locally | Opt-in planner→identity_provisioning_pre_auth→auth topology is compiled and tested; OFF preserves planner→auth. |
| Identity reactive invocation after crawler/javascript | Implemented and runtime-proven locally | Crawler and JavaScript intelligence emit the same reducer-safe producer contract; crawler→identity reactive wiring is tested and default-off. |
| IdentityRecord consumed by authentication | Implemented and runtime-proven locally; live reuse not qualified | Auth projects only `profile_ref` from `identity_records`, restores profiles from `client_id:engagement_id:identity` with legacy fallback, and never copies vault refs into credentials. Focused handoff and vault tests pass. |
| IdentityRecord consumed by access-control/business-logic workflows | Implemented locally; live workflow not qualified | Access-control now consumes the same report-safe identity-record projection when direct profiles are absent; differential confirmation still requires real causal signal, negative control, and ProofBundle. |
| Gmail API/IMAP watcher backend | Design-only / adapter boundary | `EmailVerificationWatcher` accepts an injected poller; live Gmail/IMAP adapters are intentionally not qualified. Provider/credentials-ref settings exist, but RuntimeFactory does not construct a transport automatically. |
| Vault TTL and engagement cleanup | Implemented and runtime-proven locally | TTL/expiry, composite `client_id:engagement_id:identity` addressing, legacy fallback, CLI/worker cleanup, and resume cleanup are covered by focused tests and code review. |
| Identity never leaks to report | Implemented and runtime-proven locally | Defense-in-depth redaction excludes identity-specific state keys; rendered report projection test verifies email/password/vault refs do not appear. |
| Identity reused across login pages | Implemented locally; browser/live reuse not qualified | Authentication consumes the same bounded verified profile set for primary/secondary bootstrap and reuses each profile through the existing login transport seam; no external login page was executed in this loop. |
| Gmail failure inconclusive | Implemented and runtime-proven locally | Watcher timeout/correlation failure maps to inconclusive and does not promote verification. |
| Wildcard compilation and strict anchoring | Implemented and runtime-proven locally | Focused compiler tests cover root/sibling/attacker-domain rejection and safe normalization. |
| Wildcard feeds same scope contract to target consumers | Implemented and runtime-proven locally | Compiler updates the canonical Target scope used by crawler and takeover; takeover receives only in-scope hosts and topology/behavior are covered without network. Literal object identity is not claimed across checkpoint serialization. |
| Out-of-scope discovered subdomains enter NegativeEvidenceLedger | Implemented and runtime-proven locally | Takeover filters before verification and emits scoped `NegativeEvidence` records for out-of-scope discovered hosts; no transport is invoked for them. |
| Existing Target.is_in_scope and scope_enforcer remain the single source of truth | Implemented locally but not fully live-qualified | Existing scope contracts pass; external live qualification is intentionally absent. |
| Required live Gmail/browser/lab qualification | Blocked by explicit boundary | No external credentials or lab run is authorized in this loop; no live confirmation is claimed. |

## Remaining qualification limits

1. Gmail/IMAP adapters and live qualification remain environment-dependent and must stay classified as design-only or blocked until authorized adapters and credentials are supplied.
2. Authentication/access-control confirmation remains evidence-gated: no finding is confirmed without causal signal, negative control, and ProofBundle.
3. The implementation does not run WAPTLab or Juice Shop in this loop, by explicit instruction.
