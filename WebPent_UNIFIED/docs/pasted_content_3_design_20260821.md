# Pasted Content 3 — Control Plane Design

## Objective

Add an additive, typed, fail-closed control-plane layer for scope, browser sessions, identities, email events, workflow steps, and local qualification. The layer must not create a second I/O path: live adapters are injected as policy-checked handlers and are callable only through the existing runtime/action execution plane.

## Existing seams retained

| Existing seam | Reuse rule |
| --- | --- |
| `engagement_scope.OriginPolicy` and SSRF helpers | Preserve exact-origin matching for legacy callers; add a separate wildcard compiler with explicit ambiguity status. |
| `RuntimeFactory`, `AdapterRegistry`, `RegisteredAdapter` | New control-plane capabilities are registered as typed adapters with G-02 metadata; no raw client fallback. |
| `reauth_vault` | Store only short-lived secret references and encrypted material through the existing vault seam; never put raw password, cookie, token, or OTP in graph state. |
| `ProofBundle` and `ProofBundleStore` | Extend proof metadata through existing redacted fields and enforce current promotion gates; never relax confirmation. |
| `workflow_replay` models | Add an execution result/state-machine layer without changing the existing plan-only API. |

## New typed contracts

A new `webpent.shared.control_plane` module will contain frozen Pydantic contracts:

- `EngagementScope`: engagement ID, root domains, schemes, ports, path rules, DNS/redirect policies, email domains, control-plane exceptions, wildcard interpretation, approval source, creator, and expiry.
- `ScopeDecision`: allow/deny/ambiguous decision, normalized URL, matched rule, reason, and checked policy.
- `IdentityProfileRef`: non-secret identity reference bound to one engagement, role/tenant references, lifecycle status, and provenance.
- `BrowserSessionRef`: non-secret session reference with profile/context references, authenticated origins, expiry, and a cookie fingerprint only.
- `WorkflowStep`: typed preconditions, action ID, expected transition, redacted observations, rollback action, proof references, and status.
- `EmailEvent`: hashed message identity/subject, sender domain, mailbox reference, nonce, target origin, short-lived artifact reference, confidence, and status.
- `ActionOutcome`: normalized policy/runtime result for adapter calls, with no secret payload.

All models forbid unknown fields, normalize bounded strings, and reject raw secret-shaped fields where applicable.

## Scope compiler

`compile_scope()` will parse only explicit operator input. For `https://*.g6hospitality.com`, the default is HTTPS/443, all explicitly recorded subdomain depth, apex denied unless separately listed, exact path policy, IDNA normalization, no userinfo/query/fragment ambiguity, and no look-alike suffix matching. Evaluation is pure and deterministic. DNS resolution is represented as a typed check result; resolution errors, private/reserved IPs, rebinding, and out-of-policy redirects deny execution. Gmail/OAuth origins are exceptions with `attack_surface=False`.

Ambiguous wildcard input returns `scope_ambiguous` and cannot be authorized by an LLM or by a fallback parser.

## Browser adapter boundary

`BrowserActionAdapter` is a handler protocol, not a direct Playwright client. It accepts a typed action request only after the caller has a valid `RuntimeContext`, a `ScopeDecision`, a capability check, an engagement/identity binding, and bounded budgets. A missing Playwright capability, missing adapter, expired session, CAPTCHA, MFA, security alert, unsafe upload/download, popup, or redirect returns `blocked_by_precondition` or `needs_user_takeover`; it never returns clean/success.

The adapter output is normalized and redacted before event/proof persistence. Raw cookies and authorization headers never enter the contract or proof payload.

## Gmail adapter boundary

`GmailAdapter` is an injected read-only protocol. It accepts a mailbox reference and correlation query only. Passwords, recovery settings, security changes, forwarding, and outbound mail are unsupported. Message matching requires engagement ID, recipient/mailbox reference, sender-domain allowlist, target origin, nonce, and time window. The parser strips active HTML, rejects attachments, quarantines prompt-injection content, and returns a short-lived artifact reference rather than the raw OTP or message body. Activation links are rechecked by Scope Compiler before browser navigation.

## Identity and workflow

Identity lifecycle is enforced as a finite state machine: `created -> signup_pending -> email_pending -> verified -> login_ready -> active -> quarantined -> revoked -> destroyed`. Transitions are idempotent and engagement-bound. Reuse across engagements, cross-identity cookie/token mixing, expired artifacts, and invalid transitions deny execution.

The local workflow harness will simulate signup/email activation/OTP/CSRF login/tenant and role transitions, delayed and duplicate mail, expired OTP, malicious mail content, out-of-scope links, private redirects, browser crash, and safe resume. It is a deterministic local contract harness, not a claim of live target qualification.

## Proof and autonomy

Every executed control-plane step emits a redacted runtime event and a proof reference. Only sealed bundles with causal signal, negative control, replay metadata, complete action chain, scope decision, and cleanup status can promote a finding. Missing capabilities become typed knowledge gaps and non-clean blocked results. No blocked or inconclusive workflow is reported as clean.

## Acceptance classification

Each item is classified as `implemented_and_runtime_proven`, `implemented_but_not_live_qualified`, `partially_implemented`, `design_only`, `blocked_by_missing_capability`, or `not_implemented`. The overall release remains an Advanced Candidate until browser/Gmail/workflow and live qualification gates are actually proven.

## Rollback note

All initial work is additive: new module(s), tests, docs, and optional runtime wiring. Existing legacy browser/auth paths remain unchanged until contract tests prove equivalent or safer behavior. If a focused gate fails, revert only the new files and their explicit registrations; do not weaken ActionAuthority, scope enforcement, or ProofBundle promotion.
