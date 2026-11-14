# pasted_content_3 requirements snapshot

## Local requirements to verify
- Typed EngagementScope, IdentityProfileRef, BrowserSessionRef, WorkflowStep, EmailEvent.
- Wildcard scope is HTTPS/443 by default, apex denied for wildcard, IDNA normalization, userinfo/encoded ambiguity denied, redirects/DNS/private ranges fail closed, control-plane exceptions do not count as attack surface.
- One execution plane: Browser/Gmail/API actions must be typed ActionRequest operations and pass ActionAuthority/ActionExecutor; no direct graph-node I/O.
- Gmail is read-only or user-controlled, no password/raw OTP/message body in state/logs/reports; nonce/time/origin correlation, quarantine and safe parsing.
- Identity lifecycle and engagement isolation; opaque short-lived vault refs.
- Workflow replay/resume, tenant/role differential contracts, KnowledgeGap/NBA/AutonomousController wiring.
- ProofBundle promotion requires scope, action chain, redacted evidence, before/after, oracle, negative control, replay recipe, hashes, timestamp, engagement, seal.
- Security: auth/CSRF/tenant authorization, TTL cleanup, fail-closed SSRF, rate/budget/circuit controls, kill switch, no arbitrary LLM escalation.
- Required local harness/failure paths; live browser/Gmail and WAPTLab qualification remain separate environment-dependent gates.

## Classification rule
Items are classified as runtime-proven, implemented-not-live-qualified, partially implemented, design-only, blocked by capability, or not implemented. No live qualification or confirmed finding is claimed without live causal evidence, negative control, and sealed ProofBundle.
