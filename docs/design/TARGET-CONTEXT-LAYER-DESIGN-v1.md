# Generic Target Context Execution Layer v1

## Purpose

The Target Context Layer moves WebPent from readiness-only orchestration toward safe, reusable context-aware execution. It provides a target-neutral lifecycle for scope, synthetic identity metadata, in-memory session handles, disposable fixtures, capability leases, state snapshots, readiness checks, candidate/control separation, cleanup, and audit-safe serialization.

The layer does not perform transport, authentication, route selection, business-logic interpretation, or target-specific mutation. Those responsibilities remain in adapters and are invoked only by the existing execution authority.

## Generic Core contracts

`TargetScope` binds every context to an immutable target specification, campaign identifier, run identifier, origin, and scope digest. `IdentityContext` contains only non-secret synthetic references and bounded metadata. `SessionHandle` is opaque metadata for an in-memory session and rejects persistent material. `FixtureRequest`, `FixtureHandle`, and `SnapshotHandle` require disposable, hashable state. `ReadinessResult`, `RestoreResult`, and `DisposalResult` preserve typed lifecycle outcomes instead of collapsing every failure into `LAB_NOT_READY`.

`ContextProvider`, `SessionProvider`, and `FixtureProvider` are protocols. The core coordinates their lifecycle but does not know WebGoat, crAPI, Juice Shop, routes, selectors, credentials, cookies, tokens, or response bodies.

## Capability and scope policy

`CapabilityPolicy` issues a short-lived lease only when every requested capability is explicitly allowed. The policy has no default permission and rejects credential use, token generation, external network/callbacks, authentication bypass, state mutation, and destructive actions. Lease revocation is represented in the stored lease and makes an existing `ExecutionContext` non-ready immediately.

The coordinator also checks provider-declared capabilities, target scope, lease validity, session readiness, and fixture readiness before returning a usable context. Missing or invalid context is a typed block and cannot reach `ActionAuthority`.

## Lifecycle

When the context-aware path is enabled, `CampaignExecutor` follows this sequence:

```text
planned
→ context acquisition
→ capability lease
→ readiness
→ snapshot
→ authority authorization
→ handler/baseline/candidate/control work
→ restore
→ dispose
→ completed or blocked
```

The handler receives the normal `CampaignTask` through the existing compatibility path. A context-aware caller may additionally provide `context_handler(task, execution_context)`. Existing callers that do not enable the layer keep their current behavior.

Duplicate idempotency detection disposes an already-acquired context before returning `STOPPED`; this prevents an acquired lease or synthetic session from surviving a duplicate request.

## Adapter boundary

The Mock adapter is deterministic and offline. It covers ready, blocked, restore failure, cleanup failure, synthetic session, disposable fixture, snapshot, and negative-control isolation paths.

The WebGoat adapter maps LessonSession and lesson fixture metadata only. It performs no network operation in the generic context provider. The crAPI adapter maps requester/owner/object metadata and remains offline-only; it does not perform live authentication, token generation, or application mutation.

## Evidence and redaction boundary

The context layer serializes references, roles, hashes, statuses, and bounded metadata only. It rejects secret-shaped identity metadata and never accepts raw credentials, cookies, tokens, authorization headers, or response bodies. Proof promotion remains governed by the existing causal oracle, negative control, sealed ProofBundle, verification, and replay contracts; context readiness alone is never a vulnerability finding.

## Governance state

This milestone does not modify frozen Ground Truth, P10/VIP thresholds, official run authorization, human signoff state, or Bug Bounty scope. B2.1 remains limited to the separately approved WebGoat loopback attempt. crAPI remains offline-only unless a new owner decision explicitly authorizes additional state or authentication operations.

## Verification obligations

The implementation is accepted only when targeted context tests, existing CampaignExecutor regressions, target adapter lifecycle tests, Ruff, compile checks, direct-I/O and neutrality checks, secret scans, governance validators, manifest validation, and provenance validation pass. Any live B2.1 result must distinguish `CONFIRMED`, `ORACLE_INCONCLUSIVE`, `SESSION_UNAVAILABLE`, `FIXTURE_UNAVAILABLE`, and `PRECONDITION_BLOCKED`; blocked or inconclusive observations are not scoring evidence.
