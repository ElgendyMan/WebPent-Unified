# Core Target Context Layer — Before/After Comparison v1

## Comparison scope

The comparison covers the Generic Target Context milestone only. It does not treat blocked or inconclusive target cases as detection successes or failures.

| Dimension | Before | After | Assessment |
|---|---|---|---|
| Target context contract | No reusable generic contract for context acquisition and disposal | `target_context.v1` contracts for scope, identity metadata, session, fixture, snapshot, lease, readiness, restore, and disposal | Improved |
| Capability enforcement | Authorization existed for actions, but no context-scoped capability lease | Fail-closed `CapabilityPolicy` issues scoped leases with no default forbidden permissions | Improved |
| Target binding | Context metadata was not enforced as a first-class lifecycle object | Every context is bound to TargetSpec, campaign ID, run ID, origin, and scope digest | Improved |
| Synthetic identity/session | Target-specific readiness work lacked a reusable in-memory abstraction | `SessionProvider` and `SessionHandle` support synthetic metadata only and explicit revocation | Improved |
| Fixture lifecycle | No common provision/snapshot/restore/dispose contract | `FixtureProvider` exposes deterministic disposable lifecycle and state hashes | Improved |
| Candidate/control separation | Separation was handled per test or runner | `ContextRole` and distinct scope keys make candidate, baseline, and negative-control contexts traceable and separate | Improved |
| Cleanup safety | Session/lease cleanup could be missed on fixture failure; disposal did not invalidate held lease state | Failure paths revoke prior session/lease state; disposal invalidates the held lease and reports cleanup failures | Fixed and regression-tested |
| Orchestrator integration | Campaign execution could run without context lifecycle | Context-enabled execution requires a `ContextRequest`, acquires context, snapshots, restores, disposes, and blocks safely when unavailable | Improved while preserving legacy compatibility |
| Mock coverage | Partial local fixture behavior | Ready, blocked, expired lease, missing session, restore failure, cleanup failure, and isolation variants | Improved |
| Multi-target adapter coverage | WebGoat/crAPI context behavior was not represented by one common contract; Juice Shop lacked a provider wrapper | WebGoat, crAPI, Mock, and Juice Shop expose target-local offline providers over the same generic contract | Improved |
| G-02 direct-I/O hygiene | New dynamic import was flagged by inventory | Static import used; inventory regenerated | Fixed |
| WebGoat causal quality | B2.1 produced three identical 302 observations and an inconclusive oracle | Same target evidence remains correctly `INCONCLUSIVE`; no false promotion | No detection-quality gain claimed |
| crAPI causal quality | No safe requester/owner fixture injection | Still `BLOCKED`; no unsafe live flow added | No detection-quality gain claimed |
| ProofBundle scoring evidence | No valid causal evidence for these cases | Still zero sealed scoring bundles because the oracle is not conclusive | Correct fail-closed behavior |

## Same-condition result

The core change improves the reusable execution boundary and diagnostics, but it does not manufacture target semantics. Re-running the existing B2.1 WebGoat flow under the new layer still yields an inconclusive result, while crAPI remains blocked. That is the expected same-condition result: the generic blocker is addressed, and the remaining blockers are target-local and authorization-dependent.

## Measured regression evidence

The context and target lifecycle regression set passes **39 tests** across Mock, Juice Shop, WebGoat, crAPI, and CampaignExecutor. Ruff and compileall pass for the changed implementation and tests. The broader suite still has the previously documented historical approval/provenance drift failures; those remain fail-closed and are not hidden or converted into a false green result.

## Interpretation

The milestone is a successful **engineering capability improvement** and a stronger foundation for autonomous causal execution. It is not evidence of confirmed WebGoat or crAPI vulnerabilities, not a quality metric, not a P10 run, and not VIP qualification.
