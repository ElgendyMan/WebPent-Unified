# Execution Capability Matrix v2
## After Phase 14.1 — ActorContext Repair

| Security Semantic | Current Execution | Required Execution | Status |
|-------------------|-------------------|--------------------|--------|
| Object authorization | single GET with explicit ActorContext | single GET with specific actor identity | ✅ RESOLVED |
| Role authorization | single GET with explicit role from ActorContext | single GET with specific low-privilege role | ✅ RESOLVED |
| Tenant isolation | single GET with X-Tenant header from ActorContext | single GET with tenant propagation | ✅ RESOLVED |
| Partial access | single GET with ActorContext | single GET | ✅ ADEQUATE |
| Workflow ordering | single GET only | multi-step stateful sequence | ⚠️ GAP — EXECUTION_CAPABILITY_INSUFFICIENT |
| Business logic invariant | single GET only | stateful sequence | ❓ UNVERIFIED |
| Replay | same ActorContext reproducible | same semantic sequence | ✅ ADEQUATE |
| Negative control | same ActorContext for candidate AND control | same-context comparison | ✅ RESOLVED |

## Changes from v1
- ActorContext model added to CaseExecutionSpec
- Hardcoded global identity REMOVED from CandidateExecutionLayer
- Context propagated explicitly through provenance-traceable field
- Same ActorContext now used for both candidate and negative control (critical for valid causal comparison)

## Remaining Gaps
- Multi-step workflow sequences (pilot-epsilon-case-01)
- State snapshots / reset strategies for stateful fixtures
- These are NOT addressed in Phase 14.1 and remain classified as EXECUTION_CAPABILITY_INSUFFICIENT
