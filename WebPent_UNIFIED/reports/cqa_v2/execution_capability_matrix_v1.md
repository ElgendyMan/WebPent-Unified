# Execution Capability Matrix v1
## Phase 14 — Gap Analysis

| Security Semantic | Current Execution | Required Execution | Status | Evidence |
|-------------------|-------------------|--------------------|--------|----------|
| Object authorization | single GET with global identity | single GET with specific actor identity | ⚠️ GAP | target-beta-case-01 requires non-member actor |
| Role authorization | single GET with default role | single GET with specific low-privilege role | ⚠️ GAP | target-gamma-case-01 requires viewer role (not admin) |
| Tenant isolation | single GET without tenant propagation | single GET with X-Tenant header propagation | ⚠️ GAP | target-delta-case-01 requires cross-tenant header |
| Partial access | single GET | single GET | ✅ ADEQUATE | Currently sufficient for pilot cases |
| Workflow ordering | single GET | multi-step stateful sequence | ⚠️ GAP | pilot-epsilon-case-01 requires workflow state transition |
| Business logic invariant | single GET | stateful sequence | ❓ UNVERIFIED | Not tested in pilot set |
| Replay | current target rebuild | same semantic sequence | ✅ ADEQUATE | Works for single-step cases |
| Negative control | controlled comparison | same-context comparison | ⚠️ GAP | Control must use same ActorContext as candidate |

## Critical Finding

**3 out of 3 FN cases** are caused by the same execution capability gap:
**Lack of explicit ActorContext propagation from CaseExecutionSpec through CandidateExecutionLayer.**

The current execution layer uses a hardcoded global identity, which means:
- Cross-tenant cases cannot be exercised (tenant header missing)
- Role escalation cases cannot be exercised (always runs as admin/high-privilege)
- Non-member access cases cannot be exercised (always runs as authorized member)

## Required Extension

**Proven capability required:** ActorContext propagation
- actor identity
- tenant context
- role/privilege level
- authorization headers (X-Tenant, X-Actor-Role, etc.)

**NOT yet proven required (but identified as gap):**
- Multi-step workflow sequences (pilot-epsilon-case-01 suggests this)
- State snapshots / reset strategies

## Decision

Proceed with **Phase 14.1 — ActorContext Execution-Capability Repair**.
This is an ADDITIVE extension only. No changes to:
- Ground truth
- Labels
- Thresholds
- Causal predicates
- Proof requirements
- Historical evidence
