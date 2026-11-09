# Core Target Context Layer — Failure Diagnosis v1

## Scope

This report covers the generic Target Context/Session/Fixture milestone authorized in `pasted_content.txt`. It does not open Official P10, Bug Bounty, external targets, or qualification gates.

## Diagnosis matrix

| Failure or blocker | Evidence | Classification | Action | Result |
|---|---|---|---|---|
| No generic abstraction for target context, synthetic session metadata, disposable fixtures, and snapshot/restore | Pre-change B2.1 had target-local readiness blockers and no reusable lifecycle contract | Generic-core design gap | Added typed contracts, capability leases, scope binding, coordinator lifecycle, and typed statuses | Fixed in the core; covered by regression tests |
| Lease remained apparently active after disposal | Regression exposed that registry revocation did not invalidate the lease object held by `ExecutionContext` | Generic-core lifecycle bug | Revocation now mutates both registry state and the held lease handle | Fixed; disposal now makes the context not ready |
| Fixture failure could leave a previously created synthetic session | Failure path in acquisition did not always revoke prior session state | Generic-core cleanup bug | Fixture failure path revokes session and capability lease before returning | Fixed; regression coverage added |
| Mock provider triggered a direct-I/O inventory finding through a dynamic import | G-02 inventory identified a dynamic import in the deterministic mock provider | Generic implementation hygiene issue | Replaced the dynamic import with a static import | Fixed; inventory regenerated and G-02 rechecked |
| Juice Shop had no Context Provider wrapper for cross-target lifecycle regression | Juice Shop package contained target adapter logic but no context provider | Adapter coverage gap | Added offline-only Juice Shop provider, synthetic session wrapper, fixture wrapper, and loopback scope | Fixed; lifecycle test passes |
| WebGoat IDOR live oracle remained inconclusive | Three GET observations had identical 302 redirect semantics for baseline, candidate, and negative control | Target-local semantic blocker, not core failure | Kept the case `INCONCLUSIVE`; no scoring ProofBundle created | Correctly unresolved; requires a separately safe, approved session/fixture route or remains blocked |
| crAPI object-access fixture injection remained unavailable | No safe requester/owner injection and reset path was proven | Target-local precondition blocker | Kept the case `BLOCKED`; no request was sent | Correctly unresolved |
| Four historical approval/provenance tests still fail closed | The original Option B import points to an attachment path whose current contents have changed; original raw approval text is not persisted | Historical provenance drift, not a Core regression | Did not weaken validator, rewrite history, or change the old approval record | Deliberately unresolved and reported; requires the original source artifact or a new explicit import record |

## Core-vs-target decision

The Target Context lifecycle issues were generic because the same contracts and cleanup invariants apply to Mock, Juice Shop, WebGoat, and crAPI. They were fixed in the Generic Core and validated on more than two target abstractions. The WebGoat and crAPI semantic blockers remain inside their adapters and target-specific evidence; they were not moved into the core and were not reclassified as failures of the generic layer.

## Safety outcome

The new layer accepts typed metadata only. It rejects forbidden capabilities such as credentials, token generation, external network, auth bypass, state mutation, and destructive action. Session handles are marked in-memory-only, target scope binds target spec/campaign/run, candidate and negative-control scopes remain distinct, and disposal revokes the capability lease. No raw cookies, tokens, credentials, headers, or response bodies were added to the repository.

## Qualification boundary

This diagnosis is an engineering review, not a detection-quality or qualification claim. `official_isolated_p10_runs_authorized=false`, `P10=NOT_QUALIFIED`, `P9=NOT_QUALIFIED`, `VIP=NOT_QUALIFIED`, and `Bug Bounty=BLOCKED` remain unchanged.
