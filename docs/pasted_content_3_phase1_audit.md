# pasted_content_3 — Phase 1 Audit

## Baseline

The repository already had the central `ActionAuthority`/`ActionExecutor` execution plane, G-02 adapter metadata, engagement isolation, ProofBundle storage, workflow replay foundations, and typed runtime capability gaps. The missing layer was a cohesive control-plane contract tying scope, identity, browser/email boundaries, workflow replay, secret references, and proof sealing together.

## Existing reusable paths

| Existing capability | Reused through |
|---|---|
| Scope and origin policy | `webpent.shared.engagement_scope` and the new typed scope compiler |
| Central execution and policy | `ActionAuthority`, `ActionExecutor`, `AdapterRegistry`, G-02 contract |
| Engagement isolation | runtime engagement IDs, proof store, identity/tenant graph |
| Workflow replay | existing replay/reauth foundations plus typed control-plane state machine |
| Proof and promotion | existing `ProofBundle` model/store plus strict control-plane proof input |
| Runtime checkpointing | `RuntimeContext.descriptor()` and descriptor-only reconstruction |

## Gaps addressed

The audit identified the need for explicit wildcard and path ambiguity rejection, injected DNS/rebinding policy, typed identity lifecycle and tenant object binding, opaque short-lived secret references, read-only Gmail semantics, browser session/action boundaries, idempotent workflow resume, and a single replay path through the central executor. These were implemented in `control_plane.py`, `control_plane_runtime.py`, `control_plane_spine.py`, and `secret_vault.py`, with runtime bootstrap and state wiring kept optional/additive.

## Non-goals preserved

No lab was started. No external target was contacted. No direct browser, Gmail, socket, subprocess, or raw-client fallback was introduced. No missing validator was promoted, and no confirmation can be produced without causal signal, negative control, scope decision, and sealed ProofBundle.
