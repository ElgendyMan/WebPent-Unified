# TEAM1 Rabbit-Hole Proof

**Document ID:** TEAM1-RABBITHOLE-PROOF-1.0
**Date:** 2026-09-10
**Proof type:** deterministic offline trace (`tests/test_team1_research_entity.py::test_rabbit_hole_trace_signal_to_causal_attempt`). No mock LLM used as proof of autonomous execution.

## Trace proven (5 steps, asserted in order)

| Step | Event | Evidence |
|---|---|---|
| 1 | initial critical signal ingested | `AgendaBridge.ingest(high signal)` → branch created, `priority > 0` |
| 2 | bounded research budget allocated | `branch.experiments_allocated >= 1` (finite, capped) |
| 3 | new observation → hypothesis update (no duplicate branch) | second signal same hypothesis → `len(branches)==1` (merged, not duplicated) |
| 4 | follow-up experiment selected through canonical loop | `EvidenceAwareAgentLoop.evaluate(agenda_bridge=...)` → `selected_task_id.startswith("agenda::")` (agenda changed selection) |
| 5 | causal validation attempt gated by central authority | `central_proof_verified=False` → `stop_reason == "central_verification_required"` (CausalGuard path still controls; rabbit-hole cannot self-confirm) |

## Semantics verified

- Priority **increases** on critical signal (not merely numeric — re-orders experiment selection).
- **Additional exploration** occurs via new agenda branch/experiment.
- **New observation** feeds back into same WorldModel/agenda (single store).
- **Hypothesis update** merges same-hypothesis signals (no branch explosion).
- **Follow-up experiment** is selected through the canonical loop (single entity).
- **Causal validation attempt** is always gated; nothing in the rabbit-hole path CONFIRMS a finding.
- Termination conditions: confirmed/disproven/blocked/budget-exhausted — budget exhaustion → `SAFE_STOP` (`test_budget_exhaustion_safe_stop`).

## What is NOT proven (Team-2)

- Real-LLM hypothesis generation inside the rabbit-hole loop (requires provider keys).
- Real-target observation feedback (requires authorized local target).
