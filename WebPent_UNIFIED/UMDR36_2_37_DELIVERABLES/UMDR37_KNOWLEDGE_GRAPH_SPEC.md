# UM-DR-37 Knowledge Graph Spec

Generated 2026-11-16T05:24:44.894368+00:00.

No new graph service was built (mission Part 16.2). The existing typed
layers carry the mission's relationship model:

- `models/attack_graph.py` — typed nodes (asset/identity/permission/
  privilege/state/resource/action/impact/object/workflow/endpoint/
  finding/hypothesis) with evidence-bearing edges (confidence string +
  evidence_refs).
- `appmodel` — the evidence-statused application spine (see the app
  model spec) with the frozen `to_attack_graph_projection()`.
- `knowledge/model_v2.py` — OBSERVED/INFERRED/VALIDATED/STALE/BLOCKED
  knowledge entities.
- `shared/attack_graph*.py` — deterministic, redacted projections.

Edges never confirm: the graph feeds hypothesis generation
(research/hypothesis_generator), the oracle lanes, and the funnel's
semantic stages (identity_relationships, object_ownership_relations —
honest 0s recorded when the crawl carries no ownership metadata).
