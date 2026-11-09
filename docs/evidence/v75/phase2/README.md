# v75 Phase 2 — Typed WorkflowObservation Surface Normalization

## Change

`smart_campaigns` now safely normalizes mapping-like observation models that expose `model_dump(mode="json")`. This preserves typed `WorkflowObservation` records when they arrive in graph state, allowing the existing planner to match only the explicitly observed same-origin URL. Strings and ordinary mappings retain their previous behavior.

The normalization is passive and bounded. It does not create routes, perform transport, broaden scope, or promote a candidate. A model that cannot be safely dumped is ignored fail-closed.

## Evidence

- Regression: `test_typed_workflow_observation_becomes_observed_surface_task` passed.
- Smart-campaigns and campaign-registry tests: `35 passed`.
- Ruff: passed.
- `compileall`: passed.
- `git diff --check`: passed.

## Security/qualification boundary

The regression verifies task materialization only. It does not assert a vulnerability, causal signal, negative control, proof bundle, or confirmation. The VIP/75% qualification gate remains unchanged.
