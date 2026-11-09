# IRTA v2 Start Baseline — Architecture Snapshot

## Repository state

The baseline was captured before IRTA v2 implementation. The repository HEAD, remote parity, tags, tracked-file count, and working-tree state are recorded in `repository_state.txt`.

## Existing assessment path

The current assessment path is layered: the Generic Core performs evidence-linked hypothesis generation, deterministic proposal planning, fail-closed decision control, and causal confirmation over proof/replay contracts. DCVU v1 adds disposable in-process target fixtures, a ground-truth registry, an offline campaign, and metrics. RTA v1 adds local loopback HTTP, SQLite-backed application behavior, synthetic authorization contexts, discovery, authenticated GET-only campaigns, redacted semantic observations, and causal validation.

## IRTA v2 boundary

IRTA v2 is additive. It will add independent target generation, adversarial mutations, a research-loop facade, clean evidence, stateful local workflow fixtures, difficulty-aware metrics, and memory-learning measurements. It must not alter existing validators, frozen ground truth, qualification gates, or the Generic Core with target-specific behavior.

## Baseline results

The baseline run recorded `2257 passed / 7 failed` in the full suite. Ruff passed and compileall passed. The seven failures are pre-existing governance/fixture blockers and are not treated as detection failures. The exact test output is preserved in `pytest.log`; exit codes are preserved in the `.exit` files.

The copied RTA report and metrics are historical inputs to this upgrade. They remain fixture-backed local evidence and do not constitute official P10, VIP, or production detection qualification.

## Safety invariants

All IRTA work remains local-only and disposable. No external target, real credential, login to an external service, destructive action, state-changing request against an external target, qualification promotion, or governance bypass is permitted.
