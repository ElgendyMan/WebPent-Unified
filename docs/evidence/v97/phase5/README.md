# v97 Phase 5 — Campaign validator mapping correction

## Scope

This phase corrected the declarative WAPTLab campaign policy after three bounded local qualification runs showed that several vertical campaigns were being classified as `missing-validator` even though they reused registered deterministic base validators.

The change is limited to the source policy and regression contracts. It does not add target-specific bypasses, provider I/O, credentials, or automatic finding confirmation.

## Decision

`download_idor` and `tenant_context_switching` now reuse the registered `idor` validator. `public_backup_disclosure`, `laravel_app_debug`, and `public_elasticsearch_exposure` now reuse the registered `info_disclosure` validator. `elasticsearch_snapshot_traversal` and `xslt_injection` remain `missing-validator`/human-review-only because no deterministic live validator contract is registered for them.

A campaign status of `not_observed` or `tested` is coverage/planning state only. It is not a vulnerability confirmation. Strict confirmation still requires target-backed causal evidence, an independent negative control, and a sealed/replayable ProofBundle.

## Verification

The policy, planner, plugin registry, and contract-only WAPTLab regression tests pass. The regenerated contract-only artifact reports 20 campaigns with 18 `inconclusive` and 2 `missing-validator`, with `target_contacted=false` and `waptlab_modified=false`.

The complete project regression must still be run before release. Live WAPTLab qualification remains a separate bounded operation and must be re-run after this policy change; prior rounds are not reused as evidence for the new source state.
