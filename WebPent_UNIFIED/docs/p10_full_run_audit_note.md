# P10 Full-Run Adapter Audit

Date: 2026-08-26

The existing `scripts/run_juice_shop_safe_inventory.py` is a metadata-only smoke/readiness runner. It emits `schema_version: p10.safe_inventory_smoke.v1`, sets `proof_bundle` and `metrics` to `null`, and is not a P10 proof runner.

The existing Juice Shop registry has 11 mapping-approved cases in the ground-truth artifact, but the source registry remains a safe candidate inventory. Only the typed-search case has a named workflow (`juice-shop-mat-search`) in the current browser runner. Navigate cases do not have production full-run workflow IDs or a centralized live ProofBundle adapter.

The existing oracle contracts are redaction-safe and explicitly distinguish observation proof from vulnerability proof. Several contracts require an approved challenge semantic and a negative control; an HTTP 2xx response alone is insufficient. The current prior run artifacts are XSS-only/partial and cannot be promoted.

Conclusion: full approved-set qualification cannot be honestly claimed yet. Any next implementation must add a bounded local-only adapter, explicit per-case workflow IDs, executed case IDs, redacted causal/negative-control records, sealed central ProofBundles, replay verification, and three isolated namespaces. The smoke runner must not be relabeled or reused as proof.
