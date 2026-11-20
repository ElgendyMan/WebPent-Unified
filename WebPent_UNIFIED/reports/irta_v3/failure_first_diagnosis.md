# IRTA v3 Failure-First Diagnosis

## Scope

This record was created before remediation. No legacy validator, frozen ground truth, threshold, or official governance state was changed.

## Observed failures

| Area | Failures | Classification | Initial cause |
|---|---:|---|---|
| G-02 inventory | 4 | Repository-artifact drift | Current source scan and checked-in deterministic inventory disagree after additive IRTA v3 files were added. |
| Option B approval boundary | 1 direct assertion plus 3 runner failures | Preserved fail-closed blocker | Approval source hash no longer matches the packet; the runner correctly refuses to continue. |
| WebGoat/crAPI provenance | 2 | Environment/readiness blocker | Required target source/runtime attestations are not available or do not match the pinned evidence. |
| Source-backed inventory | 1 | Environment blocker | `/tmp/juice-shop-source/data/static/challenges.yml` is absent. |

## Safety interpretation

These failures are not detection false negatives. They are artifact-integrity, provenance, or precondition failures. They remain blocked and are excluded from TP/FP/FN scoring. The existing failure record is preserved in `g02_failure_diagnosis.txt` and `legacy_failure_diagnosis.txt`.

## Safe remediation boundary

The only potentially safe remediation is regeneration of derived, deterministic audit artifacts after proving that the source change is additive and the artifact generator is authoritative. Approval hashes, frozen target evidence, external source attestations, and missing lab fixtures must not be rewritten to make tests pass. If remediation would require any of those actions, the correct outcome is BLOCKED and an owner decision packet is required.

## IRTA v3 impact

The new v3 focused suite passes independently. Full-suite status is currently red because of the preserved blockers above; this is recorded honestly and will not be converted to a pass by weakening checks.
