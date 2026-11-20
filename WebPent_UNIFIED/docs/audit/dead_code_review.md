# Dead Code and Placeholder Review

The audit scanner searched source and tests for `TODO`, `FIXME`, `NotImplemented`, and standalone `pass`. It found marker-bearing files, which are recorded in `reports/audit/architecture_scan.json`. A marker is not automatically dead code: exception guards, abstract hooks, intentionally deferred adapters, and test placeholders require semantic review.

| Classification | Decision |
|---|---|
| Intentional placeholder or abstract hook | Accept temporarily and document owner/entry condition |
| Missing implementation on an enabled path | Raise a separate bug ticket; do not silently fill during audit |
| Dead or unreachable code | Document and remove only in a separately approved cleanup change |
| Legacy blocker or unavailable local dependency | Preserve as a failing regression and record the exact prerequisite |

No module, test, historical artifact, validator, or ground-truth file was deleted as part of this audit. The seven full-suite failures remain preserved and are treated as local-lab/attestation blockers rather than dead code.
