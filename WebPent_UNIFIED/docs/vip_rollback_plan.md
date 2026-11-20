# WebPent VIP Rollback and Recovery Plan

## Preconditions

Rollback is a release operation, not an emergency way to bypass evidence gates. Record the current commit, manifest hash, artifact SHA256, database migration head, and engagement identifier before changing anything.

## Application rollback

1. Stop new scans through the normal operator control plane.
2. Preserve redacted logs, checkpoints, ledger rows, and the release manifest.
3. Revert to the last approved commit using Git, never by copying arbitrary files over the working tree.
4. Re-run `git diff --check`, the full test suite, Ruff, `compileall`, and `verify_all.py`.
5. Rebuild the manifest and compare the expected release decision before resuming scans.

## Data rollback

SQLite migrations must be backward-compatible. Do not delete findings or evidence to hide a regression. Restore the database from an operator-managed backup and run migrations in the documented direction; if a migration is irreversible, stop and request manual review.

## Evidence safety

Keep the pre-rollback ProofBundle and ledger entries immutable. A rollback must not turn a prior `Tool-Confirmed` result into an untraceable record. If a replay becomes impossible after rollback, downgrade the current assessment to `Needs Human Review` and explain why; never synthesize replacement evidence.

## Credential and connector response

If auth/vault integrity is uncertain, revoke or reseal credentials through the approved vault path. Do not print cookies, tokens, passwords, or API keys in logs. Disable the affected connector rather than retrying blindly.

## Recovery acceptance

Recovery is accepted only after all local release gates pass, manifest hashes match, redaction checks pass, and a deterministic offline regression suite confirms that scope denial, destructive denial, idempotency, negative controls, and report separation still hold.

## Current-cycle boundary

This document is a local operational artifact. No rollback, deployment, or live target action was performed against WAPTLab in the current cycle.
