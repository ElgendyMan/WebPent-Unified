# CQA v1 Execution Layer — Failure-First Record

The first focused verification of `tests/cqa/test_execution.py` failed three tests before any network request. The failure was an additive integration mismatch: the existing IRTA v3 `build_independent_targets` API accepts keyword-only configuration and does not accept a positional count argument. Ruff and compileall passed.

No legacy validator, threshold, frozen ground truth, historical report, or expected metric was changed. The safe remediation boundary is limited to adapting the new CQA tests to the existing public target-factory API; the execution layer itself must remain generic and local-only.

Observed result: `3 failed`, `Ruff passed`, `compileall passed`.

A second focused verification failure occurred in one assertion because the new test used paths from the generic IRTA v2 fixture instead of the IRTA v3 target's actual base path and route contract. The request itself was safely local and read-only; Ruff and compileall remained passing. The safe remediation is test-only path alignment using the runtime's exposed `base_path`, with no target-specific logic added to the execution layer.

Observed result: `1 failed, 2 passed`, `Ruff passed`, `compileall passed`.

The first truth-isolation scan was intentionally conservative but too broad: searching for the generic token `"label"` matched unrelated legacy data-model and template fields. No `target_owner` or `truth.json` leakage was established. The correction is limited to narrowing the scan to owner-package identifiers and truth-file references; no source code or validator changes are needed.
