# v97 Recon Behavioral Coverage

**Timestamp:** 2026-08-23 UTC

## Scope

This phase adds behavioral tests for the existing recon wrappers and the worker graph-state helper. The tests do not invoke external targets or real binaries; subprocesses and scope decisions are controlled with local fakes. No WAPTLab runtime or source was modified.

## Covered behavior

| Component | Behavioral cases |
|---|---|
| `katana` | JSONL endpoint extraction, malformed records, duplicate-safe output, off-scope and malformed-host dropping, seed scope refusal before subprocess, partial output after timeout, and non-timeout error propagation |
| `httpx` | scope filtering before subprocess, JSONL parsing with malformed/non-object records skipped, partial output after timeout, empty output classification, and non-timeout error propagation |
| `subfinder` | order-preserving deduplication, empty output classification, partial output after timeout, and non-timeout error propagation |
| `pentest_worker` | graph state distinction between pending, completed, running/paused-at-sandbox states |

## Verification

```text
Test command:
PYTHONPATH=src:/tmp/webpent-release-run/bbscout/src .venv/bin/pytest -q tests/test_v97_recon_behavior.py --cov=webpent.tools.recon.katana --cov=webpent.tools.recon.httpx --cov=webpent.tools.recon.subfinder --cov-report=term-missing

Result: 15 passed, exit 0

Coverage:
httpx.py       92%
katana.py     83%
subfinder.py  91%
Selected recon core total: 87%

Ruff: exit 0, All checks passed
Compileall: exit 0
```

The raw output is stored alongside this note. Coverage percentages are behavioral measurements for the selected wrappers, not a claim that the complete worker module is covered.
