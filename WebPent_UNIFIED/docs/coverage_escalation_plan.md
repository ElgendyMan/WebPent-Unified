# Coverage Escalation Plan

## Current measured coverage

The v95 quality gate was run with the full test suite and no lab runtime:

```text
PYTHONPATH=src .venv/bin/pytest --cov=webpent --cov-report=term-missing
1138 passed, 207 warnings
TOTAL 25221 7713 69%
```

The repository previously enforced only `--cov-fail-under=35` in CI. That threshold was materially below the measured coverage and could not detect a meaningful regression.

## Current CI gate

The CI threshold is now **66%**. This is three percentage points below the measured 69% and therefore leaves a controlled margin for normal test-environment variation while preventing a substantial coverage regression.

## Progressive release targets

| Release stage | Minimum coverage | Required action |
|---|---:|---|
| v95 current | 66% | Keep the full suite green and prevent regression below the measured margin. |
| Next release | 71% | Add tests around the weakest recon adapters and worker paths before raising the gate. |
| Following release | 76% | Expand contract tests for external-tool adapters and persistence error paths. |
| Following release | 81% | Add integration-safe tests for API, worker, and report export boundaries. |
| Long-term floor | 65% | The security automation project must never ship below this floor. |

Targets are staged because the current measured value is 69%; the next target must be reached by tests before the CI threshold is raised. Each increase should be accompanied by a fresh `--cov-report=term-missing` artifact and a review of the lowest-covered modules.

## Weakest measured surfaces

The current report identified the following low-coverage areas to prioritize, without weakening safety guards or invoking a live lab:

| Module family | Approximate coverage | Test priority |
|---|---:|---|
| `tools/recon/httpx.py` | 18% | Adapter parsing, timeout, and subprocess failure contracts. |
| `tools/recon/katana.py` | 16% | Bounded command construction and empty/error output handling. |
| `workers/pentest_worker.py` | 27% | Persistence failures, cleanup, and fail-closed state transitions. |
| `tools/recon/subfinder.py` | 26% | Scope filtering and tool-unavailable fallback behavior. |

All future coverage work must remain offline or fixture-backed unless a separately authorized lab run is explicitly requested. Coverage is a quality signal, not evidence that a vulnerability was discovered or confirmed.
