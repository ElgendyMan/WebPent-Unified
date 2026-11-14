# Smart Autonomous Bug Hunter — Baseline Record

**Recorded:** 2026-08-18
**Working tree:** `/home/ubuntu/webpent_v60`

## Reproducible checks

| Check | Result |
|---|---:|
| `pytest --collect-only -q` | 633 tests collected |
| `PYTHONPATH=src .venv/bin/pytest -q` | 633 passed, 66 warnings, 23.36s |
| Git repository metadata | Not present in the working tree |
| Latest live WAPTLab result | 2 candidates, 0 confirmed |

## Integrity note

The current working tree does not reproduce the previously mentioned 654/655 test count. Existing local historical logs show lower intermediate counts and are not equivalent to the current baseline. No test-count increase or VIP qualification claim will be made until the exact missing revision is located or the tests are restored through an explicit, reviewed change.

## Known warnings

The test run reports development-mode warnings for the audit HMAC key and Celery payload key. These are warnings in the current local profile, not a reason to change production security defaults silently. Production qualification must require strong configured secrets and fail closed when they are absent.

## Live qualification limitation

The last live WAPTLab run produced two heuristic candidates and no confirmed finding. It must not be used as recall evidence. The next live run is blocked until the smart runtime reports capability blockers explicitly and the required campaign/workflow proof paths are available.
