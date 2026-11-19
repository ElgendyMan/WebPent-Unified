# UM-DR-36.2 Evidence Integrity Report

Generated 2026-11-16T05:24:44.894368+00:00.

## The accounting anomaly, solved from data

The 36.1 evidence recorded `collected 9141` vs `executed 9142`. The
decomposition (pinned as a test): 9,134 item outcomes + 7 setup-errored
items = 9,141 started = collected; the terminal summary's 9,142 adds
one module-level COLLECTION SKIP — a non-item report. Terminal skipped
12 = 11 item skips + 1 collection skip; errors 7 = 7 setup + 0 + 0.

## The v3 contract

`scripts/pytest_accounting_plugin.py` counts every report by hook
phase; `run_tests_with_evidence.py` (schema v3) loads it, cross-checks
the hook counts against the parsed terminal summary and fails closed on
any disagreement or violated invariant; `check_test_evidence.py`
requires the v3 block (backward-compatible with v2 records). 11 new
tests pin the model (`tests/test_umdr36_2_accounting_plugin.py`),
including a live pytest run containing every category (pass, fail,
skip, xfail, setup error, collection error, collection skip,
deselection).

## Provenance fields

source_commit, tree_clean, workflow identity when present, UTC
start/end, python/uv versions, lockfile SHA-256, exact command,
scope digest, outcome counts (v2 + v3), coverage, exit code. Stale
evidence is deleted before every run.
