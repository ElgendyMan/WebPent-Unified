# UM-DR-38 — CI Verification Report

Generated: 2026-11-17T04:55:45.469765+00:00 — every gate below was RE-EXECUTED at the release commit by scripts/umdr38_deliverables.py; exit codes are recorded from the real processes, not from session memory or YAML presence.

Release commit: **b7b0b4fd77adf5374e756d7f72c4e27e04dc8460**

## Local gate execution (the same commands the root workflow runs)

| Gate | Exit code | Result |
|---|---|---|
| state-contract | 0 | **PASS** |
| orchestrator-construction-authority | 0 | **PASS** |
| isolation-denylist | 0 | **PASS** |
| vault-import-authority | 0 | **PASS** |
| test-count-floor | 0 | **PASS** |
| build-info-honesty | 0 | **PASS** |
| direct-io-inventory | 0 | **PASS** |
| ruff-ratchet | 0 | **PASS** |
| deps-cve-gate | 0 | **PASS** |
| secret-scan | 0 | **PASS** |
| bandit-high | 0 | **PASS** |
| coverage-ratchet | 0 | **PASS** |
| vip-audit-gap | 0 | **PASS** |
| test-evidence-check | 0 | **PASS** |
| evidence-contract-tests | 0 | **PASS** |
| instrumentation-tests | 0 | **PASS** |
| report-generator-tests | 0 | **PASS** |
| evidence-publication | 0 | **PASS** |
| structure-discovery-tests | 0 | **PASS** |

**19/19 gates PASS** (all green).

## Remote CI (GitHub Actions) — BLOCKED_EXTERNAL_DEPENDENCY

The canonical root workflow exists at `.github/workflows/ci.yml` (the only location GitHub discovers). The build environment holds no GitHub push credentials, so it cannot trigger a run on the release commit and NO GitHub run is claimed. To complete remote verification:

```bash
cd WebPent-Unified   # a clone of https://github.com/ElgendyMan/WebPent-Unified
git fetch origin && git checkout mission/umdr38-closure
git push -u origin mission/umdr38-closure
# then open the pull request against main; GitHub will run the root workflow on the exact pushed commit
```

The git bundle in this delivery carries the full mission/umdr38-closure history if the remote branch needs reconstruction: `git fetch WebPent_Unified_umdr38.bundle mission/umdr38-closure:mission/umdr38-closure`.
