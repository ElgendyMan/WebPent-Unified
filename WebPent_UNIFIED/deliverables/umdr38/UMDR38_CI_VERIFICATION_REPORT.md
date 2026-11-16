# UM-DR-38 — CI Verification Report

Generated: 2026-11-16T08:07:27.564772+00:00 — every gate below was RE-EXECUTED at the release commit by scripts/umdr38_deliverables.py; exit codes are recorded from the real processes, not from session memory or YAML presence.

Release commit: **471d5e1febadbf6bbc8b4b35c30c6e6ef870a6ce**

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
| ruff-ratchet | 1 | **FAIL** —     python scripts/check_ruff_ratchet.py --update-baseline --reason "..." |
| deps-cve-gate | 0 | **PASS** |
| secret-scan | 0 | **PASS** |
| bandit-high | 0 | **PASS** |
| coverage-ratchet | 0 | **PASS** |
| vip-audit-gap | 0 | **PASS** |

**12/13 gates PASS** — failing gates: ruff-ratchet

## Remote CI (GitHub Actions) — BLOCKED_EXTERNAL_DEPENDENCY

The canonical root workflow exists at `.github/workflows/ci.yml` (the only location GitHub discovers). The build environment holds no GitHub push credentials, so it cannot trigger a run on the release commit and NO GitHub run is claimed. To complete remote verification:

```bash
cd WebPent-Unified   # a clone of https://github.com/ElgendyMan/WebPent-Unified
git fetch origin && git checkout mission/umdr38-closure
git push -u origin mission/umdr38-closure
# then open the pull request against main; GitHub will run the root workflow on the exact pushed commit
```

The git bundle in this delivery carries the full mission/umdr38-closure history if the remote branch needs reconstruction: `git fetch WebPent_Unified_umdr38.bundle mission/umdr38-closure:mission/umdr38-closure`.
