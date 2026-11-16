# UM-DR-36.2 Acceptance Report

Generated 2026-11-16T05:24:44.894368+00:00.

| Gate | Status | Proof |
|---|---|---|
| G36-01 baseline verified | PASS | UMDR36_2_BASELINE.json (git facts) |
| G36-02 sources reconciled | PASS | UMDR36_2_RECOVERY_AUDIT.md |
| G36-03 portable restore | PASS | performed live after the sandbox recycle |
| G36-04 dependency integrity | PASS | uv lock/sync/pip-check |
| G36-05 frozen manifest | PASS | 647/647 gate tests |
| G36-06 BUILD_INFO provenance | PASS | verifier version_consistency |
| G36-07 accounting consistency | PASS | v3 plugin + 11 tests |
| G36-08 current-run evidence | PENDING | v3 suite executing at generation |
| G36-09 identity invariants | PASS | chain finding_id + verifier |
| G36-10 suite honestly classified | PASS | failures recorded, not silenced |
| G36-11 CI | BLOCKED | no GitHub credentials (bundle provided) |

**Phase state: PARTIALLY_VERIFIED** (G36-08 pending the running suite;
G36-11 externally blocked). Environmental failures do not block the
independent UM-DR-37 work, exactly as the mission allows.
