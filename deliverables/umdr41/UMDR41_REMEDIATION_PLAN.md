# UMDR41 Remediation Plan (remaining work, priority order)
## P0 — owner actions blocking release integrity
1. F-001/F-012: push mission commits containing fe92f17/ccb4aea/bafe618 OR regenerate BUILD_INFO from a reachable commit via the existing re-baseline tooling (scripts pattern from UM-DR-38 exists: build_release_archive + check_build_info_honesty). Never hand-edit the numbers.
2. F-008 G-08: per-site decisions for the 49 expired approvals (triage artifact G08_EXPIRED_APPROVALS_TRIAGE.json): (a) migrate raw httpx sites to shared/http boundary where the wrapper reason permits, (b) security-owner reapproval with new expiry for still-required exceptions (record new approved_by), (c) never bulk-extend dates, never weaken test_no_expired_approvals.
## P1 — engineering (next branch window)
3. DONE (follow-up window): F-014 — G-08 isolated into its own CI job (g08-inventory); checkout/setup-uv/upload-artifact pinned to commit SHAs resolved from upstream tags (SHAs recorded as comments).
4. DONE (follow-up window): F-010 — subfinder@v2.17.0, httpx@v1.12.0, katana@v1.8.0 pinned from the official repositories' release tags. REMAINING: a tool-version manifest + verify step in the image build (owner rebuild required).
5. Orphan retirement (F-013): module-by-module positive-evidence review of the 95 candidates (start with whole trees: irta (16), dom_xss (4), sourcemap_analysis (3), role_matrix (2)); archive not delete; one tree per commit with before/after test evidence.
6. God-object decomposition: validator/agent.py (4,948 lines, _validate_with_tool 1,393 lines) first — extract per-family validators behind the existing dispatch; settings.py (3,324) split by domain only if a natural seam appears. No line-count targets.
## P2 — capability
7. DONE (follow-up window): RC-7 persistent challenger state — every coverage entry now carries rank_in_batch, batch_id (deterministic) and challenger_status; the ledger carries cycle_count/last_batch_id; entries persist across research cycles through the merge_dicts state field. Deeper outcome-history (previous validator outcomes per challenger) still queued for a future window.
8. Dependency extras split (torch/chromadb/sentence-transformers into ml extra) ONLY after import-graph proof that default runtime works without them (§7.1 six-point checklist).
9. Benchmark harness (§12) with pinned Juice Shop/DVWA/WebGoat images and hidden ground truth — after P0/P1 land.
## Explicitly NOT done this window (with reasons)
- Full 9,365-test suite: sandbox cannot install torch/chromadb/etc. (size/time). Affected-module batches: 298 passed, 2 skipped, exit 0 (commands recorded in BASELINE_AUDIT §5).
- Remote CI: push requires owner authorization (directive §3.1).
- Benchmark/discovery evaluation: directive §12 requires it only after correctness+release integrity stabilize.
