# UM-DR-34 Baseline and Source Identity Report

**Window:** UM-DR-34 — Unified Scope Authority, Safe Egress & Execution Governance
**Date:** 2026-11-10
**Execution environment:** Python 3.12.16, pytest 9.0.2, Linux sandbox

---

## 1. Source lineage resolution (§0.1–0.2)

Three distinct lineages were identified and ALL THREE are preserved
(no destructive reset, no force-push, no history rewrite):

| Identity | Commit | Tree | Status |
|---|---|---|---|
| Public `main` | `989c49ba5cb3747859496d06736ae7c8317086ed` | — | fetched, read-only |
| Public `features/v0.39.0-umdr33` | `4795f02377373a1a2dc4d3376987f7702cd24bf6` | `30d0917275384c16a42351ae844a4508dd80c3c9` | **UM-DR-34 baseline** |
| Local `umdr32-identity-business-logic-evolution` | `da1f828` | — | preserved untouched (identity B) |

Findings, per the directive's own warnings:

1. **Local and public histories share NO common ancestor** (`git
   merge-base` is empty). The local tree is the UM-DR-32 imported-snapshot
   lineage; the public repository was pushed from a different history
   ("Initial project upload" → "Update to v0.38.0 UMDR32" → "Start
   feature development with v0.39.0 UMDR33").
2. **The local workspace contains NO UM-DR-33 work.** The public feature
   branch is the ONLY tree carrying the UM-DR-33 engineering set
   (discovery funnel, canonical JSON, info-gain operationalization,
   evidence-chain fixes, hard-budget/creds fail-closed fixes, tree
   hygiene; 46 files, +3,406/−396 vs its parent).
3. **Local-only content vs the public branch** (preserved on the local
   branch, never deleted): `tests/test_secrets_scanner.py` (+318),
   `tests/test_v25_javascript_intelligence.py` (+168),
   `docs/operator_credentials.example.json`, the v0.38.0 release
   manifest, and BUILD_INFO/CHANGELOG drift. These are recorded here as
   the documented local↔remote delta; they were NOT ported into the
   UM-DR-34 baseline (single clean revision per §10) and remain
   available on the preserved local branch for any future explicit
   reconciliation task.
4. **Working tree at start:** mode-bit noise only (archive-extraction
   artifacts; `git config core.fileMode false` applied), zero untracked
   files, zero content modifications. Tags: none. Remotes: `origin` →
   `https://github.com/ElgendyMan/WebPent-Unified` (fetch-only access;
   no push credentials — see §5).

**Chosen baseline (recorded per §0.2):**
`origin/features/v0.39.0-umdr33` @ `4795f02`, branch
`umdr34-scope-authority-egress-hardening` created from it.
**Final revision of this window:** `ed51ca10a17fdd6793d617d1abf5951973448976`.

## 2. Baseline test reproduction (§0.3)

The UM-DR-33 reports claim **8,990 unique tests**. Reproduction on the
actual baseline:

* **8,958 unique node IDs collected** (684 files; 13/13 chunks, portable
  runner). The 8,990 claim is **not reproducible** — it exceeds the
  collected reality by 32.
* Environment bring-up: `bcrypt`, `celery`, `esprima`, `langchain-core`,
  `langgraph`, `langgraph-checkpoint-sqlite`, `jsbeautifier` installed;
  `pip install -e . --no-deps` (the suite's subprocess-spawning tests
  require the package importable — an environment fix, not a code fix).
* Baseline result with the environment corrected: **10 of 11 initial
  failures were environment artifacts** (ModuleNotFoundError in
  subprocesses) and passed after the editable install. **Exactly ONE
  real baseline defect remained:**
  `tests/test_umdr24_release_gate_compliance.py::test_build_info_suite_count_coherent_with_collected_reality`
  — BUILD_INFO.json's `suite_count: 8990` exceeds the collected reality
  8,958. This is the UM-DR-33 release-identity inconsistency §10
  targets; it was **fixed in this window** (BUILD_INFO now records the
  reconciled count), not silenced.

## 3. Mandatory invariants (§0.4) — verification

Unchanged and re-verified by the full green suite (§4):

* `cqa_v2.guarded_causal_evaluate` / CausalGuard remains the sole
  confirmation authority — no new confirmation authority introduced
  anywhere in this window.
* ProofBundle generation and replay verification: untouched (the
  UM-DR-33 bundle-identity fix is the baseline state; no changes).
* Negative controls, HITL, budget ceilings, kill switches, execution
  boundaries: untouched at the authority layer; the transport request
  ceiling is NEW and additional (never a replacement for any of them).
* LLM output remains advisory; no new agents, planners, MCP, M10, or
  benchmark claims. No security check was weakened for test counts —
  the only test-contract updates are documented one-way STRENGTHENINGS
  (see §4 of the Security Regression Report).

## 4. Final-window suite accounting

See `UMDR34_TEST_ACCOUNTING.json` for the machine-readable record:
**9,056 collected → 9,047 passed / 0 failed / 6 skipped / 3 xfailed,
13/13 chunks, exact reconciliation, zero silently removed tests.**

## 5. Publication status (§10)

* **Not pushed.** No GitHub credentials are available in this execution
  environment (fetch-only). This is the recorded publication blocker —
  per the directive, no public release is claimed.
* Exact commands for the operator (never force-push):

```bash
git push -u origin umdr34-scope-authority-egress-hardening
gh pr create --base features/v0.39.0-umdr33 \
  --head umdr34-scope-authority-egress-hardening \
  --title "UM-DR-34: unified scope authority, safe egress & execution governance (v0.40.0)" \
  --body-file docs/engineering/umdr34/UMDR34_FINAL_ACCEPTANCE_REPORT.md
```

* The v0.38.0-era artifact discrepancy noted in §10 of the charter
  (GitHub release report SHA `8542b8…`/4,766 entries vs earlier local
  delivery `721aa9…`/4,770 files) could not be adjudicated from this
  environment — the referenced artifacts are not present here, and no
  GitHub Release for v0.39.0 exists. Recorded as **unverifiable from
  this window**; the v0.40.0 archive built here is fully
  self-describing (see the Release Integrity Report).
