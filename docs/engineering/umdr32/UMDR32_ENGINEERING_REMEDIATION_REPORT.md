# UM-DR-32 Engineering Remediation Report

**Window:** UM-DR-32 — Workstream A (engineering and release integrity)
**Report date:** 2026-11-09
**Directive sections:** §3 (Phase One) with §10.1 measured in the security report.

---

## 1. Release archive builder portability — FIXED

**Defect (§3.1):** `scripts/build_release_archive_umdr31_1.py` computed
its project prefix as `str(REPO.relative_to(GIT_ROOT)) + "/"`. When the
project root IS the Git root this yields `"./"`, while `git ls-tree`
paths never carry that prefix — the payload filter matched nothing and
the builder aborted (in variants without the abort check, an empty
archive could be emitted silently).

**Fix:** `scripts/build_release_archive.py` — the canonical builder.

- Correct prefix computation: `""` for root layout, `"sub/dir/"` for a
  nested project (never `"./"`).
- Reads every payload byte from the selected immutable Git revision
  (`git ls-tree` + `git cat-file`), never the working tree.
- **Explicit documented exclusion policy** (EX-1..EX-5): generated
  archives/checksum sidecars (with the anchored load-bearing exceptions
  that ship), operational state (databases, locks, runtime dirs),
  private credentials, local caches, runner state. Every exclusion is
  reasoned in the module docstring; the builder hard-FAILS when a
  pattern would drop production source (src/scripts/tests `.py` files).
- Deterministic: sorted entries, 1980-01-01 zip epoch, deflate-9, fixed
  0644 attributes — the same tree+revision always yields the same
  SHA-256 (test-enforced, two independent builds compared).
- Full post-build verification: CRC (`testzip`), entry count/order,
  duplicates, prefix containment, self-containment.
- Empty payload: hard refusal, never a silent empty success.
- The old script is now a deprecating shim delegating to the canonical
  builder.

**Regression tests:** `tests/test_umdr32_release_archive_builder.py`
(7 tests) — root layout, nested monorepo layout, both-build determinism,
empty-payload refusal, production-source protection, policy categories,
real-repository reproducibility (4,700+ entries), self-containment.

## 2. Release artifact provenance — FIXED

**Defect (§3.2):** the UM-DR-31 ablation artifact recorded a single
ambiguous `git_head` (via `git rev-parse HEAD`) for what are actually
four distinct concepts (source revision / test revision / artifact
revision / publication revision), and a dirty tree could masquerade as a
clean commit identity.

**Fix:** `scripts/experiment_provenance.py` — the provenance contract:

- `capture_source_provenance`: exact source commit, tree SHA, branch,
  dirty status; **default REJECTS a dirty tree** (fail-closed) for
  release-grade measurement; `--allow-dirty` records an explicitly-labeled
  engineering run carrying the source-diff hash.
- `capture_artifact_provenance`: the full record every experiment
  artifact must carry — source identity, generator-script revision
  (SHA-256 of the generator), fixture content hashes, dependency-lock
  identity, exact command, Python version, UTC start/completion
  timestamps, request budget, requests actually issued, ground-truth
  manifest identity.
- `scripts/build_umdr31_ablation_artifact.py` now enforces the contract
  and **fails FAST** (before spending the measurement budget) on a dirty
  tree; `scripts/build_umdr32_benchmark_artifact.py` was born under it.
- The historical artifact is preserved with an explicit
  `provenance_limitation` note (history is never rewritten).

## 3. Full-suite runner portability — FIXED

**Defect (§3.3):** `scripts/run_suite_chunks_umdr31_1.sh` hardcoded
`/home/z/my-project/webpent/WebPent_UNIFIED` and `/home/z/.venv/bin/python3`,
used an undeclared `rg` dependency, kept state in a fixed `/tmp` path,
hardcoded the chunk size, and — critically — **always exited 0**: a
failed or never-executed chunk never failed the run.

**Fix:** `scripts/run_suite.py` (portable Python):

- Git-root discovery (script-location fallback), configurable
  `--python`, `--tests-dir`, `--state-dir`, `--chunk-size`,
  `--chunk-timeout`, `--chunks a:b`, `--reset`, `--list`.
- Deterministic inventory: one `pytest --collect-only` pass (cached),
  sorted, every file in exactly one chunk; fallback glob is recorded
  honestly in the summary (`discovery` field).
- Per-chunk status: `ok | failed | timeout | empty`; interrupted chunks
  re-run on the next invocation (idempotent completion).
- Exact accounting: per-chunk and total counts parsed from pytest's
  summary line (including the `(0:01:21)` duration-suffix form), written
  to a machine-readable JSON summary.
- **Non-zero exit whenever any chunk failed or was never executed**;
  `SUITE OK` only when every planned chunk ran and passed.
- Default state directory lives OUTSIDE the repository (the hygiene
  gate flags `*.log` residue — caught and fixed during this window).

**Proof of work:** the entire UM-DR-32 full-suite regression (13/13
chunks, 8,903 tests) ran through this runner.

## 4. BUILD_INFO and version identity conflicts — RESOLVED

**Defects (§3.4):** package version 0.37.1 vs BUILD_INFO
"identity_note" claiming the SSOT was the "0.32.0 line"; build name
"WebPent v15.2 (unified)" (a legacy delivery label) presented beside
package versions; two conflicting git identity fields; README implying
"Python 3.12+" while pyproject declares `>=3.11`.

**Resolution — the explicit version contract** (BUILD_INFO.json
`version_identity_contract`):

| Concept | Value | Where recorded |
|---|---|---|
| Historical merge baseline | 0.34.0 (2026-11-02) — historical, not current | BUILD_INFO contract, labeled |
| Current package version | **0.38.0** | pyproject.toml, CHANGELOG (the SSOT pair) |
| Legacy delivery label | "WebPent v15.2 (unified)" — lineage label only | BUILD_INFO, explicitly non-version |
| Previous release | v0.37.1-UMDR31.1 (imported snapshot, ZIP SHA-256 recorded) | BUILD_INFO contract |
| Current release | 0.38.0 / UM-DR-32 (source revision in the release integrity report) | this package |
| Python floor | **>=3.11** (declared) | pyproject.toml |
| Python tested | 3.12.16 (documented separately from the floor) | baseline freeze, BUILD_INFO |

- README now states the floor (3.11+) and the actually-tested version
  (3.12.16) separately.
- The single ambiguous `git_head` field is replaced by a pointer to the
  per-artifact provenance contract (§3.2).
- Historical UM-DR-30/31 numbers remain in BUILD_INFO as labeled
  historical records.
- Version-consistency gates (changelog head == package version;
  Dockerfile ARG == pyproject) are green again.

## 5. Test accounting reconciliation — DONE

**Defect (§3.5):** documents mixed UM-DR-31 (8,711) and UM-DR-31.1
(8,744) numbers without labels.

**Reconciliation (exact, by unique test ID):**

| Window | Unique IDs | Collected | Passed | Failed | Skipped | Xfailed |
|---|---|---|---|---|---|---|
| Baseline (import commit, = published 0.37.1 claim) | 8,744 | 8,744 | 8,735 | 0 | 6 | 3 |
| **UM-DR-32 final** | **8,903** | **8,903** | **8,894** | **0** | **6** | **3** |

Delta: **+159 unique test IDs, 0 removed** — 152 across nine new
UM-DR-32 test modules + 5 frozen-gate parametrized entries (the five
newly frozen capability modules). Test FILES with tests: 671 → 681.
Reconciliation identity: 8,894 + 6 + 3 = 8,903 (exact). Historical
UM-DR-31/31.1 numbers remain available and are labeled with their
windows. Machine record: `UMDR32_TEST_ACCOUNTING.json`.

## 6. Architecture and qualification documentation — UPDATED

- `WEBPENT_MASTER_GUIDE.md` and `WEBPENT_ENGINEERING_REFERENCE.md` carry
  the UM-DR-32 capability sections with the seven-level status
  vocabulary (implemented / unit-tested / production-connected /
  integration-tested / campaign-demonstrated / independently-validated /
  production-qualified) — see each capability's honest status in the
  qualification matrix; nothing is promoted beyond its evidence.
- `CHANGELOG.md` leads with the 0.38.0 entry (the release-packaging gate
  enforces this).
- `DRIFT_REGISTER.md` carries the UM-DR-32 entry.
- README: Python floor corrected; credential-template warning preserved.

## 7. Secret and database handling — VERIFIED

Pre-archive scan (§3.7):

- Tracked-tree secret-pattern scan: every hit is a detection pattern in
  the scanner itself (`src/webpent/tools/js_extractors.py`), a dummy
  test-fixture value, or an already-redacted audit record. **No live
  credentials found. No rotation required.**
- `.env*`: only `.example` templates are tracked.
- `webpent.db`: NOT tracked (gitignored); present in the working
  directory only as test-suite runtime residue (pseudonymous regression
  user rows, 0 findings); excluded from archives by builder policy EX-2.
  The merge report's tracked-`webpent.db` no longer exists.
- `credentials_template.json`: read-only template, documented warning
  preserved.
- Release archive secret re-verification: see the release integrity
  report (§J).

## 8. Remaining release limitations

1. **Git lineage:** the pre-import history remains unverifiable (the
   imported-snapshot limitation is permanent for this lineage); all
   pre-import identities are labeled claims.
2. **GitHub release publishing** was not available in this environment:
   the verified archive + checksum + manifest are delivered locally with
   the release integrity report; nothing claims a published artifact.
3. Historical qualification artifacts (UM-DR-30/31 matrices) are
   preserved as historical records; only the UM-DR-32 matrix reflects
   the current tree.
