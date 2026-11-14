# UM-DR-33 Release Integrity Report

Window: UM-DR-33 (researcher brain & autonomous campaign evolution)
Release: **WebPent UNIFIED v0.39.0**
Branch: `umdr33-researcher-brain-autonomous-campaigns`
Date: 2026-11-10

---

## 1. Source identity

| Field | Value |
|---|---|
| Baseline (UM-DR-32 close) | `da1f828496f02fc647aeaac5c1c1cc3d59cf5cfb` (tree `727e660e`) |
| Final commit | recorded in `WebPent_UNIFIED_v0.39.0_UMDR33_RELEASE_MANIFEST.json` |
| Working tree at build | **clean** (`git status --porcelain` = 0 lines) |
| Lineage | unbroken 12-commit UM-DR-32 chain verified locally (see the baseline report) |

## 2. Deterministic archive — reproducibility proof

Built **twice** from the same immutable revision with
`scripts/build_release_archive.py`:

| Build | Entries | Bytes | SHA-256 |
|---|---|---|---|
| build 1 | 4766 (sorted, fixed timestamps) | 16,436,266 | `8542b8cf34e4b1f3e423b506cdb6f9a6b75755419a2124d564d2aea26644c99a` |
| build 2 | 4766 | 16,436,266 | `8542b8cf34e4b1f3e423b506cdb6f9a6b75755419a2124d564d2aea26644c99a` |

`cmp` verdict: **byte-identical**. Both builds from the SAME tree (the
§3.3 requirement — not two different trees). Exclusion policy: 17 tracked
files excluded (EX-1..EX-5: archives/checksums, operational state,
credentials, caches, runner state — the anchored exceptions ship).
Zero production-source exclusions. No self-inclusion (the builder
packages the git tree, never the output directory). ZIP CRC validated.

## 3. Version reconciliation (§3.5)

`0.39.0` consistent across: `pyproject.toml`, `src/webpent/__init__.py`
(frozen-window re-pin), `CHANGELOG.md`, `Dockerfile`
(`ARG WEBPENT_VERSION`), `BUILD_INFO.json` (`package_version`,
`current_release.window`), release manifest, Docker metadata contract
test. Python: floor `>=3.11` declared; **tested 3.12.16**; README now
states floor-vs-tested-vs-recommended explicitly.

## 4. Test accounting (full detail: `UMDR33_TEST_ACCOUNTING.json`)

- Baseline (frozen): 8,903 unique IDs = 8,894 passed + 6 skipped + 3 xfailed
- Final: **8,990 unique IDs = 8,981 passed + 6 skipped + 3 xfailed + 0 failed**
- Delta by actual node IDs: **+87 added, 0 removed, 0 replaced** across
  7 files (6 new `test_umdr33_*` modules + the frozen-gate parametrization)
- 13/13 chunks executed via the portable runner; no hidden collection
  error; suite-count honesty ritual re-fired (BUILD_INFO 8990).

## 5. Benchmark identity integrity (§3.6)

Single canonical JSON contract (`webpent.shared.canonical_json`,
`canonical-json/v1`): sorted keys, compact separators, ensure_ascii,
UTF-8. The historical dual-hash divergence (`b78ad5c6…` spaced vs
`58684262…` compact) is closed: the compact form is the ONE identity,
recorded in the regenerated benchmark artifact (both fields agree), with
18 mutation/regression tests proving every manifest mutation changes the
digest and both historical paths now produce the identical hash.

## 6. Working-tree hygiene (new this window)

The full suite no longer dirties the working tree: the econ CLI
`portfolio transition/plan` journals now honor `WEBPENT_ECON_DIR`
(pinned by `test_umdr33_tree_hygiene`); the UM-DR-32-era defect appended
to the tracked `download/econ/portfolio_transitions.jsonl` on every run.

## 7. Publication status — BLOCKED_EXTERNAL_DEPENDENCY (honest record)

This execution environment has **no Git remote and no GitHub
credentials**. All local release steps are complete. Exact publication
commands for the operator:

```bash
git remote add origin git@github.com:ElgendyMan/WebPent-Unified.git
git push -u origin main
git push origin umdr33-researcher-brain-autonomous-campaigns
git tag -a v0.39.0 -m "WebPent UNIFIED v0.39.0 (UM-DR-33)"
git push origin v0.39.0
gh release create v0.39.0 \
  download/WebPent_UNIFIED_v0.39.0_UMDR33.zip \
  download/WebPent_UNIFIED_v0.39.0_UMDR33.zip.sha256 \
  download/WebPent_UNIFIED_v0.39.0_UMDR33_RELEASE_MANIFEST.json \
  --title "WebPent UNIFIED v0.39.0 (UM-DR-33)" \
  --notes-file docs/engineering/umdr33/UMDR33_FINAL_ACCEPTANCE_REPORT.md
```

No release is claimed published. The historical GitHub-state question
(§3.1) is resolved by local evidence: the full UM-DR-32 lineage exists
locally with intact parents; only publication was never performed.

## 8. Acceptance (this report's scope)

Gate B (Release Integrity): **PASS** — archive, checksum, manifest,
reproducibility verified. Gate P (Delivery): local artifacts complete;
remote publication blocked (documented above with exact commands).
