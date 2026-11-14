# UM-DR-31.1 RELEASE INTEGRITY REPORT

Verification date: 2026-11-08. All digests below were computed from the actual files on disk by `sha256sum` / the packaging script itself.

## 1. The historical gap (audit F01) — stated precisely

- The v0.37.0 announcement claimed an archive `WebPent_UNIFIED_v0.37.0_UMDR31.zip`, 5,330 entries, sha256 `607e17fa241a5231a58c280564e68d0e02e095884eabcbfc5d1cd905bc27b4bd`.
- That archive file does not exist anywhere on the filesystem; the announced digest therefore remains **unverifiable** and is NOT claimed to be verified here or anywhere in this window's records.
- The CONTENT of the release is fully recoverable from git: the tracked tree at `2d7b928` (verified by the audit's reconstruction: exactly 5,330 entries, 16,504,627 bytes — structure and size consistent with the announcement).
- The auditor's reconstructed archive exists at `download/WebPent_UNIFIED_RECONSTRUCTED_v0.37.0_UMDR31.zip` (committed in the audit-evidence commit `914061c`). Its digest is a RECONSTRUCTION digest — git-archive-style packaging embeds live mtimes, so it necessarily differs from the never-seen original. It is recorded below for completeness only.

## 2. The UM-DR-31.1 release candidate

| Property | Value |
|---|---|
| Release | v0.37.1 (UM-DR-31.1) |
| Release commit | `21f591a` (branch `umdr31-1-intelligence-engineering-uplift`) |
| Tag | **`v0.37.1-umdr31.1`** (annotated; the first git tag in this repository's history — F19) |
| Archive | `download/WebPent_UNIFIED_v0.37.1_UMDR31_1.zip` |
| Builder | `scripts/build_release_archive_umdr31_1.py` — deterministic: tracked-tree-only contents, entries sorted by path, fixed zip-epoch timestamps (1980-01-01), explicit re-rooting; **the same rev always yields the same digest** (verified: two independent builds of the same rev produced byte-identical archives) |
| Entries | 4,728 files (the tracked tree at the tagged commit — no working-dir leakage by construction) |
| Size | 16,237,164 bytes |
| **SHA-256** | **`b814d96f5786e68c093e7d3b49d93b38927788bacf45ec9f15d93ca1851b1620`** |
| Checksum file | `download/WebPent_UNIFIED_v0.37.1_UMDR31_1.zip.sha256` (same digest, standard `sha256sum` format) |

### Archive inspection (performed, not assumed)

- `zipfile.ZipFile.testzip()` → None (every entry's CRC verified on read).
- Entries sorted (programmatic check: `names == sorted(names)`).
- All entry timestamps are the fixed zip epoch (programmatic check).
- Version inside the archive matches the release: `pyproject.toml` → `0.37.1` (programmatic check).
- Key deliverables present: `pyproject.toml`, `src/webpent/production/adaptive_research.py`, `DRIFT_REGISTER.md`, `WEBPENT_MASTER_GUIDE.md`, `WEBPENT_ENGINEERING_REFERENCE.md`, `docs/engineering/UMDR31_1_*.md|json`, `reports/qualification/umdr31_ablation.json`.
- Exclusions: nothing outside the tracked tree is included (the builder reads blobs via `git cat-file`, never the working dir); zips and other untracked artifacts cannot enter.

## 3. Digest record (all three, clearly distinguished)

| Artifact | sha256 | Status |
|---|---|---|
| v0.37.0 original announcement | `607e17fa241a5231a58c280564e68d0e02e095884eabcbfc5d1cd905bc27b4bd` | **UNVERIFIED — the file does not exist; never claim this digest verifies anything** |
| v0.37.0 reconstruction (audit, live-mtime packaging) | recorded in `download/UMDR31_AUDIT_EVIDENCE_MANIFEST.json` | reconstruction digest; differs from the original by construction |
| **v0.37.1 UM-DR-31.1 release candidate** | **`b814d96f5786e68c093e7d3b49d93b38927788bacf45ec9f15d93ca1851b1620`** | **VERIFIED** — computed from the actual generated artifact, reproducible from the tagged commit by the deterministic builder |

## 4. Historical preservation

- No v0.37.0 commit was rewritten, amended, or reverted (all corrections move forward on the new branch; `2d7b928` remains the immutable release tree).
- The post-release mutation (`2ad93aa`) is documented in DRIFT_REGISTER (UM-DR-31.1, R2) and root-caused; the affected artifact was first restored to its released bytes, then deliberately regenerated via the explicit release-time command with the new-window results (the regeneration is itself a documented, intentional act — never a test side effect again).
- The pre-existing audit evidence bundle (`download/UMDR31_AUDIT_EVIDENCE/`) is untouched.

## 5. Release metadata accuracy (R9)

- `BUILD_INFO.json`: `build_date` = true UTC at build time (`2026-11-08T19:08:06Z`; F15 closed), `package_version` 0.37.1, `suite_count` 8744 = collected reality (honesty gate green), `git_head` frozen to the window's code-head commit, and a `umdr31_1` record with the window's facts.
- `uv.lock`: webpent self-entry 0.37.1 (F16 closed); single dnspython 2.9.2 (F07 closed).
- `pyproject.toml` version 0.37.1; `src/webpent/__init__.py` `__version__` 0.37.1; `Dockerfile` ARG agreement gate green.
- `CHANGELOG.md` carries the 0.37.1 entry.
- The tag was created only after: full suite green on the final tree, all compliance gates green, and the archive built/inspected — never on an unverified tree.
