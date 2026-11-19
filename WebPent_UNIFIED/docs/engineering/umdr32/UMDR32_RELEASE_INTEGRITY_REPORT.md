# UM-DR-32 Release Integrity Report

**Release:** WebPent UNIFIED v0.38.0 (UM-DR-32)
**Report date:** 2026-11-09

---

## 1. Release identity

| Field | Value |
|---|---|
| Package version | 0.38.0 (pyproject.toml = CHANGELOG.md head = Dockerfile ARG) |
| Window | UM-DR-32 (branch `umdr32-identity-business-logic-evolution`) |
| Archive source commit | `d3937b2a98c4b488587e616fd98cbbe36f2f36d7` |
| Archive source tree SHA | `c385c1302a98750e8a46617b96b4c8769ef4de64` |
| Builder | `scripts/build_release_archive.py` (deterministic; exclusion policy EX-1..EX-5) |

The archive source revision and the artifact-delivery revision are
recorded SEPARATELY (the §3.2 contract): the delivery commit adds this
report, the manifest and the checksum file on top of the archived
revision — the archive's identity is pinned to the revision it was
built from.

## 2. Archive identity

| Field | Value |
|---|---|
| Path | `download/WebPent_UNIFIED_v0.38.0_UMDR32.zip` |
| SHA-256 | `ad4c61d3614df3eb390e052abbc2c55bc4b97c01a7efa0bb49b919bdfd4fa1d6` |
| Size | 16,385,799 bytes |
| Entries | 4,748 files (sorted, fixed 1980-01-01 timestamps, deflate-9, 0644) |
| Checksum file | `download/WebPent_UNIFIED_v0.38.0_UMDR32.zip.sha256` |
| Manifest | `download/WebPent_UNIFIED_v0.38.0_UMDR32_RELEASE_MANIFEST.json` |

## 3. Reproducibility — PROVEN

Two independent builds from the same immutable revision produced
**bit-identical archives**: identical SHA-256, identical entry list,
identical contents (verified per-entry), valid ZIP CRC in both
(`testzip`). The same tree at the same revision always yields the same
digest — the reproducibility class of gap that made the historical
v0.37.0 announcement digest unverifiable is now structurally closed.

## 4. Content verification

- Entry count 4,748; deterministic sorted order; no duplicates; every
  entry under the `WebPent_UNIFIED/` prefix; no path traversal.
- Package version inside the archive: **0.38.0** ✓.
- The archive does not contain itself; no working-directory leakage
  (every byte read from the Git revision, never the working tree).
- Exclusions applied: 17 tracked files, every one by the documented
  policy (EX-1 generated archives/checksum sidecars — with the
  load-bearing anchored exceptions that ship; EX-2 operational state;
  EX-3 credentials; EX-4 caches; EX-5 runner state). The builder's
  production-source protection guarantee: zero production source
  excluded (hard-fails otherwise).
- Secret safety re-verified on the archive payload: no `webpent.db`, no
  real `.env`, no credential files (only `.example` templates and the
  documented read-only credential TEMPLATE).

## 5. Gates at release

| Gate | Result |
|---|---|
| Full suite (portable runner, 13/13 chunks) | 8,903 collected → 8,894 / 0 failed / 6 skipped / 3 xfailed |
| Frozen-module gate | GREEN — 644 entries (6 re-pinned + 5 new, documented) |
| Direct-I/O inventory | GREEN — 1,177 records (+7 declared) |
| Broad-exception register | GREEN — 25 handlers (documented) |
| State contract | GREEN — 294 declared keys |
| Version consistency (changelog/Dockerfile/pyproject) | GREEN |
| Hygiene gate (resurrect) | GREEN |
| Benchmark artifact provenance | Clean tree, full §3.2 contract, ground-truth hash recorded |

## 6. Delivery status and limits

GitHub release publishing was NOT available in this environment: the
verified archive, checksum and manifest are **delivered locally** in
`download/`. No claim is made that the artifact is published anywhere.
The pre-import Git lineage remains unverifiable (the recorded
imported-snapshot limitation; the new lineage from the import commit is
fully verifiable).
