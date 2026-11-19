# UM-DR-34 Release Integrity Report

**Phase 10 deliverable — release identity and provenance
reconciliation.** This window releases **WebPent UNIFIED v0.40.0
(UM-DR-34)**.

---

## 1. The inconsistencies this window was chartered to fix (§10)

On the public `features/v0.39.0-umdr33` branch (@ `4795f02`):

| Field | Value on baseline | Problem |
|---|---|---|
| `pyproject.toml` version | 0.39.0 | — |
| `src/webpent/__init__.py` `__version__` | 0.39.0 | — |
| `Dockerfile` `ARG WEBPENT_VERSION` | 0.39.0 | — |
| `BUILD_INFO.json` `package_version` | **0.38.0** | stale version_identity_contract |
| `BUILD_INFO.json` `version_identity_contract.package_version` | **0.38.0** | conflicting identity meaning |
| `BUILD_INFO.json` `suite_count` | **8990** | exceeds the collected reality (8,958); the UM-DR-24 release gate FAILED on the baseline for exactly this reason |
| Branch name vs UM-DR-33 report branch | `features/v0.39.0-umdr33` vs `umdr33-researcher-brain-autonomous-campaigns` | different lineages; documented in the Baseline Report |
| Release artifact discrepancy | GitHub report SHA `8542b8…`/4,766 entries vs earlier local delivery `721aa9…`/4,770 files | **unverifiable from this window** — neither artifact is present in this environment and no v0.39.0 GitHub Release exists; neither value was adopted |

## 2. Reconciliation performed

1. **Next version: 0.40.0** — monotonic policy honored: 0.39.0 is
   taken by the public UM-DR-33 branch lineage; UM-DR-34 does not
   silently reuse or reset it.
2. Every version field now has ONE consistent meaning:
   `pyproject.toml` = `__init__.py` = `Dockerfile` =
   `BUILD_INFO.package_version` = `version_identity_contract.package_version`
   = **0.40.0**; CHANGELOG carries the 0.40.0 entry; `suite_count`
   records the reproduced reality (9,056).
3. `BUILD_INFO.version_identity_contract.previous_release` records the
   v0.39.0 UM-DR-33 lineage WITH its provenance limitation documented
   (branch, commit, the unreproducible 8,990 claim, and the gate
   failure it caused) — history preserved, never rewritten.
4. Local UM-DR-32 lineage preserved untouched on its branch
   (`da1f828`); both identities coexist (see the Baseline Report).
5. Frozen manifest re-pinned for the 14 thawed files per DR-009, with
   old hashes recorded in `scripts/refreeze_manifest_umdr34.py`.
6. Direct-I/O inventory regenerated deliberately (documented delta:
   −3 raw-client identities, +5 documented ones).

## 3. Deterministic archive (§12.12)

Built from the immutable release source revision with the canonical
portable builder (`scripts/build_release_archive.py`), **twice,
independently**:

| Property | Value |
|---|---|
| Release source revision | `umdr34-scope-authority-egress-hardening` @ `a2f569c7dce04b5a02a64e9438abf1a982f6d8eb` (Phase-13 docs commit; engineering final code revision `ed51ca10`) |
| Entries | **4,786** (sorted, fixed timestamps `(1980,1,1,0,0,0)`) |
| Bytes | **16,519,404** |
| SHA-256 (build 1) | `0205b8614263e3f6da8c5bf7b2e26f9a75f20b7dffd9182c69fe4e119e99fd48` |
| SHA-256 (build 2) | `0205b8614263e3f6da8c5bf7b2e26f9a75f20b7dffd9182c69fe4e119e99fd48` |
| Bit-identity | `cmp` verified — **byte-for-byte identical** |
| CRC | `testzip` clean (the builder's built-in verification) |
| Exclusions | policy EX-1..EX-5 (archives/checksums anchored exceptions, operational state, credentials, caches, runner state) — 0 tracked files excluded this build |
| No private data / no self-inclusion | verified by the builder contract |

(An earlier code-state build from `ed51ca10` — SHA
`e3f1da15…`, 4,776 entries — was also verified bit-identical twice;
the figures above are the release build that includes this document
set. The one-commit provenance delta is disclosed here rather than
papered over.)

## 4. Publication status — BLOCKED (recorded, with exact commands)

No GitHub credentials exist in this execution environment (the remote
was fetch-only). **No push, no PR, no GitHub Release was performed and
none is claimed.** The blocker and the exact operator commands are
recorded in the Baseline Report §5. The deliverable is the release
archive + this evidence set.

## 5. Provenance chain of this delivery

```
baseline  features/v0.39.0-umdr33 @ 4795f02 (public, fetched read-only)
   └── umdr34-scope-authority-egress-hardening
          ├── ed51ca10 — engineering final code revision (all Phases 0-12)
          ├── a2f569c7 — Phase-13 documentation deliverables (release source)
          │     ├── 14 frozen files re-pinned (DR-009, old hashes recorded)
          │     ├── 170 new regression tests
          │     ├── full suite: 9,056 collected → 9,047/0/6/3 (13/13 chunks)
          │     └── deterministic archive ×2 bit-identical (SHA-256 above)
```

Every claim in this report is reproducible from the repository at the
revision above; the UM-DR-33 historical discrepancies are preserved as
recorded history, never silently resolved.
