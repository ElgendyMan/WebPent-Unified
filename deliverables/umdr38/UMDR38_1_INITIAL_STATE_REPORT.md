# UM-DR-38.1 — Initial State Report (Phase 0)

Generated: 2026-11-17T04:58:58.410840+00:00 — every observation below was executed against the ACTUAL repositories at mission start; superseded UM-DR-38 claims are quoted only as history.

## The published state

* `origin/main` at mission start: **bf9a136c9c3c** — “Update project to v0.40.1 UMDR38 FINAL”, parent `2338fd5` (the UM-DR-36.2/37 publish squash).
* Root layout of the published tree (`git ls-tree --name-only origin/main`): **`WebPent_UNIFIED/` ONLY** —
  - root `README.md`: ABSENT;
  - root `.github/workflows/`: ABSENT (GitHub cannot discover workflows there — the canonical root workflows had been published INSIDE `WebPent_UNIFIED/.github/workflows/`);
  - `WebPent_UNIFIED/README.md`: present (the ORIGINAL project README — the release ZIP's copy order had overwritten the root entrypoint text inside the project directory);
  - the mission deliverables landed under `WebPent_UNIFIED/deliverables/{umdr38,umdr37}/` while the UM-DR-38 reports referenced ROOT-level `deliverables/` paths;
  - `WebPent_Unified_umdr38.bundle` published INSIDE `WebPent_UNIFIED/`.

## The six SHAs named by the UM-DR-38 artifacts

| SHA | Referenced by | Resolution on this branch |
|---|---|---|
| `e6f387c8230d` | BUILD_INFO provenance.source_revision | resolvable (carried by the published bundle) |
| `e31cad5efcf8` | BUILD_INFO provenance.tested_revision/evidence_revision | resolvable (carried by the published bundle) |
| `d23e4e868f5f` | campaign records source_commit | resolvable (carried by the published bundle) |
| `7b3fa8dc3d7b` | UM-DR-38 deliverables-era commit | resolvable (carried by the published bundle) |
| `471d5e1febad` | UM-DR-38 deliverables-era commit | resolvable (carried by the published bundle) |
| `bf50d995fb01` | UM-DR-38 deliverables-era commit | resolvable (carried by the published bundle) |

## The bundle recovery

The published tree carries `WebPent_Unified_umdr38.bundle`; `git bundle verify` PASS and `list-heads` yields:

```
8f43e88410a74a779e85152e848b6e83333570ab refs/heads/mission/umdr38-closure
```

That branch shares legitimate ancestry with published main (merge-base **2338fd5**). The corrective branch merges it with `-s ours`: the mission commits become resolvable ancestors WITHOUT inventing ancestry, and the three provenance-bearing SHAs (`e6f387c`, `e31cad5`, `d23e4e8`) resolve from this branch. The three deliverables-era SHAs (`7b3fa8d`, `471d5e1`, `bf50d99`) were cut AFTER the bundle was created and remain **unresolvable** — their reports are preserved as history and marked superseded; NO claim of resolution is made.

## Root-cause of the publication defect

The UM-DR-38 release ZIP wrapped EVERYTHING — including the repository-root artifacts — under a `WebPent_UNIFIED/` prefix, and its copy order let the project README silently overwrite the root entrypoint. Publishing the ZIP contents therefore reproduced the pre-UM-DR-38 flat layout. UM-DR-38.1 fixes the BUILDER so the ZIP root layout EQUALS the required repository layout (Phase 7), ending the publish-loop defect class.
