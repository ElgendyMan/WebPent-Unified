# UM-DR-32 Final Acceptance Report

**Window:** UM-DR-32 — Autonomous Intelligence, Object Identity & Business Logic Evolution
**Decision date:** 2026-11-09
**Consolidated final report** (links all supporting evidence; §15 format).

---

## 1. Executive result

**UM-DR-32 COMPLETED** — both workstreams, on the dedicated branch
`umdr32-identity-business-logic-evolution`, package version **0.38.0**.

- Release: WebPent UNIFIED v0.38.0 (UM-DR-32) — archive
  `ad4c61d3614df3eb390e052abbc2c55bc4b97c01a7efa0bb49b919bdfd4fa1d6`,
  source commit `d3937b2a`, tree `c385c130`, reproducible bit-identically.
- Gates: **A, B, C, D, E, F, G, H, I, J — all PASS** (with the explicit
  delivery limitation recorded below; no gate is BLOCKED or NOT
  VERIFIED).
- **Engineering acceptance decision: ACCEPTED WITH LIMITATIONS** (the
  limitations are itemized in §8 — none weakens a security control, a
  confirmation authority, or a release gate).

## 2. Release and provenance closure

| Item | Value |
|---|---|
| Starting source identity | imported snapshot commit `5965917` (ZIP `abb21bd7…`, 4,734 files; NO preserved Git history — recorded limitation, no fabricated lineage) |
| Final source identity | `d3937b2a` (archive source; delivery commit `6b4d290` adds the delivery artifacts — recorded separately per the §3.2 contract) |
| Branch | `umdr32-identity-business-logic-evolution` (main untouched after the import) |
| Tag | NOT created (no publication channel in this environment; a tag would claim a published release) |
| Package version | 0.38.0 |
| Archive | `download/WebPent_UNIFIED_v0.38.0_UMDR32.zip` — 4,748 entries / 16,385,799 bytes |
| Archive SHA-256 | `ad4c61d3614df3eb390e052abbc2c55bc4b97c01a7efa0bb49b919bdfd4fa1d6` |
| Reproducibility | two independent builds bit-identical (SHA-256 + entries + contents + CRC) |

## 3. Capability implementation matrix

| Capability | Implemented | Production-connected | E2E verified | Quantitatively measured | Limitations |
|---|---|---|---|---|---|
| Object Identity | Yes | Yes (identity_workflow node + channels) | Yes | Yes (resolution 0/4→4/4, 0 false merges) | schema-less targets limit alias corroboration; no cross-campaign memory |
| Alias Resolution | Yes | Yes (hints + differentials) | Yes | Yes (4/4 pairs, P=1.0, abstention respected) | same as above |
| Multi-Identity Reasoning | Yes | Yes (the closed privilege_differential route) | Yes | Yes (3 scenarios at P=1.0) | execution in the harness path; role vocabulary is documented |
| Composite Business Logic | Yes | Yes (candidates + engine under the authorized executor) | Yes (live fixture) | Yes (4/4 with the unified chain, P=1.0/R=1.0) | observed-transitions-only; execution deliberately not a graph node |
| Unified Research Pipeline | Yes | Yes (composed redirect chain, 6 channels, real pool) | Yes (real compiled graphs) | Yes (unified arm 4/4, deterministic) | full 45-node LLM campaign not run (no operator credentials) |
| Engineering integrity | Yes | Yes (release pipeline) | Yes | n/a | GitHub publishing unavailable (local delivery) |

## 4. Quantitative results (the controlled lab — team-authored fixture,
equivalent budgets, ground truth fixed before measurement; see
`reports/qualification/umdr32_benchmark.json`)

| Arm | TP | FP | FN | Precision | Recall | Requests |
|---|---|---|---|---|---|---|
| baseline | 0 | 0 | 4 | — | 0.00 | 28/120 |
| object_identity | 0 | 0 | 4 | — | 0.00 | 28/120 |
| alias_resolution | 0 | 0 | 4 | — | 0.00 | 28/120 |
| multi_identity | 3 | 0 | 1 | 1.00 | 0.75 | 65/120 |
| composite_workflow | 4 | 0 | 0 | 1.00 | 1.00 | 82/120 |
| unified | 4 | 0 | 0 | 1.00 | 1.00 | 82/120 |

Separately reported (not vulnerability metrics): alias resolution
0/4 → 4/4 confirmed pairs, **zero false merges in every arm**, the
namespace/type/query never-merge pairs and the abstain pair never
confirmed. Determinism: repeat runs identical (test-enforced).
Population honesty: mechanism validation only — no generalization,
no real-world, no cross-tool claims.

## 5. Security assessment

- Scope preserved (all pre-existing scope/budget/kill-switch/HITL
  contracts green in the 8,903-test suite).
- The §10.1 origin-scheme admission defect FOUND and FIXED (complete
  normalized origin comparison; 17-test matrix; 61 pre-existing
  admission tests unchanged and green).
- Principal/session isolation verified (SessionBindingError before any
  request; credential-free projections).
- Tenant isolation verified at every layer (registry, alias, matrix,
  lab measurement).
- Alias merges safe (zero false merges measured + boundary tests).
- **CausalGuard remained the sole confirmation authority** — the new
  modules expose no promotion vocabulary (mechanically verified);
  ProofBundle and replay contracts untouched and green.
- No security regression observed (full suite 0 failures; every
  security gate green).

## 6. Regression results

- Collected test IDs: **8,903** (unique; baseline 8,744; +159, 0 removed)
- Passed **8,894** / Failed **0** / Skipped **6** / Xfailed **3** /
  Collection errors **0** — reconciliation exact (8,894+6+3 = 8,903)
- Chunks: **13/13 ok** via the portable runner (no missing chunk, no
  collection error, no unexecuted file)
- Frozen gate: GREEN (644 entries; 6 re-pinned + 5 new, documented)
- Direct-I/O gate: GREEN (1,177 records; +7 declared identities)
- Broad-exception register: GREEN (25 documented handlers)
- Dependency/lock: suite dependencies installed per declaration; the
  lock identity is recorded in the benchmark provenance
- Lint: GREEN by the repo's ratchet gates; new production files clean
- Secret scan: GREEN (no live credentials; no operational data in the
  archive)

## 7. Changed files (by class)

- **Production source:** `object_identity.py`, `alias_resolution.py`,
  `multi_identity.py`, `composite_workflows.py`, `identity_workflow.py`
  (new, frozen from birth)
- **Validators/routing:** `agents/validator/registry.py`
  (privilege_differential registration),
  `production/experiment_fabric.py` (the PRIVILEGE_DIFFERENTIAL
  experiment)
- **Graph integration:** `graph/builder.py` (the composed redirect
  chain + node wiring)
- **State models:** `state/state.py` (six declared channels)
- **Configuration:** `config/settings.py` (4 capability flags + 5
  bounds), `pyproject.toml`/`__init__.py`/`Dockerfile` (0.38.0),
  `BUILD_INFO.json` (the version contract)
- **Security fix:** `production/adaptive_research.py` (origin scheme
  admission + identity hints consumption)
- **Tests:** 9 new modules (154 tests — UM-DR-33 §3.7 erratum: originally
  miscounted as 152; recomputed from actual node IDs as 154, plus 5
  frozen-gate entries = 159 for the window, matching
  `UMDR32_TEST_ACCOUNTING.json`) + frozen-gate scope + register
- **Release scripts:** `build_release_archive.py`, `run_suite.py`,
  `experiment_provenance.py`, `refreeze_manifest_umdr32.py`,
  `regen_direct_io_inventory_umdr32.py`,
  `build_umdr32_benchmark_artifact.py` (+ the deprecated builder shim
  and the provenance-fixed ablation generator)
- **Documentation:** the 11-deliverable `docs/engineering/umdr32/`
  package, both principal documents, README, CHANGELOG, DRIFT_REGISTER
- **Evidence artifacts:** `reports/qualification/umdr32_benchmark.json`,
  the baseline freeze, the test accounting, the release archive +
  checksum + manifest

## 8. Remaining limitations (every one with its evidence and capability)

1. **Independently validated: NO** (all capabilities) — M10 remains
   CLOSED / BLOCKED_EXTERNAL_DEPENDENCY; the UM-DR-32 evaluation is a
   controlled local engineering evaluation on a team-authored fixture.
2. **Published release: NO** — GitHub publishing unavailable; the
   verified archive/checksum/manifest are delivered locally (release
   integrity report §6).
3. **Pre-import Git lineage: unverifiable** (permanent; recorded in the
   baseline report; nothing fabricated).
4. **Full LLM campaign traversal: not run** (no operator credentials);
   the LangGraph-level wiring is proven with real compiled graphs.
5. **Differential/workflow execution lives in the harness path**, not
   as autonomous graph nodes — deliberate (bounded execution under the
   authorized executor; the hypotheses ARE in the real pool and the
   validator route IS production-registered).
6. **Schema-less alias corroboration** limited (abstention is the
   honest outcome) — measured and documented in the design report.
7. **Historical artifacts preserved as claims** (UM-DR-30/31 counts,
   the ablation git_head) — labeled, never rewritten.

## 9. Final acceptance

**ACCEPTED WITH LIMITATIONS.**

Every gate passed with direct evidence; every limitation above is
itemized with its affected capability and its evidence; no limitation
weakens a security control, a confirmation authority, or a release
gate. The core research goal — moving WebPent from endpoint-oriented
testing toward evidence-driven object, identity, state and workflow
reasoning — is implemented, integrated into the real production path,
measured under controlled equivalent conditions, and honestly
documented.

## 10. Handoff

| Deliverable | Path |
|---|---|
| Master Guide (updated, §12) | `WEBPENT_MASTER_GUIDE.md` |
| Engineering Reference (updated) | `WEBPENT_ENGINEERING_REFERENCE.md` |
| Final execution report | `docs/engineering/umdr32/UMDR32_EXECUTION_REPORT.md` |
| Capability matrix | `docs/engineering/umdr32/UMDR32_CAPABILITY_QUALIFICATION_MATRIX.json` |
| Benchmark results | `reports/qualification/umdr32_benchmark.json` |
| Test accounting | `docs/engineering/umdr32/UMDR32_TEST_ACCOUNTING.json` |
| Security report | `docs/engineering/umdr32/UMDR32_SECURITY_REGRESSION_REPORT.md` |
| Release integrity report | `docs/engineering/umdr32/UMDR32_RELEASE_INTEGRITY_REPORT.md` |
| Archive | `download/WebPent_UNIFIED_v0.38.0_UMDR32.zip` |
| Checksum | `download/WebPent_UNIFIED_v0.38.0_UMDR32.zip.sha256` |
| Release manifest | `download/WebPent_UNIFIED_v0.38.0_UMDR32_RELEASE_MANIFEST.json` |
| Baseline & provenance | `docs/engineering/umdr32/UMDR32_BASELINE_AND_PROVENANCE_REPORT.md` |
| Engineering remediation | `docs/engineering/umdr32/UMDR32_ENGINEERING_REMEDIATION_REPORT.md` |
| Object identity design | `docs/engineering/umdr32/UMDR32_OBJECT_IDENTITY_DESIGN.md` |
| Final evaluation report | `docs/engineering/umdr32/UMDR32_FINAL_EVALUATION_REPORT.md` |
| Final acceptance (this report) | `docs/engineering/umdr32/UMDR32_FINAL_ACCEPTANCE_REPORT.md` |
