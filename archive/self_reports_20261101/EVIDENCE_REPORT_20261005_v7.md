# EVIDENCE_REPORT — WebPent FINAL v7 (2026-10-05 build, R3 window)

Sprint R3 — Unfreeze Patch Window | Dispatch #005 | Ruling R3-002.
TEAM-CODE deliverable D8. Verification anchor: fresh-extracted v7 ZIP.

## 1. What v7 is

v7 is the first release produced through an OPEN unfreeze window: exactly
three ratified fixes (E-1, E-2, E-4) landed on the v6 baseline under a
delta-mode gate, then the tree was re-frozen with a mapped manifest-delta.
Zero src/ files outside the ruling's thaw list changed. Frozen-manifest
scope unchanged at 695.

- Baseline: WebPent_FINAL_v6_20261005.zip (sha256 be3ade91…5d0689cb)
- v7 manifest digest (sha256 of frozen_modules.sha256):
  33885034a9da3d945c66ff67c00fcec23d8aaede778414dd74281adda32b2a33
- v6 manifest digest (retired): fb42957d661d5b337a0d08e0cf61d871a0d6a70e28a2ba48216a54cdbbf0a1d2

## 2. Disposition-closure table (BYP → fix → test)

| Finding (M1/R2) | Disposition in v7 | Fix commit | Proof (test) |
|---|---|---|---|
| BYP-02 (OOB seal+confirm outside promotion) | FIXED by E-1: callback path records authority-neutral advisory evidence; ProofBundle/marker/confidence-flip removed from the path | a42d005 | T-04 (real), T-05 (real, hardened), tests/test_r3_e1_advisory.py (10) |
| BYP-05 (dead-code node raise; builder skips node) | FIXED by E-2: build_graph REJECTS composition under UNSUPPORTED_LEGACY_ONLY; node raise retained as defense-in-depth | 89330a0 | T-06 (real, hardened), tests/test_r3_e2_builder_rejection.py (7) |
| Entrypoint truthfulness residual (silent direct_invoke label) | FIXED by E-4 mechanism (b): truthful > derivable > fail-closed derivation; silent fallback removed | 83447b8 | T-03 (updated contract), T-03b (hardened real), tests/test_r3_e4_entrypoint.py (9) |
| B-06 residual (campaign_worker entrypoint vocabulary) | DENIED this window (E-3): campaign_worker.py NOT thawed | 54e8bd9 (reason update) | T-07b stays xfail(strict), reason updated |
| BYP-01 / B-06 core / Hygiene (absent since v5 lineage) | unchanged — still absent (tripwires T-03/T-07 real) | — | T-03, T-07 |

## 3. Amended-ruling closure (RED-1 RF-01..RF-07)

| RED-1 finding | R3 disposition | Proof/demo |
|---|---|---|
| RF-01 CRITICAL (tripwires silently deletable; stale floor) | R1(a): floor 1940→3105 via documented --update; floor gate wired into the acceptance battery | deletion demo: battery exit 1 (3098<3105) |
| RF-02 CRITICAL (build-side laundering ships all-green) | R1(d): external anchor protocol — v6 digest/ZIP pinned in D2; laundering demo reproduces in-package all-green AND anchor catches it | G2 laundering demo: ANCHOR MISMATCH → STOP |
| RF-03 P1 (valid callbacks 500 post-demotion) | E-1 mandatory hunk landed: parity check validates advisory state | tests/test_r3_e1_advisory.py::test_http_204_parity_preserved_after_demotion |
| RF-04 P1 (advisory append not replay-idempotent) | E-1: token-deduped append under BEGIN IMMEDIATE | matrix: repeat → duplicate, single record |
| RF-05 (T-04 needs Amendments A/B/C) | all three applied: docstring rewritten, Finding.advisory_evidence added, fixture asserts save_finding→None | T-04 real, passing |
| RF-06 (T-05 alias/getattr blind; T-06 comment-satisfiable; build completeness) | R1(b)+R1(c): AST-hardened nets (6/6 evasion demo); build refuses missing deliverable classes | net demo log; build refusal exit 2 |
| RF-07 (hygiene gaps; ~97 inherited residue files) | R2: extended hygiene gate (C1–C6 classes) + classification/purge record; 98 tracked residue files purged | hygiene PASS; scripts/r3_residue_classification.json (D6) |

## 4. Known limitations (honest boundaries)

1. E-3 DENY stands: production_spine.py (KNOWN_ENTRYPOINTS) frozen;
   T-07b remains xfail(strict) through Phase 1 ("denied — deferred M3").
2. E-5 (smart-lane/persistence call sites) NOT unfrozen in Phase 1 —
   interim boundaries documented in CAMPAIGN_GUIDE §9 remain in force.
3. Drift registry is per-process (ruling 3.4(iii)): cross-process drift is
   invisible (probe P3 re-proven). Registered for M2.
4. Frozen validator poll (`_poll_for_oob_callback`) waits for
   Tool-Confirmed, which the demoted OOB path never sets — poll times out
   by design; OOB validation outcomes surface as advisory records only.
   Rewiring the poll is registered for M2 (validator NOT thawed in R3).
5. REGISTER FINDING R3-PROBE-01 (pre-existing, M2): the modern-spine node
   is structurally unreachable through the real hunter graph —
   PentestState does not declare target_url/url, and LangGraph drops
   undeclared input keys (empirically proven); production campaigns run
   through the adapter-free/campaign-worker paths. Fix requires the M2
   ingress contract (state.py frozen in R3).
6. OQ-1 narrowed, still open: canonical Dispatch #002 A2/A3/A4/A6/A7/A9
   text outstanding (docs/audit/R3_OQ1_DISPATCH002_ACCEPTANCE_RECORD.md —
   A1/A5/A8/A10 recorded with provenance).
7. OOB confirm route remains default-off (two-layer composition per
   §3.2(vi)); enabling requires WEBPENT_OOB_CONFIRM_ROUTE_ENABLED=true.
8. E-4 known consequence: a production process launched outside the
   documented surfaces (bare uvicorn, custom harnesses) FAILS CLOSED at
   the recon node until launched via worker.py/server.py/webpent-cli.sh/
   `python -m webpent.cli` or an explicit WEBPENT_ENTRYPOINT. This is the
   ratified never-silent-wrong-label behavior.

## 5. Environment incidents

- R3-ENV-01 (4th workspace reset of class): delivery tree + R2-era git
  history + venv state lost. Restored per the documented freeze procedure
  only (PyPI freeze set + PyTorch CPU wheel for torch==2.14.1+cpu);
  517/517 pins exact + editable webpent; pip check EXIT 0. Incident log:
  external D1 §0. No other network use; zero external-target interaction.

## 6. Verification (fresh-extract, G6)

Executed against a fresh extraction of the built v7 ZIP (not the build
tree): tree-diff vs source IDENTICAL; frozen gate 695/695 from extraction;
authority manifest OK (13); full suite 3131 passed + 1 xfailed; battery
153/153 incl. the RF-01 floor gate; register 3/3; g02 4/4; bandit
0H/17M/122L; pip check EXIT 0; closure CLEAN; real-browser smoke 4/4;
hygiene PASS; hardened gates demonstrably active in the extraction
(contracts + floor + delta/anchor tooling present and green).
Detailed numbers: external D1 phase-gate pack (every command + output).

## 7. Deliverable map (in-package)

- WORKLOG.md — in-package process history (R6; NF-03 healing)
- deliverables/r3_dossiers/D4_PER_FIX_DOSSIERS_R3.md — per-fix dossiers
- deliverables/r2_dossiers/ — R2 dossier class (E-1..E-5 lineage)
- docs/audit/R3_OQ1_DISPATCH002_ACCEPTANCE_RECORD.md — R5/OQ-1 record
- scripts/gate_frozen_delta.py, scripts/r3_anchor_check.py,
  scripts/build_delivery_v7.py, scripts/hygiene_gate_extended.py,
  scripts/r3_residue_classification.json, scripts/e4_probe_d3.py —
  R3 gate tooling (re-runnable by R3-V)
- deliverables/requirements_closure.txt + requirements_freeze_final.txt —
  environment artifacts (closure CLEAN; pins exact)

## 8. Reproduction (single commands, from the package root)

```
sha256sum -c frozen_modules.sha256          # 695/695 OK
python scripts/verify_frozen_manifest.py    # authority manifest OK (13)
python -m pytest tests/test_r2_spine_authority_contracts.py \
                 tests/test_r3_e1_advisory.py \
                 tests/test_r3_e2_builder_rejection.py \
                 tests/test_r3_e4_entrypoint.py -q          # R3 contracts
python scripts/hygiene_gate_extended.py     # PASS
python scripts/r3_anchor_check.py           # v7 manifest digest (§1)
bash scripts/run_integration_battery.sh     # floor gate + 153/153
python scripts/poc_smoke_real_browser.py    # 4/4
python -m pytest tests/ -q                  # full suite 3131+1xf
```

## 9. R3 acceptance criteria (Dispatch #005 §8, A1–A12)

Verbatim criteria per the dispatch; verification mapping (R3-V inputs):
A1 manifest-delta == thaw list (§4/D5: exactly 5 src/ files; scope 695);
A2 phase gates green in order (D1 pack); A3 RF amendments landed and
re-runnable (§3 demo column); A4 E-1 matrix green (§6); A5 E-2 surfaces +
default regression (§6); A6 E-4 probe + mechanism per evidence (D3); A7
tripwire pre-fix xfail / post-fix pass (§3, git history); A8 floor wired +
deletion demo, hygiene per-class (D1); A9 suite grew 3105→3132 collected,
zero deletions, C6-listed modifications justified (§3, D4); A10 bandit 0H,
zero new dependencies, network = documented restore only (§5); A11
fresh-extract verification incl. smoke (§6); A12 every claim
single-command reproducible (§8 + D1).
