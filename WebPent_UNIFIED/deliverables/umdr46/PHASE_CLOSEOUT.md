# UM-DR-46 — PHASE CLOSEOUT (Phases A–K)

**Status: Phases A–J LANDED AND PUSHED (9 commits, 6 pushes, all on GitHub at `06eb943`). Phase K benchmark complete — closeout suite was still running at hand-off time (last full-suite measurement before it: 9716 passed / 0 phase-caused failures).**

## What was delivered (per phase — RED→GREEN evidence + wiring + gates)

| Phase | Deliverable | Tests | Commit |
| --- | --- | --- | --- |
| A | Security Knowledge Graph: 9 entity classes (Users→IDENTITY), deterministic query API (`get_all_paths_to`, `ownership_changers`, `reads_without_authz_marker`, `workflow_skip_candidates`, `ui_vs_api_permission_diff`), `skg_evidence` channel, RC-9 fold (v1 retires to a read-only AppModel projection) | 23 | 792e028 |
| B | Researcher Brain (100% deterministic): behavioral profiles, business rules, transition semantics, invariant candidates, contradiction detection recorded in the SSOT (`mark_contradicted`, both evidences KEPT); node `researcher_brain` (appmodel→brain→hypothesis); `HypothesisOrigin.RESEARCHER_BRAIN` | 22 | a6fea8d |
| C | Adaptive hypothesis engine: mutation/decomposition/competing/negative-evidence/info-gain (pure, uuid5 ids, pool dedup); node `hypothesis_evolution` | 15 | 74c048e |
| D | Cross-feature attack chains: info+authz composition, workflow-bypass chains, cross-surface chains; node `attack_chain` | 12 | e5b1067 |
| E | Discovery intelligence: unobserved transitions, parameter siblings, single-path resources, unmarked state triggers; node `discovery_intel` | 8 | cc5f8ac |
| F | Experiment planner: registry-bound plans, complete observed principal matrices only, honest abstention (`blocked_targets`); ResearchLoop stays the sole scheduler; node `experiment_planner` | 7 | 8a5f2aa |
| G | Coverage intelligence: (resource × principal × operation) cells, verified only under guard-adjudicated evidence; node `skg_coverage` | 8 | 468b049 |
| H | Research memory: wall-clock-free lesson compaction + ranking-time demotion lookups (−0.1×refutations, clamped −0.5) — the pool's DECLARED values are lifecycle-protected (UM-DR-44 B2 honored); node `research_memory` | 7 | 468b049 |
| I | Autonomous QC: deterministic deficiency reports (hypotheses/lessons/plans) — never deletes or modifies; node `research_qc` | 9 | 06eb943 |
| J | Multi-protocol depth: workflow sequences, enumerable object-id spaces, cross-origin workflows; node `protocol_depth` | 6 | 06eb943 |
| K | FINAL BENCHMARK: 36 campaigns re-run through the official entrypoint — **identical to baseline (TP=6 FP=0 FN=18, precision=1.0, replay 6/6, zero regressions)**; DELTA_REPORT fail-closed | — | this commit |

**117 new mission tests, all GREEN at their gates.**

## Gate evidence (all verified per phase)

- Phase tests RED→GREEN evidence files: `deliverables/umdr46/evidence/phase_{a,b,c,d,e,f,g}_*.txt`
- Full suite: 9716 passed / 8 fixed / final at hand-off (see below) — `worklogs/fullsuite_*.log` (sandbox-side)
- Frozen-manifest refreeze: `scripts/refreeze_manifest_umdr46_ab.py` (re-pinned 3 trust-chain files + pinned 9 new advisory-node files + removed 3 stale P0.3 entries; 655 entries ≥ floor 630)
- Direct-I/O artifact: regenerated with declared deltas (9 getattr identities, ZERO raw-transport changes) — `scripts/regen_direct_io_inventory_umdr46_ab.py`
- Broad-exception register: 9 new fail-soft node boundaries registered + documented (`docs/ACCEPTED_EXCEPTIONS_REGISTER.md`)
- Dead-code ratchet: 149 ≤ 149 OK; marker ratchet: OK; ruff ratchet: improved (8040 < 8147)
- Secret scan: PASS (one documented allowlist entry: the frozen P0.5 battery's out-of-scope dummy fixture)
- Topology pins updated per phase: 57→68 nodes (11 advisory nodes), each documented in `tests/test_vip_parallel_recon.py`

## Baseline integrity (the P0.5 comparability law)

`BASELINE_METRICS.json` / `BASELINE_REPORT.md` / `run_files/` UNTOUCHED (the final battery writes to `final_benchmark/` only).

## Honest residuals

1. The closeout full suite (after Phase K) was still running at hand-off; the last COMPLETE full-suite measurement (post-I/J code, pre-K docs) was 9716 passed with zero mission-caused failures. The three mechanical failures seen mid-session (broad-ex register, g02 artifact, frozen re-pin) were each fixed and re-verified green before the corresponding push.
2. CI on pushes #3–#6 was still in the GitHub Actions queue at hand-off (4 runs in flight); push #1 (25ac194) CI failed PRE-EXISTING on the branch (the P0.3 manifest omission this mission repaired in commit 74c048e) — pushes after that repair carry the fix.
3. Phases were batched into 6 pushes (not 9) per the push-economy law; counts stated honestly: 6 pushes, 9 phase commits (+1 closeout commit).

## Recovery pointer

`scripts/RECOVERY_STATE_UMDR46.md` (sandbox-side) + this file: any fresh session can resume from `git clone` + the GOVERNANCE_INDEX rows, which ARE the durable mission memory on GitHub.
