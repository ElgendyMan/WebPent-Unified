# EVIDENCE REPORT — WebPent v8 (M2-impl, Dispatch #009)

**Window:** UNFREEZE WINDOW #2 — SPRINT M2-IMPL | TEAM-CODE (Super Z) | 2026-10-06
**Baseline:** `WebPent_FINAL_v7_20261005.zip` (sha256 `a226645e…90dc3`; manifest digest `33885034…2a33`)
**Deliverable:** `WebPent_FINAL_v8_20261006.zip` (+ sidecar). Environment: carried over converged from the RED-2 cycle (pip check EXIT 0; **no workspace reset this window** — the 8th reset did not materialize). Foreign-pip-on-PATH trap documented and avoided (all pip via `/home/z/.venv/bin/python -m pip`).

## HEADLINE

1. **NF-M2-01 (P0) IS FIXED END-TO-END**: the research-campaign lane runs through the REAL compiled graph — the window exit gate (graph-level chain test) proves fixture → intake → registration → **rehydration** → campaign **executes** with a NON-EMPTY research loop (`research_campaign_executed=True`, `research_loop_rehydrated≥1`, `research_loop_active_candidates≥1`), with `_modern_orchestrator` absent from state (R2 prohibition holds) and the audit descriptor surviving (WP-A).
2. **Ruling M2-001 landed in full**: R1 (corrected census = implementation baseline: 43 keys declared, 190 → 236), R2 (object transport removed; factory re-derivation via `resolve_spine_orchestrator`), R3 (rehydration via CampaignState v2; equivalence proven registered == recovered), R4 (canonical-only dispatch; hostile dicts neither crash nor ride raw), R5 (audit seam fixed: real `append_event` chain fires; durable dedupe; hardened guard), R6 (five flags consumed fail-closed), R7 (skips operator-visible), R8 (masked tests fixed; genuine through-graph coverage), R9 (register closure), R10 (`production_spine.py` untouched — zero diff).
3. **Riders R1–R4 landed BEFORE the thaw** (G2): floor re-pinned 3105→3132 (deletion-demo RED proven, then green); canonical Dispatch #002 A1–A10 committed verbatim (OQ-1 closed); manifest-vs-HEAD standing gate active; M2 delta gate with full authorization map ran green after EVERY window commit.
4. **NF-R2-01..10: ALL TEN CLOSED** (D4 table) + GAP-R2 wired + `_TEST_ESCAPE_ENV` contained (both escapes pytest-contained).
5. **NEW FINDING — NF-M2I-01 (P2, scope completion)**: the v7 frozen manifest never pinned 12 `src/` files that shipped in v7 (`cli/__main__.py`, 5×`integration/`, `production/validators.py`, 2×`recon/`, 3×`reporter/poc_*`). All 12 verified byte-identical to the v7 baseline, then retro-pinned. The v8 manifest completes the scope: **708 entries** (695 + 12 retro-pinned + 1 authorized new file). Consequence fixes: broad-exceptions gate scope updated (registered sites now hash-pinned — stronger), frozen gate carries the documented M2 thaw union + scope-completion paths.

## PHASE GATES (D1)

| Gate | Result | Evidence |
|---|---|---|
| Phase 0 | PASS | fresh extraction `work/m2impl/v7x` (2654 files; manifest digest anchor match); env converged (522 pkgs, pip check 0, no reset); git baseline commit `c1c1a72` |
| G1 baseline | PASS | 3131 passed + 1 xfail (rc 0, 207.71s) — exact expected baseline |
| G2 riders | PASS | R1 floor 3132 (`--update`; deletion demo RED rc=1 → restored green); R2 canonical file; R3 standing gates green (695); R4 delta gate green (auth map) |
| G3 thaw anchor | PASS | all 6 thaw files PINNED+CLEAN vs manifest & HEAD at baseline |
| G4 window | PASS | WP-A `a0820b9`, WP-B/C/D (atomic per R3), WP-E, WP-F, WP-G, WP-H — delta gate green after every commit (one abort: own smoke residue `artifacts/` — purged, exactly the designed enforcement) |
| G5 re-freeze | PASS | v8 manifest 708 entries; delta == thaw list + scope completion (D5); standing gates green post-refreeze; anchor recorded |
| G6 battery | PASS | full suite **3167 passed + 1 xfail** (rc 0, 208.12s — grew by 36: 23 new contract/gate tests + 13 parametrized manifest pins); battery 153 passed + floor live (rc 0); **bandit 0 HIGH / 17 MED / 122 LOW** (= v7 baseline); hygiene gate PASS (R2 residue disposition: hunt_artifacts audit jsonl purged per R3 classification carried forward, addendum recorded) |
| G7 build+verify | PASS | v8 built with enforcement (see below); fresh-extract verification: tree diff, manifest 708/708, full suite, battery, chain-gate re-run, import-origin proven |

Mid-window gate enforcement proof points: state-contract meta-gate caught one undeclared key during the window (`research_campaign_hypotheses_rejected`) → declared; delta gate caught own smoke residue (`artifacts/`) → purged; g02 meta-gate caught the window's 3 new getattr sites → documented adjudicated regen (+3, all non-transport, script `regen_direct_io_inventory_m2_20261006.py`).

## WP SUMMARY (D3 dossiers in deliverables/m2_dossiers/)

- **WP-A**: audit API mismatch fixed (`append_event`); `_audit_chain` descriptor declared+produced (real hash-chained events fire); object-identity spine token (filename spoofing dead); durable per-engagement dedupe (CampaignState v2 registry); seam bounds re-check (MAX_SOURCE_BYTES/caps).
- **WP-B**: 43 additive declarations; campaign node acquires via factory re-derivation from declared state; orchestrator transport REMOVED; target routed via declared state (`target_url` ladder target_url → target.url → url; empty fails closed); markers survive to final state.
- **WP-C**: mandatory rehydration — CampaignState v2 `registered_candidates` written at registration; campaign node load→factory→re-register; equivalence test green; rehydration evidence keys declared.
- **WP-D**: `canonicalize_campaign_hypothesis` — canonical-only dispatch; hostile/malformed entries rejected+counted+logged (never dispatched raw through AVI; never a crash); AVI field compatibility preserved.
- **WP-E**: every skip/error path emits `RESEARCH CAMPAIGN SKIPPED (operator-visible, R7)`; marker persists; CAMPAIGN_GUIDE documents the contract.
- **WP-F**: NEW `spine_flag_gates.py` — factory-bound flag snapshot (never state/mid-run env), binding-checked (placeholder `target_unknown` denied), five gates: ingress+fixture gates intake, multi-principal gates dispatch, live-proxy unconditional refusal, foreign-report-writer consumed; fixture-cannot-set proven; E-2 composition verified.
- **WP-G**: R8 rewrites (no exception swallowing, no direct-node proof, fake removed — 7 modified test sites in the C5 ledger); NEW exit-gate chain test + 19 contract tests + C10 SqliteSaver additive round-trip.
- **WP-H**: GAP-R2 wired as a real test helper; `_TEST_ESCAPE_ENV` contained in `modern_spine.py` (scoped: env-var block only); D2 census artifact; D4 closure table; C9 docs.

## C-CONSTRAINT LEDGER

- C1 scope: diffs confined to thaw list + authorized non-src classes (delta gate green per commit; final manifest-delta record D5).
- C3 Trust Spine: zero semantic modification; `production_spine.py` byte-identical (R10).
- C4 direction: additive declarations; gates tighten (flag DENY defaults, escape containment, bounds re-check); no new authority path.
- C5 tests: 3132 → 3168 collected (grew; zero deletions); 9 modification groups listed+justified in the WP-G dossier.
- C6 zero new dependencies (uv.lock/pyproject untouched); network = none beyond the standing environment procedure.
- C7 bandit 0 HIGH (0/17/122 = baseline).
- C8 rollback: E-2 composition rejection unchanged+tested; `WEBPENT_MODERN_SPINE=0` downgrade path independence preserved.
- C9 docs: CAMPAIGN_GUIDE M2-impl section (skip visibility, flag semantics, transport design note).
- C10 checkpoint compat: additive resume proven via real SqliteSaver round-trip; no live objects in state (descriptor/projection pattern).

## VERIFICATION (single-command, D6-style)

- Full suite: `python -m pytest tests/ -q --no-header -p no:cacheprovider` → 3167 passed, 1 xfailed
- Battery: `bash scripts/run_integration_battery.sh` → 153 passed, floor gate live
- Exit gate: `python -m pytest tests/team1_acceptance/test_m2_graph_chain_gate.py -q` → 4 passed
- Standing gates: `python scripts/m2_standing_gates.py manifest-vs-head` / `anchor`
- Frozen gate: `python -m pytest tests/test_frozen_module_gate.py -q` → 710 parametrized pins
- Fresh-extract: `sha256sum -c WebPent_FINAL_v8_20261006.zip.sha256` + tree-diff vs HEAD + suite re-run (import-origin proven)
