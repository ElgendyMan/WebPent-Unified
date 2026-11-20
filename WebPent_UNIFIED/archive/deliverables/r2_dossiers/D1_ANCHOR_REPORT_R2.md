# D1 — ANCHOR REPORT: M1 AUDIT RE-ANCHORED ON v5 HEAD

**Sprint:** R2 Choke-Point Restoration, Phase 1 (MVP) — Orchestrator Dispatch #002
**Baseline:** WebPent_FINAL_v5_20261005.zip — SHA256 `f23aadbd35accaff7ec7b756b80ea7bbe95ab7ca724d3595fd74522d76948ca1` (verified on fresh extraction)
**Audited snapshot being re-anchored:** `TEAM2_AVI_V1_2_POST_CLOSURE_FULL_PROJECT.zip` (tree hash `02c16401…`) — M1 citations do NOT carry over verbatim; every item below was re-derived on the v5 tree.
**Method:** read-only re-derivation on the v5 extraction BEFORE any change; freeze status checked against the in-repo manifest `frozen_modules.sha256` (695 files, `sha256sum -c` = 695/695 OK from this extraction).

---

## 0. HEADLINE RESULT

The v5 lineage is **not** the tree M1 audited. Between the M1 snapshot and v5, at least two later
sprints (annotated in-code as "Sprint I-1, item 1.3", "Sprint I-1b, item 2.1 (BYP-05)", "FIX 1",
"Sprint I-1 Continuation Part 4", "V5 Sprint 5/8/9", "Sprint R1 FIX 2") already landed and were
absorbed into the frozen manifest. Consequences, per finding:

| Item | M1 verdict (old tree) | v5 verdict | Consequence for this sprint |
|---|---|---|---|
| BYP-01 | PRESENT (direct construction) | **ABSENT** — factory routing landed | Nothing to apply; contract tests added (T-01..T-03 mapped); one residual gap recorded (entrypoint provenance) |
| BYP-02 | PRESENT (seal+confirm outside promotion) | **PRESENT** (drifted lines, additional mitigations) | Fix target frozen → UNAPPLIED dossier per C2 |
| BYP-03 | PRESENT (parallel lane) | **PRESENT** (drifted lines) | All persistence sites frozen → boundary note + escalation dossier (per R2-05 condition) |
| BYP-04 | PRESENT (second authority) | **PRESENT** (drifted lines) | No editable seam → operator procedure + escalation dossier (per R2-06 condition) |
| BYP-05 | PRESENT (silent re-route) | **PRESENT — partially fixed with a dead-code raise**: node-level raise exists, but the graph wiring skips the node when disabled, so the re-route persists on the production path | Fix target frozen → UNAPPLIED dossier per C2 (T-06 pins the gap) |
| B-06 | PRESENT (hand-built loopback profile) | **ABSENT (core)** — factory + canonical profile landed; **one residual**: `entrypoint="worker"` where the ratified directive says `campaign_worker` (not in `KNOWN_ENTRYPOINTS`) | Residual frozen → dossier line-item |
| Hygiene | PRESENT (dead/dup imports) | **ABSENT** — ruff F811/F401 clean on both cited files | Note-and-park resolved as "nothing to do" (D7) |

**STOP CONDITIONS (6.2):** none triggered. No audited module is absent from v5. Where logic drifted,
the drift is the v5 lineage absorbing later remediation sprints; in every case the ratified fix
design remains valid against the v5 code as read (corrected line numbers below), so items proceed
to either "already satisfied" or "C2 dossier mode" — no improvisation was required or performed.

---

## 1. FREEZE-STATUS TABLE (every file a ratified fix would touch)

Verified against `frozen_modules.sha256` (authoritative manifest shipped in v5; gate re-run on this
extraction: **695/695 byte-identical, exit 0**).

| File (v5 path) | Frozen? | Audited role | Would be touched by |
|---|---|---|---|
| `src/webpent/production/modern_spine_integration.py` | **FROZEN** | BYP-01 construction site; BYP-05 node mode/raise; seam `modern_spine_execution_authorized` | R2-01, R2-03 |
| `src/webpent/production/production_spine.py` | **FROZEN** | The factory (`resolve_production_spine`, `KNOWN_ENTRYPOINTS`, drift registry, `ProductionTrace`) | R2-01(v) — must not touch; R2-04 entrypoint vocabulary |
| `src/webpent/graph/builder.py` | **FROZEN** | Node wiring `_combined_recon_node` (BYP-05 graph path); campaign-node fail-closed; hygiene import site | R2-01(ii), R2-03, R2-07 |
| `src/webpent/api/app.py` | **FROZEN** | OOB receiver + ProofBundle seal + confirm call; OOB routes | R2-02 |
| `src/webpent/memory/db.py` | **FROZEN** | `mark_oob_confirmed` (confidence flip) | R2-02 |
| `src/webpent/production/campaign_worker.py` | **FROZEN** | B-06 target | R2-04 |
| `src/webpent/cli/commands.py` | **FROZEN** | Finding-persistence call site | R2-05 |
| `src/webpent/workers/pentest_worker.py` | **FROZEN** | Finding-persistence call site (`_persist_findings`) | R2-05 |
| `src/webpent/config/settings.py` | **FROZEN** | `scan_mode` / smart-profile config | R2-06 |
| `src/webpent/state/initial_state.py` | **FROZEN** | Profile resolver | R2-06 |
| `src/webpent/agents/smart_campaigns/agent.py` | **FROZEN** | Smart execution path | R2-06 |
| `src/webpent/shared/action_authority.py` | **FROZEN** | Second authority model | R2-06 |
| `src/webpent/shared/runtime.py` | **FROZEN** | ActionAuthority construction | R2-06 |
| `src/webpent/shared/campaign_executor.py` | **FROZEN** | ActionAuthority use | R2-06 |
| `src/webpent/production/modern_spine.py` | **FROZEN** | Hygiene duplicate-imports site | R2-07 |
| `tests/team1_acceptance/test_durable_research_state.py` | non-frozen | B-06 durability test | R2-04 (test update — see dossier: left untouched, justified) |
| `tests/` (new files) | non-frozen | Contract tests | T-01..T-07 |
| Editable orchestration surfaces: `entrypoint.sh`, `Makefile`, `docker-compose*.yml`, `webpent-cli.sh` | non-frozen | Env-var threading per R2-01(ii) | See §2.1 — deliberately NOT wired (rationale in dossier) |

**Definitive editable surface under `src/` (14 files, none on any audited authority path):**
`cli/__main__.py`, `integration/{browser_hypothesis_bridge,hypothesis_priority_contract,learning_ab_contract,planner_enrichment_bridge,session_recovery_bridge}.py`, `production/validators.py`, `recon/{auth_resilience,session_recovery}.py`, `reporter/{poc_cli,poc_export,poc_recorder}.py`, `templates/reports/{html,report.html.j2}`.
→ **Every semantic fix target of Section 3 is frozen.** This is the fact that drives the sprint's
dossier-mode shape; per C2 nothing was applied to any frozen file and no unfreeze was performed.

---

## 2. PER-FINDING ANCHORS (corrected v5 line numbers)

### 2.1 BYP-01 — factory bypass — verdict: **ABSENT on v5** (already remediated in lineage)

M1 evidence: direct `ModernOrchestrator(engagement_id=…, scope_law=…, tool_boundary=…, advisory_memory=…)` at `modern_spine_integration.py:72-77`; factory with zero production callers.

v5 state (all re-derived on this tree):
- `modern_spine_integration.py:81-113` — annotated **"FIX 1: construct via the single authoritative factory"**: imports `ProductionSpineConfig, resolve_production_spine` (:93), builds `ProductionSpineConfig(engagement_id=…, target_url=…, entrypoint=state.get("entrypoint") or "direct_invoke")` (:103-107), resolves through the factory (:108), attaches caller-supplied `tool_boundary`/`advisory_memory` post-resolution as plain attributes (:109-112), and records `state["_production_trace"] = production_trace.summary()` (:113).
- Repo-wide sweep for direct construction: **exactly one** `ModernOrchestrator(` call in `src/` — inside the factory itself (`production_spine.py:392`, guarded by `_FACTORY_TOKEN`; `modern_spine.py:169` documents that the token is held by the factory).
- Factory enforcement verified present on v5 (`production_spine.py`): entrypoint vocabulary + engagement/target validation + `modern_spine_enabled=False` hard reject (:139-150); strict-bool flag resolution with fail-closed defaults (:62-91); per-engagement config-digest drift registry raising `ProductionSpineError` (:344-355); `ProductionTrace` with required stages incl. `entrypoint_resolve` and `flag_resolution` bound to engagement + target fingerprint (:274-279, :357-378); canonical ScopeLaw derivation via `build_authorized_lab_profile` (:380-389); `entrypoint_parity_check` (:403-437).
- Other production callers all factory-routed: `autonomous_validation_v1.py:835`, `autonomous_recon.py:89`, `campaign_worker.py:69` (plus the graph node above).
- Existing test coverage: `tests/test_orchestrator_construction_authority.py` (construction is factory-only; direct construction raises without factory token/escape; factory resolves), `tests/team1_acceptance/test_sprint_i1_part2_flag.py::test_flag_is_drift_registered` (registry drift fails closed).

**Residual gap recorded (not in M1, surfaced by this re-anchor):** `state["entrypoint"]` has **no setter anywhere** in `src/` (sweep: only the node reads it, `modern_spine_integration.py:102`). Every graph run therefore resolves as `"direct_invoke"` — a value that IS in `KNOWN_ENTRYPOINTS` (:32) and whose in-code rationale (:97-101) is truthfulness ("no convention establishes which top-level channel invoked this node"), but which cannot distinguish cli/worker/campaign_worker as R2-01(ii) requires. All would-be setters (`cli/commands.py`, `api/app.py`, `workers/pentest_worker.py`, `state/initial_state.py`) are frozen → **residual goes to the R2-01 dossier with a proposed diff**. The dispatch's fallback ("set an explicit env var at editable orchestration surfaces") was evaluated and **deliberately not wired**: the frozen node reads `state["entrypoint"]`, not any environment variable, so surface-level env wiring would be inert config — adding it would satisfy the letter of (ii) while providing zero enforcement, contrary to C4's fail-closed-only discipline and to honest documentation. The dossier instead proposes the minimal frozen-side diff (read `WEBPENT_ENTRYPOINT` as a fallback inside the node) plus the editable-surface wiring as one coherent patch.

### 2.2 BYP-02 — OOB confirmation outside promotion authority — verdict: **PRESENT on v5** (drifted lines; hardened but same authority semantics)

M1 evidence: `app.py:1677-1692` builds+seals a ProofBundle with `causal_oracle={"decision":"CONFIRMED"}`; `app.py:1697` → `memory/db.py:1192-1205` sets Tool-Confirmed/CONFIRMED; routes at `app.py:1952,1993`.

v5 state (corrected anchors):
- `app.py:1852-1938` `_oob_db_lookup_and_confirm` — builds a ProofBundle via `build_proof_bundle(...)` with `causal_oracle={"decision": "CONFIRMED", "basis": "oob_callback_with_per_finding_token_correlation"}` (:1912-1927) and calls `db.mark_oob_confirmed(...)` (:1932-1938). In-code comment (:1864-1875) explicitly re-asserts the confirmation authority with token correlation as the negative control — a design position the ratified disposition supersedes ("token correlation alone is not causal proof").
- `app.py:2189-2205` — handler requires the flip to have happened (`confidence_level == "Tool-Confirmed"` or 500) and logs "upgraded to Tool-Confirmed".
- `app.py:2208-2247` route `GET/POST /api/oob/{finding_id}/{secret}`; `app.py:2250-2290` workspace-scoped route `GET/POST /api/oob/{thread_id}/{finding_id}/{secret}` (M1's `:1952,1993`).
- `db.py:1209+` `mark_oob_confirmed` — flips `confidence_level → "Tool-Confirmed"`, `confidence → Confidence.CONFIRMED`, validates causal observation + sealed negative-control bundle structure before writing (fail-closed on malformed input, but the semantics are confirmation).
- **Mitigations present on v5 (recorded, they bound but do not remove the violation):** `_reject_if_oob_confirm_route_disabled` (:1943-1961, "Sprint R1 FIX 2") — fail-closed master switch `settings.oob_confirm_route_enabled`, **default disabled**, both routes call it first (:2232, :2286); empty global secret → 503 (:2004-2013); per-finding constant-time token validation (:1793-1826); workspace split-brain fail-closed (:2055-2073); 64KB body cap (:2116-2135).
- Receiver authentication unchanged vs M1's (v) requirement: per-finding token comparison preserved.

Disposition per ratified record: FIX NOW → demote to advisory-evidence-only. **Both fix targets frozen → UNAPPLIED dossier (D2/R2-02) with proposed diff + unfreeze request.** The (iv) editable-quarantined-store branch was evaluated and is **unreachable**: the receiver itself is frozen, so no editable code on the callback path exists that could write an advisory record anywhere; storing advisory records in a side store without changing the receiver would leave the ProofBundle-sealing and confidence-flip semantics fully intact — i.e., it would not implement the ratified directive. Documented as "impossible → dossier" exactly per (iv).

### 2.3 BYP-05 — UNSUPPORTED_LEGACY_ONLY re-routes instead of rejecting — verdict: **PRESENT on v5** (partially fixed; the raise is dead code on the production graph path)

M1 evidence: `modern_spine_integration.py:33-37` mode constants; node early-return `:61-64` silently continues via legacy; `builder.py:1327` if-false branch skips modern recon → legacy runs alone.

v5 state (corrected anchors):
- `modern_spine_integration.py:35-40` — mode resolution unchanged in shape (`MODERN_SPINE_ENABLED = MODERN_SPINE_MODE != "UNSUPPORTED_LEGACY_ONLY"`; `WEBPENT_MODERN_SPINE=0` alone only downgrades to `COMPATIBILITY_LEGACY`).
- `modern_spine_integration.py:61-79` — **"Sprint I-1b, item 2.1 (BYP-05)"**: the silent early-return was replaced by `raise UnsupportedLegacyOnlyModeError(...)` with a loud, named message pointing at the invariant "never re-route, only reject". Exception type exists (`shared/exceptions.py:27`).
- **However** — the raise is only reachable if the node is CALLED while disabled. The production graph wiring (`builder.py:1338-1370`, `_combined_recon_node` inside `build_graph`) guards the call with `if MODERN_SPINE_ENABLED:` (:1341). When the mode is `UNSUPPORTED_LEGACY_ONLY` the branch is skipped and legacy `recon_node` runs alone (:1349-1364) — **exactly the re-route the invariant forbids, now one level above the fixed node**. The downstream campaign node remains fail-closed (`builder.py:1375-1378`, `research_campaign_skipped: no_orchestrator` — R2-01(vii) preserved), so the re-route degrades recon/knowledge only, matching M1's severity bound.
- Existing test coverage pins the node-level raise only (`tests/team1_acceptance/test_sprint_i1b_part2_byp05.py` calls `modern_spine_recon_node` directly); **no test covers the graph path** — the gap is untested, which is how it survived the I-1b fix.

Disposition per ratified record: FIX NOW → reject fail-closed with a loud marker. **Fix target (`builder.py` disabled-branch) frozen → UNAPPLIED dossier (D2/R2-03) with proposed diff + unfreeze request.** T-06 ships as an executable, currently-xfailed contract so the violation is reproducible by a single command (A10) and flips green when the unfreeze lands.

### 2.4 B-06 — campaign worker hardcodes profile — verdict: **ABSENT on v5 (core)**, one residual

M1 evidence: `production/campaign_worker.py:47-81` hand-builds an AuthorizedLabProfile with hardcoded `127.0.0.1`/`localhost`; durability test cites factory-less path.

v5 state (corrected anchors):
- `campaign_worker.py:55-69` — annotated **"FIX 1"**: constructs via `resolve_production_spine(ProductionSpineConfig(engagement_id=state.engagement_id, target_url=state.target_url, entrypoint="worker"))`; the comment records that the old explicit loopback entries were already no-ops under `AuthorizedLabProfile.is_target_authorized()`. Source sweep of the module: **no** `127.0.0.1`/`localhost` profile literals remain.
- Fail-closed startup gate retained: `enforce_construction_escape_gate()` (:20-21, `shared/preflight.py`).
- **Residual:** entrypoint is `"worker"` (:67), not the ratified `"campaign_worker"` — and `"campaign_worker"` is not in the frozen `KNOWN_ENTRYPOINTS` (`production_spine.py:32` = {cli, api, worker, direct_invoke}); constructing with it today would raise `ProductionSpineError` (:140-141). The dispatch requires the worker/campaign_worker distinction, so this is a real (small) gap. Both files frozen → **dossier line-item (D2/R2-04)** with the proposed two-file diff. The durability test (`tests/team1_acceptance/test_durable_research_state.py`, non-frozen) was **deliberately left untouched**: it passes against the current frozen behavior; updating it to a factory/vocabulary assertion that cannot hold until the unfreeze lands would violate C6. The proposed test change ships inside the dossier.

### 2.5 BYP-03 — parallel legacy lane — verdict: **PRESENT on v5** (drifted lines) → escalation dossier

- Finding-persistence call sites (corrected v5 lines): `cli/commands.py:944` (`db.save_finding(finding)`), `workers/pentest_worker.py:224-259` (`_persist_findings` → `db.save_finding` at :250). **Both files frozen.**
- The unwired seam persists: `modern_spine_execution_authorized` (`modern_spine_integration.py:239-257`) still has **zero production callers** (repo-wide sweep: only its `__all__` entry).
- R2-05 condition resolved: "IF all are frozen: boundary note in D5 + escalation dossier. Do not force it." → **D2/R2-05 escalation dossier + D5 boundary note.** T-08 not applicable (nothing landed).

### 2.6 BYP-04 — ActionAuthority second authority — verdict: **PRESENT on v5** (drifted lines) → escalation dossier

- All smart-path files frozen: `config/settings.py` (`scan_mode` default `LEGACY`, env-tunable via `WEBPENT_SCAN_MODE`/`SCAN_MODE`/`SCAN_PROFILE`, :306-319), `state/initial_state.py` (profile resolver; `_profile_enables_autonomous_controller` :49-57), `agents/smart_campaigns/agent.py`, `shared/action_authority.py`, `shared/runtime.py`, `shared/campaign_executor.py`.
- No editable seam exists anywhere on the path → per R2-06: **documented operator procedure (D5 §4.2) + escalation dossier (D2/R2-06)**. The SDD §8-conformant flag machinery itself already exists in the frozen factory (strict-bool, engagement+fingerprint-bound, trace-recorded — `production_spine.py:43-110, 360-378`), which is the natural home the unfreeze request builds on.

### 2.7 Hygiene — dead/duplicate imports — verdict: **ABSENT on v5**

- `ruff check --select F811,F401` on `src/webpent/graph/builder.py` and `src/webpent/production/modern_spine.py`: **clean**.
- `builder.py:77-83` (the audit's `:78` neighborhood): the smart-campaigns import block — all four imported names used (usage sweep: each ≥2 occurrences incl. import).
- `modern_spine.py:36-43`: no duplicate imports present.
- Disposition: note-and-park resolved as **"nothing to do — already clean on v5"** (recorded in D7; no diff proposed).

---

## 3. ENVIRONMENT / BASELINE INCIDENTS (6.1)

- No environment drift detected this session: venv pins match the shipped freeze file exactly (`langgraph==1.2.10`, `langgraph-checkpoint-sqlite==3.1.1`, `playwright==1.57.0`, `celery==5.6.3`, `fastapi==0.142.2`, `pydantic==2.12.5`, `cryptography==50.0.2`); `pip check` exit 0; `SqliteSaver` imports.
- Baseline from the fresh extraction: full suite **3098/3098 pass** (180.15s), integration battery **153/153 pass** (exit 0), frozen manifest **695/695** (exit 0), authority manifest **OK (13 files)**. Baseline green → cleared to proceed.

## 4. SPRINT-SHAPE CONSEQUENCE (for the Orchestrator's record)

Because every semantic target is frozen, the ratified Section-3 directives resolve as follows:
**applied in this sprint** = contract tests that pin the already-landed fixes (T-01..T-03 analogues verified present; T-03/T-07 gap-filling tests added and passing) + executable dossier contracts (T-04/T-05/T-06 as strict-xfail, currently red-by-design, single-command reproducible) + dossiers with proposed diffs/unfreeze requests + boundary documentation;
**not applied (per C2, awaiting Orchestrator unfreeze ruling)** = every frozen-file semantic change (R2-01 residual, R2-02, R2-03, R2-04 residual).
No frozen file was modified; no Trust Spine component (C3 list) was touched semantically; no new dependency, no network activity, no target execution (C5/A6).
