# EVIDENCE_REPORT_20261005_v6 — SPRINT R2: CHOKE-POINT RESTORATION (PHASE 1 MVP)

**Supersedes:** EVIDENCE_REPORT_20261005_v5.md
**Dispatch:** Orchestrator Dispatch #002 (TEAM-CODE) — implement exactly the ratified
disposition record for M1 findings BYP-01..BYP-05, B-06, Hygiene, on the v5 baseline,
deliver verified v6.
**Baseline:** WebPent_FINAL_v5_20261005.zip — SHA256 `f23aadbd35accaff7ec7b756b80ea7bbe95ab7ca724d3595fd74522d76948ca1`
**AMENDMENT BANNER (v6):** this sprint's defining result is an **anchor** result. The M1 audit
was performed on an older snapshot (`TEAM2_AVI_V1_2`, tree `02c16401…`). Re-anchoring on v5
(D1, §6.2 mandatory step) showed that the v5 lineage had ALREADY absorbed remediation for the
largest findings, and that every remaining fix target is a FROZEN file. The sprint therefore
delivers: anchor report, executable contracts (including strict-xfail tripwires), unapplied
patch dossiers + unfreeze requests, escalation dossiers, and boundary documentation — and
**zero semantic changes to `src/`** (C2/C3/C4 held by construction).

---

## 1. BASELINE (6.1) — GREEN BEFORE ANY CHANGE

| Gate | Command | Result |
|---|---|---|
| Archive integrity | `sha256sum WebPent_FINAL_v5_20261005.zip` | `f23aadbd…76948ca1` — MATCH |
| Fresh extraction | `unzip` → file count | 2731 files |
| Frozen manifest | `sha256sum -c frozen_modules.sha256` | **695/695 OK, exit 0** |
| Authority manifest | `python3 scripts/verify_frozen_manifest.py` | **OK (13 files)** |
| Environment vs shipped freeze | importlib.metadata vs `deliverables/requirements_freeze_final.txt` | exact match: `langgraph==1.2.10`, `langgraph-checkpoint-sqlite==3.1.1`, `playwright==1.57.0`, `celery==5.6.3`, `fastapi==0.142.2`, `pydantic==2.12.5`, `cryptography==50.0.2`; **no restore needed** |
| pip check | `pip check` | **No broken requirements found (exit 0)** |
| Full suite | `pytest tests/ -q` | **3098 passed** in 180.15s |
| Integration battery | `bash scripts/run_integration_battery.sh` | **153 passed, exit 0** |

## 2. ANCHOR REPORT (6.2) — headline per-finding verdicts on v5

Full evidence, corrected line numbers, and the 16-file freeze table: `deliverables/r2_dossiers/D1_ANCHOR_REPORT_R2.md`.

| Item | v5 verdict | One-line evidence (v5 lines) |
|---|---|---|
| BYP-01 | **ABSENT** (fixed in lineage) | node resolves via `resolve_production_spine` (`modern_spine_integration.py:93-113`); sole remaining `ModernOrchestrator(` in src/ is inside the factory itself (`production_spine.py:392`, factory-token-guarded) |
| BYP-01 residual | PRESENT (gap) | no setter of `state["entrypoint"]` anywhere in src/ — all runs resolve `"direct_invoke"` (truthful but cannot distinguish cli/worker/campaign_worker) |
| BYP-02 | **PRESENT** (drifted; hardened) | `app.py:1912-1938` builds+seals ProofBundle `decision=CONFIRMED` + `mark_oob_confirmed`; routes `:2208-2290`; mitigations: default-off master switch `:1943-1961`, per-finding token, body cap |
| BYP-03 | **PRESENT** (drifted) | persistence sites `cli/commands.py:944`, `workers/pentest_worker.py:224-259`; seam `modern_spine_execution_authorized` still has zero production callers |
| BYP-04 | **PRESENT** (drifted) | smart lane files all frozen (`settings.py:306-319` scan_mode default LEGACY, env-tunable) |
| BYP-05 | **PRESENT — dead-code raise** | node raises `:61-79` (Sprint I-1b) but `builder.py:1341` skips the node when disabled → legacy runs alone on the graph path (the invariant violation, one level up); only the node-level raise is tested today |
| B-06 | **ABSENT (core)** + residual | factory construction `campaign_worker.py:55-69`, no loopback literals in active code; residual: `entrypoint="worker"` vs ratified `"campaign_worker"` (not in frozen `KNOWN_ENTRYPOINTS` `production_spine.py:32`) |
| Hygiene | **ABSENT** | ruff F811/F401 clean on both cited files |

**STOP CONDITIONS:** none triggered (no module absent; all drifts analyzed in D1 §0/§2 — each is
the v5 lineage absorbing later remediation sprints, and each ratified fix design remains valid
against v5-as-read). No improvisation was performed.

## 3. DISPOSITION-CLOSURE TABLE (what R2 delivered per directive)

| Directive | Disposition executed | Where |
|---|---|---|
| BYP-01 (P0) FIX NOW | Core: **verified already-landed** + contract tests; residual: **C2 dossier + unfreeze request E-4** (entrypoint provenance) | D1 §2.1, D2/R2-01, tests T-03/T-03b |
| BYP-02 (P0) FIX NOW | **C2 dossier + unfreeze request E-1** (advisory-only demotion, proposed diff) + executable tripwires | D2/R2-02, tests T-04/T-05 (xfail-strict) |
| BYP-03 (P1) CONDITIONAL | Condition resolved: **all persistence sites frozen** → boundary note + escalation dossier E-5; not forced | D1 §2.5, D2/R2-05, D5 §4.3 |
| BYP-04 (P1) CONDITIONAL | Condition resolved: **no editable seam** → operator procedure + escalation dossier E-5; not forced | D1 §2.6, D2/R2-06, D5 §4.2 |
| BYP-05 (P2) FIX NOW | **C2 dossier + unfreeze request E-2** (builder-level fail-closed rejection, proposed diff) + executable tripwire | D2/R2-03, test T-06 (xfail-strict) |
| B-06 (P3) FIX NOW | Core: **verified already-landed** + contract test; residual (`campaign_worker` entrypoint): **C2 dossier + unfreeze request E-3** | D1 §2.4, D2/R2-04, tests T-07/T-07b |
| Hygiene (P3) | Condition resolved: **already clean on v5** — note-and-park resolved as nothing-to-do | D1 §2.7, D7 |

**A1 compliance:** every FIX-NOW item either has its ratified effect verified present on v5 with
new passing contract tests, or carries an escalated dossier whose frozen-target justification is
the 695-manifest itself (C2). Nothing was applied to frozen files; nothing was self-unfrozen.

## 4. OPERATOR-VISIBLE BEHAVIOR + INTERIM BOUNDARIES (C9 / A8)

No runtime behavior changed in v6 (zero `src/` diffs). The operator-facing changes are
documentation: `docs/CAMPAIGN_GUIDE.md` §9 "Interim authority boundaries":

- **§9.1** keep `WEBPENT_OOB_CONFIRM_ROUTE_ENABLED` unset (default-off) on Phase 1 engagements — the armed route flips findings outside PromotionPipeline until E-1 lands (F-04 context: the pathway is inert in default deployments; the demotion remains required because one flag arms it).
- **§9.2** Phase 1 engagements run the default `LEGACY` scan profile; do not set `WEBPENT_SCAN_MODE`/`SCAN_MODE`/`SCAN_PROFILE` to smart profiles until E-5's enforcement design is ruled on.
- **§9.3** never deploy `WEBPENT_MODERN_SPINE_MODE=UNSUPPORTED_LEGACY_ONLY`; the SDD §8 flag-based rollback is the only supported rollback.
- **§9.4** single-command verification of this section.

## 5. TEST EVIDENCE (D3)

New file `tests/test_r2_spine_authority_contracts.py` (7 tests):

| Test | Kind | Maps to | State |
|---|---|---|---|
| `test_t03_graph_node_records_production_trace` | REAL (passing) | R2-01(iv)/T-03 | pins the landed factory trace in graph state (entrypoint fallback ∈ KNOWN_ENTRYPOINTS, 16-hex config digest, required early stages) |
| `test_t03b_entrypoint_has_no_production_setter` | REAL (passing) | R2-01(ii) residual | pins the residual itself; its failure message instructs the same-commit update when E-4 lands |
| `test_t07_campaign_worker_uses_factory_no_loopback` | REAL (passing) | R2-04/T-07 | factory construction, no hand-built profile, no loopback in active code, entrypoint literal ∈ KNOWN_ENTRYPOINTS |
| `test_t07b_campaign_worker_entrypoint_is_campaign_worker` | xfail (strict) | R2-04 residual | ratified `"campaign_worker"` — passes only after E-3 |
| `test_t05_sole_confirmation_authority_inventory` | xfail (strict) | T-05/BYP-02 | architectural inventory: `mark_oob_confirmed` must have no caller outside promotion — currently violated by app.py |
| `test_t04_oob_callback_is_advisory_only` | xfail (strict) | T-04/BYP-02 | behavioral: valid token must NOT flip confidence + advisory record must be attached — currently violated |
| `test_t06_builder_rejects_unsupported_legacy_only` | xfail (strict) | T-06/BYP-05 | graph wiring must raise the loud rejection — currently the disabled branch skips and runs legacy alone |

Existing-test modifications: **NONE** (C6: zero modified, zero deleted; count grew 3098 → 3105).
Pre-existing coverage mapped for TEAM-REVIEW: T-01 → `tests/test_orchestrator_construction_authority.py` (3 tests), T-02 → `tests/team1_acceptance/test_sprint_i1_part2_flag.py::test_flag_is_drift_registered`, T-09 → full suite + battery (no semantic change to regress).

## 6. GATE BATTERY RESULTS (6.5, post-change) — ALL GREEN

| Gate | Result |
|---|---|
| Full suite `pytest tests/ -q` | **3101 passed, 4 xfailed** in 180.97s (3098 baseline + 7 new: 3 passing + 4 designed-xfail dossier tripwires; exit 0) |
| Frozen manifest | **695/695 OK** (exit 0) |
| Integration battery | **153/153, exit 0** |
| Broad-exceptions register gate | **3/3** |
| g02 direct-I/O inventory gate | **4/4** (no inventory shift — zero src/ changes) |
| bandit src/ | **0 HIGH / 17 MEDIUM / 122 LOW** — identical to v5 baseline; no new findings to triage (A5) |
| pip check | **exit 0** |
| Dependency closure audit | **VERDICT: CLEAN** (1 accepted residual: chromadb 1.5.9, 4 advisories — unchanged, tracked upgrade) |

## 7. CONSTRAINT COMPLIANCE

- **C1 scope:** only Section 3 items handled; discovered items registered (D7 F-01..F-06), none fixed; ingress contract (M2) NOT pre-implemented.
- **C2 frozen modules:** 695/695 byte-identical before and after; zero unfreeze performed; every frozen-target fix = unapplied dossier + unfreeze request.
- **C3 Trust Spine:** zero semantic changes anywhere in src/ — the C3 list is trivially intact (no src/ file was modified at all).
- **C4 fail-closed-only:** the only applied artifacts are additive documentation and tests; every dossier diff REMOVES authority or tightens checks; the one rejected design (inert env-var wiring) is documented in D2/R2-01 with the C4 rationale.
- **C5:** zero new dependencies (closure audit unchanged), zero network activity, zero target execution, no pip installs (no egg-info contamination; hygiene-verified).
- **C6:** 3098 pre-existing tests all pass unmodified; count grew only; xfail tests are new, not modified pre-existing tests.
- **C7:** full battery executed (§6); g02 unshifted; register gate green.
- **C8:** SDD §8 rollback definition untouched and still valid; BYP-05 dossier explicitly points operators to it.
- **C9:** CAMPAIGN_GUIDE §9 documents the interim boundaries (§4 above).

## 8. ENVIRONMENT INCIDENTS

None this session. The known incident class ("environments reset between sessions") was checked
for and did not occur: the venv matched the shipped freeze file exactly (§1), so no restore was
needed. Recorded for continuity.

## 9. VERIFICATION REPLAY (A10 — every claim, one command)

```bash
sha256sum WebPent_FINAL_v6_20261005.zip                                 # §D6 hash
sha256sum -c frozen_modules.sha256                                      # 695/695 (C2)
python3 -m pytest tests/ -q                                             # 3101 passed, 4 xfailed
python3 -m pytest tests/test_r2_spine_authority_contracts.py -v         # 3 passed + 4 designed-xfail
bash scripts/run_integration_battery.sh                                 # 153/153
python3 -m pytest tests/test_editable_broad_exceptions_gate.py tests/test_g02_direct_io_inventory.py -q  # 3/3 + 4/4
python3 -m bandit -r src/ -q -f json | python3 -c "import json,sys; d=json.load(sys.stdin); print({r['issue_severity']: sum(1 for x in d['results'] if x['issue_severity']==r['issue_severity']) for r in d['results']} or '0 findings')"   # 0 HIGH
pip check                                                               # exit 0
python3 scripts/dep_closure_audit.py                                    # VERDICT: CLEAN
python3 scripts/poc_smoke_real_browser.py                               # real-browser smoke 4/4
```

## 10. HONEST LIMITATIONS (carry-forward + new)

1. **The audited violations BYP-02 / BYP-05 (graph path) / BYP-03 / BYP-04 remain live in v6** — bounded by the documented mitigations (OOB route default-off; scan_mode default LEGACY; campaign node fail-closed) and pinned by executable tripwires, but not eliminated: every fix target is frozen, and C2 forbids self-unfreeze. The unfreeze requests E-1..E-5 are ready for ruling.
2. **Entrypoint provenance is coarse** (`direct_invoke` for all graph runs; campaign subprocess labels as `worker`) — truthful, never guessed, but not yet distinguishing per R2-01(ii)/R2-04 until E-3/E-4 land.
3. Carry-forward from v5 (unchanged): frozen ledger without WAL-mode file for the audit chain, 2 pinned unapproved transport identities in the direct-I/O inventory, chromadb 2.x upgrade sprint, BYP-01/02/05 authority caveats as analyzed here.
