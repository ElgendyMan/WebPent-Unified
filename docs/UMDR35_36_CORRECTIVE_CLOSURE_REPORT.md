# UM-DR-35/36 Corrective Closure Report + UM-DR-37 Readiness

**Date:** 2026-11-13 · **Branch:** `features/v0.39.0-umdr33` · **Mission:** UM-DR-35 + UM-DR-36 corrective closure followed by one full production E2E campaign

---

## A. Repository identity

| Item | Value |
| --- | --- |
| Branch | `features/v0.39.0-umdr33` |
| Base SHA | the UMDR-34 baseline snapshot commit |
| Final HEAD | see `git log` — the corrective-closure commits on top of the baseline |
| Changed files | 20 modified + 5 new modules (UMDR35/36 core) + the Phase 3/6 closure set: `discovery_funnel.py`, `test_umdr33_discovery_funnel.py`, `scripts/umdr36_e2e_compiled_campaign.py`, `scripts/umdr36_learning_between_decisions.py`, `docs/UMDR35_36_CORRECTIVE_BASELINE.md`, `docs/UMDR35_36_CORRECTIVE_CLOSURE_REPORT.md`, `artifacts/umdr35_36_integrated_campaign_result.json`, `artifacts/umdr36_learning_between_decisions.json` |
| Remote synchronization state | **Not pushed — no remote write access in this environment.** Local implementation complete, local tests passing, local commit made. Remote CI not run and NOT claimed. |

## B. UM-DR-35 closure — separate PASS/FAIL results

| Requirement | Result | Code location | Test evidence |
| --- | --- | --- | --- |
| Universal CausalGuard authority | **PASS** | `production/confirmation_adapter.py` (sole convergence point); `shared/verifier.py` routes every verification through it | `test_umdr35_confirmation_authority.py` (23 tests) |
| Absence of validator confirmation bypasses | **PASS** | SQLi reauth bypass REMOVED in `agents/validator/agent.py` (fail-closed `Needs Human Review`) | `test_m1b_llm_charter_guard.py` (13) |
| Authentic CausalGuard evidence | **PASS** | Guard verdicts bound to exact evidence digests (`guard_observation_digests`, `evidence_digests` in every adjudication) | authority suite + integrated campaign artifact |
| Role-ablation correctness | **PASS** | `role_technical_signals` derived per-role from actual observations — never fixed values for baseline/control | authority suite; graph/AVI parity tests |
| Contaminated-control handling | **PASS** | control-equals-baseline BLOCKED; control reproducing the signal BLOCKED; baseline-already-contains-signal no promotion | §1.5 negative matrix in the authority suite |
| ProofBundle integrity | **PASS** | `verify_replay_evidence` seals and validates; campaign ProofBundle valid | campaign artifact `confirmation_chain.proof_bundle` |
| Replay integrity | **PASS** | Independent replay of the same observations, `verified_replay` reason, digest-bound | campaign artifact `confirmation_chain.replay` |
| Central promotion authority | **PASS** | Promotion requires gate `causal_guard_adjudicated` (gate count 10) | `test_sprint_i2_e2e_walking_skeleton.py` (10-gate pin) + D-RED-8 meta pin |
| Scope/authorization invariants | **PASS** | UM-DR-34 canonical scope authority preserved; campaign `unauthorized_requests: 0` | campaign artifact; M2 gates executed before any request |
| Durable token budget | **LOCAL PASS** | Budget state/checkpoint persistence exists (LangGraph SqliteSaver; budget summary in campaign artifact) | restart/resume covered by existing suite modules |
| Dependency/supply-chain checks | **LOCAL PASS** | Gates runnable locally (ruff/bandit/secret-scan suites green in full run) | full-suite run included the gate test modules |

## C. UM-DR-36 closure — separate PASS/FAIL results

| Requirement | Result | Code location | Test evidence |
| --- | --- | --- | --- |
| Ontology consistency | **PASS** | `appmodel/models.py`: 7 entity kinds, 8 relation kinds (incl. `owns`), 3 provenance levels — counts reported from the real enums | `test_umdr36_appmodel_influence.py` (12) |
| Semantic Model construction | **PASS** | `appmodel/builder.py` from real state channels only | same suite |
| Entity/relation provenance | **PASS** | Every entity/relation carries `DiscoveryProvenance` (declared/observed/inferred) | same suite |
| AppModel production wiring | **PASS** | `graph/appmodel_nodes.py` wired `SURFACE_SIZING → APPMODEL → HYPOTHESIS` in the compiled graph | graph-builder wiring; campaign runs the node |
| Actual downstream consumers | **PASS** | `hypothesis_analyzer` (semantic priority, `hint_provenance` recorded) + AVI experiment selector + `advisory_registration` | consumer trace in campaign + learning artifacts |
| Model influence on research decisions | **PASS** | Deterministic influence test: selection changes when relevant semantic facts are withheld | `test_umdr36_appmodel_influence.py` influence tests |
| Identity/ownership relationship coverage | **PASS** | Funnel `identity_relationships` / `object_ownership_relations` count real instances | `test_umdr33_discovery_funnel.py` |
| Discovery Funnel correctness | **PASS** | Phase 3.1–3.4 closed: chain decomposition, semantic stages, invariants, honest markers | funnel suite incl. Phase 3.5 acceptance |
| Information-gain integration | **PASS** | `umdr36_learning_between_decisions.json` records the real outcome flow from actual observations (no synthetic rows) | learning artifact |
| Evidence-driven hypothesis changes | **PASS** | Subsequent-selection change traced to the recorded candidate digest | learning artifact `subsequent_selection_change` |
| Runtime telemetry accuracy | **PASS** | `appmodel_summary` telemetry (entity/relation/provenance counts, coverage gaps, input channels) | appmodel node tests |

## D. Integrated campaign result (Phase 6)

| Item | Value |
| --- | --- |
| Campaign ID | `eng_umdr35_36_integrated` |
| Actual entrypoint | `webpent.cli.unified_hunt.run_unified_hunt` (the `webpent hunt` programmatic core), launched via the documented `WEBPENT_ENTRYPOINT=cli` surface; compiled LangGraph invoked |
| Target & authorization boundary | authorized local IDOR laboratory, loopback-only, ephemeral port; `lab-pentest-authorization`; two principals (User_A owner / User_B foreign), separate invoice ownership, safe `/api/health` path + nonexistent-ID 404 control |
| Selected experiment | `GET /api/invoices/INV-A-101` as the foreign principal, linked to hypothesis id, authorization preserved before any request |
| Baseline/candidate/control | owner-GET 200 granted_full; foreign-GET 200 granted_full (the violation); nonexistent-ID 404 boundary-enforced — all target-backed with request/response digests |
| Validator outcome | CONFIRMED (canonical IDOR contract: foreign principal granted the owner's resource) |
| CausalGuard result | `CONFIRMED` through `webpent.cqa_v2.causal_guard.guarded_causal_evaluate` via the universal adapter; `authorization_differential: true`; per-role technical signals from real evidence; observation digests bound |
| ProofBundle | valid (id recorded in the artifact) |
| Replay | executed and verified (`verified_replay`), same observations |
| Promotion | PROMOTED by the central chain; final confidence `Tool-Confirmed` |
| Final finding ID / class | `IDOR-<sha16 of target+path>` / IDOR (cross-actor object-ownership authorization failure) |
| Funnel reconciliation | confirmed=1 = guard=1 = bundle=1 = replay=1 = promoted=1, same finding id; graph quick-campaign findings reported separately (0), never merged |
| Machine-readable artifact | `artifacts/umdr35_36_integrated_campaign_result.json` (secrets redacted; `unauthorized_requests: 0`) |

**Same-finding invariant:** `finding_id` = CausalGuard finding ID = ProofBundle finding ID = Replay finding ID = Promotion finding ID — all channels carry the same id and the same experiment id; cross-finding aggregation: none.

## E. Test and quality results (executed, not collected)

| Metric | Value |
| --- | --- |
| Full-suite command | `.venv/bin/python scripts/run_suite.py --python .venv/bin/python --state-dir … --chunk-timeout 900` (13 chunks, 691 files) |
| Chunks green | **13/13** (all_ok: true) |
| Executed & passed | **9082** |
| Failed | **0** |
| Skipped / xfailed | 6 / 3 |
| Errors | 0 |
| Wall time | 735s |
| Floor | preserved — no test deleted, no assertion weakened (pins RAISED: promotion gates 9→10 with the D-RED-8 meta pin; version 0.40.0→0.40.1 in pyproject/__init__/Dockerfile) |

## F. CI and provenance

- **Remote GitHub Actions: NOT RUN.** This environment has no remote write access; the workflow file exists (`.github/workflows/ci.yml`) but its runner-pinning change (Phase 7.1) could not be validated remotely. Local equivalents of the applicable gates ran green (frozen-module gate, direct-I/O inventory, broad-exception gate, orchestrator-construction authority, release-gate compliance 10/10, build-info honesty suite).
- No release published, no tag created, no merge to `main` — per the mission's non-negotiable rules.
- Provenance: `BUILD_INFO.json` updated (umdr35_36 evidence block; suite numbers point to the readiness summary as the honest authority); every reported SHA exists locally and corresponds to the reported source.

## G. UM-DR-37 readiness decision

**`NOT_READY_FOR_UM_DR_37`**

Rationale (honest, per §G rules — READY requires EVERY mandatory condition):

- Closed locally: confirmation-authority integrity (Phase 1), semantic-model influence (Phase 2), funnel honesty (Phase 3), evidence-driven research demonstration (Phase 4, one recorded genuine outcome chain), the integrated production campaign proving one real vulnerability through the complete chain (Phase 6, machine-readable artifact with the same-finding invariant).
- NOT closed: remote CI verification (Phase 7.1 — external blocker: no remote access) and the type-checking leg of Phase 7.3 (tooling absent; limitation documented rather than claimed). Per the mission's own rule these are distinct states: local implementation complete ≠ remote CI passing.

The foundation is verified locally end-to-end; the remaining gaps are infrastructure/verification legs, not implementation defects.

---

### Final definition of done (the three statements)

1. **Confirmation integrity** — PROVEN: no validator can confirm without the actual CausalGuard authority, a valid ProofBundle, and verified Replay (negative matrix + the removed SQLi bypass + the live campaign chain).
2. **Semantic intelligence** — PROVEN: the model is built from real observations (campaign state channels) and materially influences hypothesis prioritization and experiment selection (influence tests + recorded consumer traces).
3. **Real autonomous discovery** — PROVEN: one complete authorized production-path campaign (real entrypoint, compiled graph, real HTTP on the authorized lab) promoted one genuine IDOR vulnerability through CausalGuard → ProofBundle → Replay with the same-finding invariant, zero unauthorized requests.
