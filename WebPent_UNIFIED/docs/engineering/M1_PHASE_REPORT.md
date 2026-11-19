# M1_PHASE_REPORT.md — M1a (Critical Security & Configuration Recovery + Evidence Integrity + Runtime Wiring + Legacy Disposition)

**Phase:** M1a of the CANONICAL_PHASE_REGISTRY (the Execution Mandate's M1 — recovery & wiring half; the Part-4 model-contract half is **M1b**, still open).
**Date closed:** 2026-11-05 (UTC).
**Execution order used (per M1_READINESS_REVIEW §7):** M1-B (evidence integrity — anchors the charter guard) → M1-A (security/config) → M1-C (wiring) → M1-D (disposition).
**Windows:** UM-DR-10 (M1-B) · UM-DR-11 (M1-A; entry retroactively completed and first-hand re-verified by the closing session) · UM-DR-12 (M1-C + M1-D).
**Baseline:** pristine M0 checkpoint (M0 deliverables in `download/M0/`, registry record in `docs/engineering/CANONICAL_PHASE_REGISTRY.md`).

---

## 1. Finding dispositions (M0 register → closure)

| ID | Finding | Disposition | Evidence |
|---|---|---|---|
| H-1 | Unauthenticated API + cloudflared republishes surface | **fixed** | `api/app.py` `reject_tunneled_requests_when_auth_disabled` (401 on proxy/tunnel indicators when auth off; loopback dev + auth-on reverse-proxy unaffected; OOB endpoints exempt) · `test_m1a_tunnel_exposure.py` |
| H-2 | `.env.example` CHANGE-ME placeholders pass all secret gates | **fixed** | `settings.py::_looks_like_placeholder` across JWT/AUDIT/CELERY + `api/auth.py::_ensure_seeded` refusal · `test_m1a_placeholder_rejection.py` |
| H-3/1.3a | Fabricated composite preconditions (chain analyzer) | **fixed** | M1-B: unverified_precondition labeling, probe-gated; M1-C E-4 adds the real writer · `test_m1b_precondition_integrity.py` + `test_m1c_e4_oauth_wiring.py` |
| H-3/1.3b | `validate_exploit_chain` confirms without negative control | **fixed** | M1-B control_replay requirement (fail-closed default) · `test_five_families.py` hardened contract |
| H-3/1.3c | `validate_oauth` confirms on weak derived booleans | **fixed** | M1-B delivered-artifact marker + legitimate-callback baseline · `test_five_families.py` |
| H-3/1.3d | SQLi reauth promotion: LLM co-gate + replay bypass | **fixed** | M1-B: `confirmed = det_confirmed` (LLM advisory-only), dead `llm_confirmed` term removed, `causal_signal` deterministic-only · `test_m1b_llm_charter_guard.py` |
| M-1 | `webpent-cli.sh` auto-approves HITL sandbox gate | **fixed** | interactive confirm + `--yes` + `WEBPENT_API_TOKEN` Bearer + auth-off refusal · `test_m1a_cli_hitl_gate.py` |
| M-2 | katana cross-origin crawl, post-hoc mitigation | **fixed** | explicit `-fs fqdn` scope pinning · `test_m1a_katana_scope_pinning.py` |
| M-3 | GlobalRateGovernor dead code, no central ceiling | **fixed** | transport-chokepoint enforcement when `rate_limit_enabled`; fail-open+CRITICAL on governor bugs · `test_m1a_transport_rate_ceiling.py` |
| M-4 | ContainedHTTPClient raw-httpx fallback | **fixed** | delegation to `make_safe_httpx_client`; fallback removed (fail-closed) · `test_m1a_legacy_containment_transport.py` |
| M-5 | raw `urlopen` on env-shaped URLs | **fixed** | both channels on the one safe transport; M1-C adds the loopback-trusted exemption for first-party collectors (context-scoped, loopback-only, default-off) · `test_m1a_oob_dispatch_safe_transport.py` + `test_m1c_loopback_trusted_endpoint.py` |
| L-1 | Playwright surfaces without route guard | **fixed** | `install_playwright_ssrf_guard` on browser_farm + poc_recorder contexts · `test_m1a_playwright_ssrf_guards.py` |
| L-2 | SMART_AUTO_APPROVE lifts active-action approval | **mitigated (kept, documented)** | operator opt-in preserved; HITL-interrupt guard test + `.env.example` documentation · `test_m1a_cli_hitl_gate.py` + `test_m1a_docs_l2_l7_contracts.py` |
| L-3 | CLI hunt never declares engagement hosts | **fixed** | `_invoke_with_progress` sets/clears `set_engagement_target_hosts` around the graph stream · `test_m1a_cli_engagement_hosts.py` |
| L-4 | OAST DNS responder binds 0.0.0.0 default | **fixed** | default `127.0.0.1`; explicit bind stays available · `test_m1a_oast_bind_decision_log_redaction.py` |
| L-5 | `decision_log` metadata without enforced redaction | **fixed** | `redact_sensitive` enforced at append · `test_m1a_oast_bind_decision_log_redaction.py` |
| L-6 | OOB endpoints unauthenticated by design | **accepted (monitor)** | compensations verified (token checks); recorded in the M0 risk register; no code change |
| L-7 | `WEBPENT_ALLOWED_EXECUTABLES` PATH-order nuance | **documented** | `.env.example` + SECURITY.md note · `test_m1a_docs_l2_l7_contracts.py` |
| E-1 | Tool-Confirmed writers not architectural; cost_alerts ungated | **fixed** | M1-B model-level proof requirement (ValueError without provenance) + writer-registry AST gate + cost_alerts demoted to Pending+lifecycle_status · `test_m1b_tool_confirmed_writers.py` |
| E-2 | IDOR in `_DETERMINISTIC_STRUCTURAL_CLASSES` | **fixed** | dead entry removed; exclusion lives in the set · `test_m1b_prioritization_guards.py` |
| E-3 | Report quality gate default OFF | **policy implemented (bounded hardening)** | CLI hunt stays OFF (evidence-first demotion always-on); strict gate ON for platform exports · `test_platform_export.py` E-3 cases |
| E-4 | OAuth analyzer dead fields | **fixed (M1-C)** | real recon observations verify `oauth_flow_present`; M1-B speculative contract unchanged otherwise · `test_m1c_e4_oauth_wiring.py` |
| E-5 | 118 `except: pass` | **deferred-with-reason** | ruff S110 with documented noqa budget in M2's typed-execution work (churn risk if swept blindly in M1) |
| E-6 | 10 `NotImplementedError` | **deferred-with-reason** | owned by dojo/families/goed phases (opt-in/test-only modules) |
| E-7 | LLM payload strings into state | **deferred-with-reason** | payloads already flow through HITL + sandbox; schema-validated payload contract is M3 scope |

**New findings closed this phase (surfaced during M1-C/M1-D execution):**
- Missing-flag defect (`enable_oast`, `enable_causal_chain_candidates`, `enable_campaign_resume` + 5 OAST settings fields referenced-but-undeclared) → declared fail-closed · `test_oast.py`, `test_causal_chain_candidates.py`.
- M-5 latent regression (safe transport vetoed the documented loopback OOB/receiver rule; 4 live OAST failures) → context-scoped loopback-only exemption · `test_m1c_loopback_trusted_endpoint.py`.
- ق9 legacy-disposition engine over-match (parent-prefix variant made ~190 files fake importers; module scanned itself) → full-name-only matching · `test_m1d_legacy_disposition_overmatch.py` + pinned suite still green.
- Working-tree Makefile tab corruption (all `make` targets dead) → restored from git HEAD, window additions re-applied with tabs.

---

## 2. The 10 named M0 regression tests — all exist and pass

`test_m1a_tunnel_exposure.py` (H-1) · `test_m1a_placeholder_rejection.py` (H-2) · `test_m1b_precondition_integrity.py` (chain-without-probe rejected, H-3) · `test_m1b_llm_charter_guard.py` (LLM in promotion = failure + LLM decision-field write guard, charter) · `test_m1a_cli_hitl_gate.py` (M-1) · `test_m1a_katana_scope_pinning.py` (M-2) · `test_m1a_transport_rate_ceiling.py` (M-3) · `test_m1a_legacy_containment_transport.py` (M-4) · `test_m1a_oob_dispatch_safe_transport.py` (M-5) · `test_m1b_prioritization_guards.py` (E-2 IDOR guard).

---

## 3. Gate evidence at closure

- **Frozen manifest:** 659/659 byte-verified after the UM-DR-12 refreeze (`scripts/refreeze_manifest_m1c_m1d_wiring_disposition.py`: exactly 4 declared files re-pinned — settings.py, shared/http.py, agents/validator/agent.py, cli/commands.py — post-write self-check passed). Frozen-gate pytest green.
- **Frozen gate + every M1 guard suite: 776 passed** (single run, post-refreeze).
- **Collection:** 8,223 tests, **0 collection errors** (the M0-era 91 errors were pip-environment gaps, closed by installing declared deps: langchain-core, langgraph(+checkpoint-sqlite), bcrypt, esprima, celery, jsbeautifier).
- **Test-count gate:** 8,223 ≥ floor 8,115.
- **Coverage ratchet:** 4.27% ≥ 4.07% (enforcement mode, pinned scope); now a REQUIRED CI step and a Makefile target.
- **ق5 self-benchmark:** dojo suites green (25 passed) and wired into nightly CI.
- **q9 disposition run:** `docs/m1_legacy_disposition_run.json` — 5 review (bounded gray zone, archive deadline 0.34.2), 4 absorbed with real importers.
- **Environment limits (unchanged, documented):** no Docker (compose/tunnel verified by config + TestClient); no external targets ever contacted; ruff/bandit not run in this sandbox (CI holds them).

---

## 4. Deferred to owning phases (registered, not silently dropped)

| Item | Owning phase | Reason |
|---|---|---|
| OAST/`enable_campaign_resume` production-graph wiring | M3 | needs node patterns outside the frozen builder; flags now exist fail-closed |
| ق5 cve_advisory → target_understanding, ق8 api_surface_shadow → planner, ق7 identity_orchestrator runner injection | M3 | frozen nodes get their own phase contract |
| ruff S110 (`except: pass`) budget | M2 | typed-execution work touches the same files |
| sqlmap internal differential extraction | M6 | M0-documented deferral, evidence-heavy |
| review-cluster archive actions | 0.34.2 deadline | two-release clock now ticking (documented, bounded) |

---

## 5. Registry update

`docs/engineering/CANONICAL_PHASE_REGISTRY.md` M1 entry: **M1a = COMPLETE** (this report is the evidence record); **M1b = OPEN** (next phase: unified domain contracts & PentestState reconciliation). Nothing from the readiness review is dropped; every disposition above carries its test file.

— End of M1_PHASE_REPORT.md —
