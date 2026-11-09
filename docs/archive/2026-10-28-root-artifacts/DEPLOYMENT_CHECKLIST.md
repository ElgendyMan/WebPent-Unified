# Deployment Checklist — Unfreeze 2026-10-05 (Hunting Intelligence Live Wiring)
Five frozen files were unfrozen and modified additively. All new behavior is
**default-off**; the frozen trust spine is untouched. The frozen manifest was
regenerated after the changes were accepted, so the gate is 695/695 OK; the
pre-unfreeze state is preserved in `frozen_modules.sha256.baseline_pre_unfreeze`.

> **v2 note (post-hostile-audit):** the v1 line "pip check clean (project
> scope)" promised a gate the delivered environment could not pass literally
> (audit D-02). Fixed by removing 7 orphan packages and upgrading pyopenssl;
> the gate below is now the literal command with exit code 0. A ZIP hygiene
> gate (`scripts/zip_hygiene_gate.py`) was also added — run it after building
> any deployment archive (audit D-04/D-05).

## A. Pre-deploy verification (gate — must all pass)
- [ ] **Full suite (hermetic):** `pytest tests/ -q` → **3046/3046 pass** (includes the frozen-gate pytest, direct-I/O drift gate, broad-exception register gate, and all sprint/acceptance suites).
- [ ] **Synthetic acceptance:** sprint (46) + chain/browser (21) + fix verification (13) → **80/80 pass**.
- [ ] **Frozen hash gate:** `sha256sum -c frozen_modules.sha256` → **695/695 OK**; and `pytest tests/test_frozen_module_gate.py` → 697/697 (pins byte-identity + the 5 documented unfreeze deltas vs the baseline manifest).
- [ ] **Trust spine untouched:** `ProofBundle`, `PromotionPipeline`, `CausalGuard`, `ScopeLaw`, `ToolBoundary`, `M4/ContextAuthority`, `ReplayVerifier` byte-identical to baseline (subset of 695 OK).
- [ ] **Zero-FP:** refusal / 403-not-dead tests pass; healthy responses never trigger recovery (see `test_hunting_sprint_session_recovery.py` zero-FP cases).
- [ ] **Default-off confirmed:** `run_hunter_campaign` signature has `recovery_enabled=False`, `enrichment_enabled=False` defaults; `HypothesisGenerator.generate(..., enriched_context=None)` default.
- [ ] **Dependency pins:** `pip check` → literal exit 0 (v2 environment: 7 orphan packages removed, pyopenssl 26.4.0); `langgraph==1.2.10` + `langgraph-checkpoint-sqlite==3.1.1` installed (exact pins — see pyproject.toml); dependency-closure security gate: `python scripts/dep_closure_audit.py` → 0 open findings (1 accepted residual: chromadb); evidence in `EVIDENCE_REPORT_20261005.md` §Phase 5.
- [ ] **Secret keys configured:** `JWT_SECRET_KEY`, `CELERY_PAYLOAD_KEY`, `AUDIT_SECRET_KEY` set to strong values (≥32 chars; production boots fail-closed otherwise — enforced by `Settings` validation).

## B. Configuration (opt-in, per campaign)
- [ ] Decide per-engagement whether to enable `recovery_enabled` (recommended for long campaigns with cookie/JWT sessions).
- [ ] Decide per-engagement whether to enable `enrichment_enabled` (recommended when A/B `learning_proven` for that target class).
- [ ] If using API-key principals: operator supplies key out-of-band; set profile `auth_type: api_key`; confirm header name matches target (preserved in M4 seal as `api-key:name=value`).
- [ ] Confirm `principal_credentials` are present before enabling `recovery_enabled` (recovery re-logins using them; without them recovery halts fail-closed).

## C. Deploy steps
- [ ] Tag release (e.g., `v2-phase1-unfreeze-20261005`).
- [ ] Deploy to staging; run one smoke campaign with both flags **off** → behavior identical to baseline.
- [ ] Run one smoke campaign with `enrichment_enabled=True` → same findings, no crash.
- [ ] Run one smoke campaign with `recovery_enabled=True` against a target whose session you can expire → confirm recovery resumes (audit event `session.recovered`).
- [ ] Promote to production.

## D. Monitoring / rollback
- [ ] Watch audit ledger for `campaign.halted` events with reason `recovery_exhausted_*` (indicates target session structure changed — investigate, do not disable fail-closed).
- [ ] Watch for unexpected `api_key` signals in `auth.detected` audit events (advisory; low confidence; operator-gated).
- [ ] **Rollback:** `git checkout` the 5 files above; re-run `sha256sum -c frozen_modules.sha256` → 695/695 OK. No data migration needed.

## E. Documentation
- [ ] `QUICKSTART_CAMPAIGNS.md` delivered (this release).
- [ ] Team notified that 5 files are now unfrozen; future edits to these files must update `frozen_modules.sha256` and re-run the gate.

## F. Final-prep sprint additions (2026-10-05 v3)
- [ ] **POC recorder:** `pytest tests/test_poc_recorder.py tests/test_poc_integration.py` → 27/27 (fail-soft contract covered: POC failure never blocks promotion).
- [ ] **Campaign scripts:** `run_campaign.sh` / `stop_campaign.sh` / `verify_campaign.sh` / `export_findings.sh` syntax-checked (`bash -n`) and scope-fail-closed via `webpent hunt --scope`.
- [ ] **CLI surface:** `webpent-poc --help` works (dedicated console script; frozen typer app untouched).
- [ ] **Templates:** `scope_template.yaml` (real grammar) + `credentials_template.yaml` (JSON principals) shipped at repo root.
