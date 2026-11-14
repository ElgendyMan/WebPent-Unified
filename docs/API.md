# WebPent HTTP API Reference

**Status:** refreshed 2026-10-05 (fix-sprint). Endpoint surface extracted from
`src/webpent/api/app.py` (the single FastAPI application served by `server.py`
and the `api` docker-compose service).

All routes except `/health` and `/token` require authentication. Destructive
routes additionally require the `admin` role. Every route is subject to the
engagement scope (ScopeLaw) and the rate-limit middleware; scan resources are
ownership-checked (`_authorize_scan_resource`).

## Conventions

- Base URL: `http://<host>:8000`
- Auth: `POST /token` → bearer token → `Authorization: Bearer <token>`
- Errors: standard FastAPI error shape; fail-closed semantics — a missing
  gate never degrades to a success response.
- Secrets are never echoed: response models redact evidence bodies
  (`evidence_bundle` is summarized, not returned verbatim).

## Health & auth

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness/probe. Returns service status; no target interaction. |
| POST | `/token` | none | Exchange operator credentials for a JWT bearer token. |
| GET | `/api/v1/me` | bearer | Identity of the caller (username, roles). |

## Scope management

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/scope/load` | bearer | Load an engagement scope file (allowlist of hosts/paths). Fail-closed on malformed scope. |
| GET | `/api/v1/scope` | bearer | Show currently loaded engagement scope. |
| GET | `/api/v1/scope/check` | bearer | Check a URL against the active scope without executing anything. |
| DELETE | `/api/v1/scope/{engagement_id}` | bearer | Remove an engagement scope. |

## Recon & scans

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/recon` | bearer | Adversary-invisible recon-only run. Returns surface facts; never confirms findings. |
| POST | `/api/v1/scans` | bearer | Start a full campaign (202 Accepted). Payload is encrypted at rest in the Celery queue (`CELERY_PAYLOAD_KEY`). Body: target URL, engagement id, scope file reference, approval mode (`auto_approve=false` requires HITL). |
| GET | `/api/v1/scans/{thread_id}/status` | bearer (+owner) | Campaign status, current node, HITL pending approvals. |
| POST | `/api/v1/scans/{thread_id}/approve` | bearer + **admin** | Approve/reject a pending HITL checkpoint. Audited; ownership-checked. |
| GET | `/api/v1/scans/{thread_id}/findings` | bearer (+owner) | Findings with lifecycle stage (`Hypothesis → Evidence → Reproduction → Confirmed`) and proof-bundle references. |
| GET | `/api/v1/scans/{thread_id}/risk-summary` | bearer (+owner) | Aggregated risk view (counts by severity/confidence; no raw evidence). |

## Campaign control & product layer

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/campaigns/{campaign_id}/halt` | bearer | Cooperative stop (kill switch). Halts before the next bounded step; in-flight request completes or times out. |
| POST | `/api/v1/campaigns/{campaign_id}/resume` | bearer | Resume a halted campaign from its durable state. |
| GET | `/api/v1/campaigns/{campaign_id}/estimate` | bearer | Cost/time estimate for the remaining campaign plan. |
| GET | `/api/v1/campaigns/{campaign_id}/dashboard` | bearer | HTML live dashboard (campaign progress, decisions, costs). |
| GET | `/api/v1/campaigns/{campaign_id}/reports` | bearer | List generated campaign reports (JSON/HTML artifacts). |

## OOB callbacks (out-of-band interaction receiver)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST/GET | `/oob/{token}` (generic + scoped variants) | none (token IS the credential) | Receives out-of-band interactions (DNS/HTTP callbacks) for OOB-confirmed vulnerability classes. |

⚠️ **Authority note (documented limitation):** the OOB receiver seals a
ProofBundle and marks a finding tool-confirmed directly from the callback
path. This is the one confirmation path that does not traverse
`PromotionPipeline` + `ReplayVerifier` (audit finding BYP-02,
`TEAM_REVIEW_MILESTONE1_CALL_GRAPH_AUDIT.md` §Chain 5). It is scoped to
token-matched findings only; treat OOB-confirmed findings as a separate
confidence tier until this path is re-routed through the promotion gates.

## Execution path (what a scan actually invokes)

```
POST /api/v1/scans
  → Celery task run_pentest_task (worker.py)
    → build_graph(checkpointer=SqliteSaver)         # langgraph 1.2.10 + checkpoint-sqlite 3.1.1
      → NODE_RECON (modern spine; MODERN_SPINE_ENABLED)
        → ModernOrchestrator.run_deep_recon / research_loop
      → NODE_RESEARCH_CAMPAIGN → run_autonomous_validation_campaign
        → ScopeLaw + ToolBoundary → bounded execution
        → validators → ProofBundle seal → ReplayVerifier → PromotionPipeline
  → checkpointed state per thread; resume via /approve + resume task
```

## Versioned environment (verified)

| Component | Verified version |
|---|---|
| Python | 3.12.14 |
| langgraph | 1.2.10 (exact pin) |
| langgraph-checkpoint-sqlite | 3.1.1 (exact pin) |
| fastapi | 0.142.2 |
| starlette | 1.7.0 |
| celery | 5.6.3 |
| Full-suite verification | 3043/3043 pass (2026-10-05) |

## POC & Evidence Export CLI (FINAL PREP SPRINT 2026-10-05)

Console script `webpent-poc` (also `python -m webpent.reporter.poc_cli`):

| command | flags | behavior |
|---|---|---|
| `webpent-poc record` | `--finding <uuid> --engagement <id> [--ledger PATH] [--output DIR] [--owner-token/--foreign-token (env: WEBPENT_POC_OWNER_TOKEN/WEBPENT_POC_FOREIGN_TOKEN)] [--token-header H]` | records `poc_<id>.webm` (≤5 MB, ≤30 s) + `poc_<id>.json` metadata; **fail-soft** (exit 0 with `status=failed` on any recording error) |
| `webpent-poc export` | `--engagement <id> [--finding <uuid>] [--output DIR] [--poc-dir DIR] [--ledger PATH]` | writes `<id>_bugbounty.md` + `<id>_evidence.json` per promoted finding (CVSS, numbered steps, cURL pairs with `$OWNER_TOKEN`/`$FOREIGN_TOKEN` placeholders, impact, remediation, ProofBundle ref) |
| `webpent-poc embed` | `--report <html> --poc-dir DIR` | idempotent video-section injection into rendered HTML reports |

Library API: `webpent.reporter.poc_recorder.maybe_record_poc(finding, ...)`
(the sanctioned post-promotion hook — never raises), `record_poc(plan, ...)`,
`build_poc_plan(finding, ...)`, `webpent.reporter.poc_export.export_all_promoted(...)`.
Watcher: `scripts/poc_watcher.py --engagement <id>` (opt-in via
`WEBPENT_POC_ENABLED=1`), started automatically by `scripts/run_campaign.sh`.
