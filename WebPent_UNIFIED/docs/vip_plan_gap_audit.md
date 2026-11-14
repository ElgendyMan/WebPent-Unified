# WebPent v60 — VIP Plan Gap Audit

## Sources reviewed

This audit compares `/home/ubuntu/upload/pasted_content_3.txt`, `/home/ubuntu/upload/التدقيقالشاملالنهائيلـWebPentوتحويلهإلىVIPAutonomousBugHunter.md`, and the current release matrix in `docs/vip_audit_compliance_matrix.md`.

## Findings

| Area | Current evidence | Status | Required follow-up |
|---|---|---|---|
| Authentication, tenant authorization, shared token revocation, resume consume-once, registry health, login throttling | Existing security regressions and compliance matrix | Implemented under tested contracts | Re-run deployment smoke tests in the actual authorized deployment |
| Shared re-auth vault | Optional SQLite store, migration 0003, TTL/sweep, lifecycle tests | Implemented as opt-in | Production must share DB and `CELERY_PAYLOAD_KEY`; default fallback remains in-memory |
| Scope/egress kernel | OriginPolicy, Playwright transactional guard, raw socket budgets | Implemented/verify | Preserve active engagement scope context for all raw/OOB callers; live oracle remains environment-dependent |
| Dependency advisories | Strict audit artifact and documented resolver conflict | Blocked/documented | Major dependency migration, lockfile/SBOM update, and migration tests remain outstanding |
| Broad exception cleanup | Critical paths hardened, historical catches remain | Partial | Convert remaining broad catches to typed failure taxonomy and structured events |
| Source-inspection tests | New behavioral tests added, historical source tests remain | Partial | Replace remaining inspection assertions with behavioral fixtures |
| Worker critical path | Current measured coverage 23% | Blocked/partial | Dedicated Celery/graph crash, redelivery, concurrency, and terminal-cleanup harness; target 85% |
| Surface Evidence Graph | Typed `SurfaceNode`/`SurfaceEdge`, deterministic metadata projection, redaction, and mandatory disposition queue are covered by behavioral tests | Implemented as passive graph contract | Rich browser/XHR/OpenAPI/GraphQL/multipart/service-fingerprint ingestion still depends on adapters and authorized observations; no passive node is promoted to tested |
| Application Intent Model | Explicit actors/objects/fields/boundaries/sinks/transitions/jobs/services schemas and route-renaming-invariant passive builder are covered by behavioral tests | Implemented as passive model | Live application semantics remain evidence-dependent; LLM projection is bounded and fail-closed |
| Identity matrix and workflow replay | Identity matrix fields, session health, bounded replay plan, scope/approval gates, and cleanup contracts have behavioral fixtures | Implemented as plan-only contract | No replay request is executed without an authorized executor, valid scope, identity/session evidence, and explicit approval |
| Campaign planner and hypothesis DAG | 20 campaign entries, preconditions/actions/oracle/budget, DAG and gap statuses exist | Implemented as planning contract | Real executors/oracles are still required for missing classes; no campaign may be marked tested without evidence |
| Validator plugins | Authoritative registry, seven-stage plugin contract, and offline evidence/oracle/cleanup adapters for the seven unsupported campaign classes exist | Partial, improved locally | Implement complete live detector/executor/oracle/report plugins for CSV SQLi, JWT traversal, redirect/OAuth, SSTI/export, XML/XSLT, Elasticsearch, backup/debug/dependency, header/identity/tenant families as applicable; offline adapters remain review-only and never set `tested` |
| Evidence Ledger | Redaction-safe deduplicating ledger is wired to validator outcomes and Proof Engine outcomes, with causal metadata, cleanup status, and dedupe regressions | Implemented for current producer paths; bounded | Any future producer must call the shared merge helper; raw tool output and secrets remain excluded, and ledger status does not create a Finding |
| Proof Engine | Gap taxonomy, bounded proposals, causal/cleanup/confidence contracts, approval/scope gates, and proof-outcome ledger projection are covered by behavioral fixtures | Implemented as approval-gated planning/outcome contract | A real executor/oracle integration and live authorized probe transcripts remain environment-dependent; no duplicate proposal is emitted without a new evidence fingerprint |
| WAPTLab regression | 20 dispositions plus synthetic replanning; target contact false; WAPTLab unmodified | Contract-only | Add authorized local positive/negative fixtures or run the existing lab only when explicitly available; record transcripts, coverage diffs, false-positive reports, and rollback plans |
| Quality/release metrics | Compileall, Ruff, 561 pytest, 522 functions, local safety artifact | Green for local gates | VIP thresholds are not met: 15/20 evidence-reviewable, 95% surface, 90% workflow, 100% P0/P1 validator reachability, 85% worker coverage, zero unexplained skips |
| Documentation/comments | Major release docs updated | Partial | Sweep stale security comments/docs and keep all blocked limitations visible |

## Release interpretation

The reviewed release now implements the locally verifiable, passive, and approval-gated portions of the two source plans: security contracts, shared vault, Application Intent, typed Surface Evidence Graph, workflow replay planning, campaign planning, validator/Evidence Ledger contracts, offline evidence adapters for the seven unsupported campaign classes, Proof Engine outcome projection, and local WAPTLab safety regression. It still does not fabricate end-to-end application-intent execution, complete active validators for all 20 classes, integrated WAPTLab evidence, or the ambitious worker/coverage/dependency targets. Those environment-dependent or high-risk items remain explicitly blocked and documented.

## Safety constraints retained

No WAPTLab source is to be modified. No external target is to be contacted. No candidate is to be promoted to `tested`, `Tool-Confirmed`, or `Evidence-Confirmed` without an actual executor/oracle/evidence bundle. Every blocked or unobserved class must retain an explicit disposition.
