# WebPent Smart Autonomous Bug Hunter — Plan Gap Audit

**Source under review:** `webpent_v60_smart_hunter.zip` (SHA256 `261c26a0d85f19662f4f22d81f4404564f1a647e36932c15f7f77b99c53d2605`)

**Baseline:** `661 passed, 96 warnings in 26.85s` from the restored source before changes.

## Gate-by-gate verification

| Gate | Current evidence | Status | Critical gap / safe next action |
|---|---|---|---|
| G0 | Restored archive, editable install, reproducible pytest baseline; no verified SBOM/signed release manifest/PostgreSQL qualification in this review | Partial | Add release evidence only; do not claim production reproducibility or PostgreSQL readiness |
| G1 | `ActionAuthority`, scope/origin checks, budgets, idempotency and fail-closed active-method policy exist; `SecretStr` is partial and direct transport/browser calls remain in legacy agents | Partial | Keep central smart path fail-closed; document legacy direct-call debt; do not weaken authority to gain recall |
| G2 | `scan_mode`, governance, capability manifest and smart planning/execution nodes are persisted and graph-wired; no explicit per-run CLI `--mode` or complete topology proof | Partial | Add explicit additive CLI mode override and state trace tests |
| G3 | Surface records, workflow projections and deterministic planner refresh exist; browser/discovery support is optional and family-diverse/GraphQL/OpenAPI coverage is not proven | Partial | Report unavailable browser/tool families as blockers; no silent fallback |
| G4 | Identity profiles, BAC relational evidence and authorization matrix exist, but access probes are read-only same-URL; no complete owner/foreign workflow replay or tenant-switch state machine | Partial / blocked for active IDOR | Preserve current conservative BAC logic; add explicit identity context and differential trace fields before active workflows |
| G5 | `CampaignTask` and `CampaignExecutor` support method/risk/capability structurally; smart execution handler currently always calls GET; `decision_trace` is executor-local only | Partial | Persist trace in `PentestState`; make task transport method-aware and allow POST only under `authorized-active` with approval and explicit body evidence |
| G6 | Planner uses surface/workflow tokens and proof gap projections; no demonstrated verified learning that changes ordering | Partial | Do not claim learning; keep task ordering deterministic and evidence-backed |
| G7 | Proof planning/projection and validator registry exist; no immutable sealed ProofBundle, hash verification, or replay store; seven WAPTLab classes remain human-review/missing-validator | Partial / blocked | Add append-only, sealed proof bundle model/utility and explicit `human_review_only` status without relabeling legacy tests |
| G8 | Live result is documented as 2 candidates/0 confirmed; no deterministic WAPTLab harness/ground-truth registry/three-run qualification | Not met | No recall claim; live qualification remains blocked by browser, identities, POST, OOB and validators |
| G9 | SQLite/dev checkpointer and Celery exist; no PostgreSQL multi-worker qualification or structured metrics completeness | Not met | Keep SQLite dev-only claim and list operational debt |
| G10 | No release-gate evidence for B/C/D; current classification remains Autonomous Candidate / Early Beta | Not met | Do not label Smart Autonomous Bug Hunter/VIP |

## Confirmed high-impact implementation facts

1. `CampaignExecutor` already builds an `ActionRequest` with `method`, `risk`, `capability`, `identity_ref`, budget and idempotency. Its `decision_trace` is only an in-memory list.
2. `smart_campaigns_execution_node` selects concrete surfaces but always calls `client.get(task.target_url)`, and returns `get_only: true` even when the profile is `authorized-active`.
3. `CampaignTask` can carry method/capability/action family, but `_task_from_entry` does not populate these from campaign contracts.
4. `coverage_ledger.py` does not include `human_review_only` in terminal statuses and maps `needs_human_review` to `candidate`.
5. `CAMPAIGN_HUMAN_REVIEW` explicitly identifies seven known WAPTLab classes, while existing tests intentionally preserve `missing-validator` compatibility.
6. CLI accepts bounded `--second-creds` identities and seals them in the re-auth vault, but the initial graph state receives an empty identity projection and no explicit per-run `--mode` option.

## Conservative patch scope selected

- Add a first-class additive `decision_trace` state projection and return executor traces from the smart execution node.
- Add explicit `human_review_only` as a supported terminal status while retaining `missing-validator` compatibility for legacy campaign/planner contracts.
- Make smart task construction read method/risk/capability/action-family/body metadata when explicitly supplied by observed evidence/contract; never guess active payloads.
- Make smart HTTP transport execute GET/HEAD/OPTIONS in `safe-smart`; allow explicit POST only in `authorized-active`, only through `ActionAuthority`, and only with operator approval/auto-approval plus a bounded evidence-backed body.
- Add a per-run CLI mode override that is additive and defaults to the settings/env profile.
- Add focused tests for the new state/trace/mode/status contracts before running the full suite.

## Explicit non-claims after this review

This patch cannot by itself establish dual-identity workflow replay, OOB SSRF/XXE confirmation, browser coverage, immutable ProofBundle replay, deterministic WAPTLab harness, or 15+/20 live recall. Those remain release blockers and will be reported as such.
