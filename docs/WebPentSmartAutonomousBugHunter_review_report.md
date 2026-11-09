# WebPent v60 — Smart Autonomous Bug Hunter Review Report

## Executive summary

تمت مراجعة الخطة المرجعية `WebPentSmartAutonomousBugHunter.md` مقابل نسخة المصدر المستعادة من الأرشيف المنقح، ثم تنفيذ إصلاحات additive محافظة في مسار smart runtime. النتيجة الحالية **أفضل من baseline السابق** من ناحية سلامة التمرير بين LangGraph nodes، per-run authority، method-aware execution، decision trace، وتصنيف human-review-only، لكنها **ليست بعد Autonomous Bug Hunter مكتملًا ولا Release A**.

التصنيف الصادق بعد هذه المراجعة هو: **Autonomous Candidate / Early Beta**.

لا توجد في هذه المراجعة أي دعوى عن ثغرات مؤكدة جديدة على WAPTLab. لم يتم إجراء live scan جديد لأن Docker Server غير متاح للمستخدم الحالي: `permission denied while trying to connect to the Docker API at unix:///var/run/docker.sock`.

## Implemented changes

| Area | Implemented change | Safety/compatibility property |
|---|---|---|
| G5 state propagation | Added append-only `decision_trace` to `PentestState` and initialized it in `build_initial_state`. | Additive field; legacy checkpoints and existing state contracts remain usable. |
| G5 NBA trace | Smart planning now records decision id, task id, class, score, reasons, and planned/stopped status. | Trace is advisory telemetry; it never grants execution authority. |
| G5 per-run mode | Added `--mode legacy|safe-smart|authorized-active` to the CLI and an optional `scan_mode` override to `build_initial_state`. | Uses local `model_copy`; does not mutate process-wide settings or environment. |
| G5 active workflow | Surface evidence can carry an explicit `method` and bounded request body. GET/HEAD/OPTIONS remain available; POST is attempted only with `authorized-active`, authority approval, same-origin checks, idempotency, and body evidence. | Safe-smart remains read-only; unsupported methods fail closed. |
| G5 authority correctness | Smart execution derives the runtime authority profile and per-run auto-approve from the current engagement state instead of relying only on global environment settings. | Fail-closed on invalid profiles and missing capabilities. |
| G7 coverage reporting | Added official `human_review_only` status and an explicit `human-review-only-validator` gap. | Existing `missing-validator` and legacy statuses are preserved. |
| G7 proof primitive | Added frozen `ProofBundle`/`CustodyEvent` models with redacted evidence hashes, seal verification, immutable post-seal behavior, and deterministic replay verification. | Stores hashes/references rather than raw bodies, cookies, or secrets. |
| G7 state channel | Added initialized append-only `proof_bundles` state field. | Does not promote findings by itself; validator integration is still required. |

## Verification results

| Check | Result |
|---|---:|
| Full pytest regression | **667 passed** |
| Previous required baseline | 661 passed |
| New focused ProofBundle/smart tests | 15 passed |
| Ruff on modified source files (`E,F,W`, line length 100) | **All checks passed** |
| Live WAPTLab qualification | Not run; Docker API permission unavailable |

## G0–G10 compliance matrix

| Gate | Current assessment | Evidence / remaining gap |
|---|---|---|
| G0 Baseline/Reproducibility | Partial | Full regression is reproducible in the restored virtualenv. SBOM, signed release manifest, and PostgreSQL qualification are still absent. |
| G1 Action Authority | Improved / Partial | ActionAuthority, capability manifest, same-origin and risk checks exist. SecretStr, per-engagement identity vault, and a complete static no-direct-HTTP enforcement check remain open. |
| G2 Smart Runtime Wiring | Improved / Partial | Smart nodes are wired, state fields survive graph transitions, and CLI now supports `--mode`. Full topology/CLI contract coverage is still not equivalent to the formal gate. |
| G3 Surface Evidence Graph | Partial | Surface graph and deterministic refresh exist. Playwright/browser availability, family-diverse queue, GraphQL/OpenAPI discovery remain environment or implementation gaps. |
| G4 Identity/Tenant/Workflow | Not complete | Secondary identity entrypoints exist in parts of the project, but a complete dual-identity matrix and owner-vs-foreign differential proof across campaigns are not demonstrated by this review. |
| G5 Campaign Executor/NBA | Improved / Partial | Method-aware authorized-active execution, decision trace, idempotency, and bounded task selection are present. Full bounded DAG circuit-breakers and persisted durable traces remain open. |
| G6 Hypothesis Generation/Learning | Partial | Path/surface-driven hypothesis generation exists. Verified learning that changes task ordering with durable feedback is not fully closed. |
| G7 Validator Plugin System | Improved / Partial | Validator registry and campaign planning exist; `human_review_only` and immutable/replayable proof primitives were added. ProofBundle creation is not yet wired through every validator and replay is not a full browser/workflow replay harness. |
| G8 WAPTLab Ground Truth | Not complete | No deterministic ground-truth registry or three consecutive 15+/20 live runs were produced in this review. |
| G9 Persistence/Observability | Not complete | SQLite/checkpoint paths exist. PostgreSQL persistence and structured campaign metrics are still open. |
| G10 Release Qualification | Not started | The project must not be labeled Release A or VIP Autonomous Bug Hunter yet. |

## Why the live result should not be overstated

The prior live result remains **2 candidate findings and 0 confirmed vulnerabilities**. The dominant blockers identified earlier—missing browser capability, safe-smart GET-only policy, missing dual-identity differential, missing OOB channel, and validator/precondition gaps—are not all solved by this patch. Authorized-active now has a controlled POST path, but that capability is not equivalent to proving CSV, SSTI, SQLi, SSRF, stored-XSS, IDOR, or tenant-isolation findings on the real lab.

A finding should be reported as confirmed only when its validator emits reproducible evidence, including the required negative control where applicable. Candidate and human-review-only statuses remain deliberately distinct.

## Release recommendation

The resulting build is suitable for **continued controlled beta testing and offline regression**. It is not yet suitable for a claim of production-grade autonomous coverage of all 20 WAPTLab vulnerabilities. The next highest-impact work should be:

1. Implement and validate the owner/foreign dual-identity matrix with deterministic differential oracles.
2. Wire ProofBundle creation, sealing, and replay into validator results and reporter exports.
3. Add browser capability installation/qualification and browser-backed validators for DOM/stored XSS and workflow behavior.
4. Add deterministic WAPTLab ground-truth fixtures and repeatable three-run qualification.
5. Add a bounded OOB test channel for SSRF/XXE/RCE classes under explicit authorized scope.

## Integrity note

This report describes only the source changes and tests executed in the isolated review copy. The WAPTLab source was not modified.
