# Phase 10 — Production Architecture Assessment

**Assessment date:** 2026-08-23  
**Repository:** `ElgendyMan/webpent-v61`  
**Assessment scope:** source and deployment configuration only; no external target activity and no claim of live production qualification.

## Executive decision

> **Decision: NOT PRODUCTION-QUALIFIED for a multi-instance or multi-tenant deployment.**
>
> **Conditionally usable:** the current implementation is suitable for a controlled, single-node, owner-operated lab or pilot when the production profile is used, secrets are injected securely, Redis is independently operated over TLS, and SQLite persistence is treated as a single-writer local store.

The architecture already contains the important control-plane boundaries: scope enforcement, Action Authority, evidence/proof gates, authenticated API options, rate limiting, Celery task execution, fail-closed backend capability reporting, and health checks. The assessment does **not** recommend rebuilding those components. The limiting issue is operational qualification: the default persistence implementation is SQLite-only, while the production compose file contains an optional PostgreSQL service that the application explicitly refuses to qualify. A deployment that starts PostgreSQL without an application PostgreSQL backend would create a misleading production posture, so the fail-closed behavior is correct and must remain.

## Evidence-based capability matrix

| Area | Observed implementation | Status | Required qualification or remediation |
|---|---|---:|---|
| API process | FastAPI served by `server.py`/Uvicorn; container health check calls `/health` | Present | Add an independently tested reverse proxy/TLS and load-balancer profile before public exposure |
| Worker execution | Celery app uses Redis broker/backend, JSON serialization, late acknowledgements, prefetch 1, startup retry, bounded task time limits, and result expiry | Present, not fully qualified | Qualify worker crash recovery, duplicate delivery, broker outage, and result-backend loss under representative load |
| Broker | Production compose requires externally supplied `REDIS_URL`; development compose owns local plaintext Redis | Conditionally ready | Use managed Redis or separately operated Redis with `rediss://`, certificate validation, ACLs, backup/restore, and monitoring |
| Primary persistence | Native managers and checkpointers are SQLite-backed; `BackendCapabilityReport` marks SQLite qualified | Qualified only for bounded single-node use | Do not run multiple writers or multiple API/worker replicas against the SQLite bind mount; add and independently qualify a transactional production backend before horizontal scaling |
| PostgreSQL | Optional compose profile exists, but `BackendCapabilityReport` marks PostgreSQL unsupported and fail-closed | Not qualified | Implement migrations, repositories, locking, checkpoint semantics, isolation tests, backup/restore, and a production rehearsal; until then keep the profile disabled |
| Tenant/engagement isolation | Client and engagement scope are carried through memory and campaign contracts; missing scope fails closed in relevant paths | Implemented at application-contract level | Add deployment-level integration tests with concurrent tenants and verify no shared-volume, log, cache, or result leakage |
| Authentication/RBAC | Production compose explicitly enables auth and requires JWT/audit/Celery secrets plus explicit users | Present, configuration-gated | Use an external identity provider or a controlled secrets/user lifecycle for real production; test rotation and revocation procedures |
| Rate limiting | API rate limits and Redis-backed distributed rate-limit configuration are present | Present, configuration-gated | Verify limits across replicas, fail behavior during Redis outage, and alerting on abuse or exhaustion |
| Secrets | Compose uses required environment interpolation for critical secrets; comments prohibit weak defaults | Hardened configuration | Use a secret manager, rotation, redaction tests, and a procedure that prevents secrets from appearing in process listings or logs |
| Filesystem state | `output`, `memory`, and `webpent.db` are bind-mounted; runtime artifacts are local filesystem state | Safe for controlled single-node use | Use encrypted, access-controlled storage, retention rules, backup/restore tests, and avoid shared writable mounts across replicas |
| RAG/vector memory | Chroma and SQLite-backed memory paths exist, with scoped retrieval contracts | Present, not deployment-qualified | Qualify persistence durability, index rebuild, concurrent access, retention, and per-client/engagement deletion |
| LLM boundary | Provider routing is lazy and advisory; provider failures must not become evidence or confirmation | Present | Keep provider credentials outside images; test provider timeout, quota, malformed output, and deterministic fallback in production-like conditions |
| Logging | JSON logging is configured in the production compose; worker observability records bounded task lifecycle data | Present, incomplete operationally | Add centralized collection, immutable audit retention, PII/secret scanning, correlation IDs, dashboards, and alert thresholds |
| Metrics/tracing | No Prometheus/OpenTelemetry/Grafana implementation was found in the assessed source paths | Missing | Add an observability design and qualification tests before claiming SLO/SLA readiness; do not infer health from logs alone |
| Backup/restore | Local SQLite and named volumes are defined; no verified production backup/restore run is part of this assessment | Incomplete | Define encrypted backups, RPO/RTO, restore rehearsal, corruption handling, and tenant-scoped recovery procedures |
| Container hardening | Image has a health check and startup entrypoint that drops to `webpent`; production compose avoids publishing Redis/PostgreSQL ports | Present | Pin base-image digests, scan images, use a read-only root filesystem where compatible, apply seccomp/capability policy, and qualify upgrades |
| Network boundary | Compose uses an internal bridge network; API port is configurable; optional tunnel is profile-gated | Present, configuration-gated | Place API behind a hardened ingress, restrict egress, document OOB callback exposure, and test SSRF/scope controls after deployment changes |
| Deployment lifecycle | Compose supports API and worker services with restart policies | Pilot-level | Add migration ordering, rollout/rollback procedure, readiness checks for dependencies, version compatibility checks, and canary rehearsal |

## Architectural risks that must not be hidden

### SQLite is the current production ceiling

The source-level capability contract explicitly qualifies `sqlite` and rejects `postgres`/`postgresql` until an independent implementation is available. The compose file’s PostgreSQL profile is therefore an infrastructure placeholder, not a supported persistence mode. SQLite can be valid for a single-node pilot, but a bind-mounted SQLite file is not a safe substitute for a transactional multi-replica database. Running several API or worker writers would create locking, consistency, and recovery risks around findings, checkpoints, action ledgers, leases, and memory stores.

### Celery availability is not worker qualification

The worker has meaningful reliability settings, including late acknowledgements, fair prefetch, retries, bounded execution time, and redacted failure telemetry. Those settings reduce risk but do not prove correct recovery. A production qualification must intentionally terminate a worker during a task, observe redelivery/idempotency, simulate broker loss, verify no credential or raw request leakage in failure/DLQ records, and confirm that a human approval checkpoint remains safe after recovery.

### Health is not readiness

The container health check verifies the HTTP health endpoint. It does not by itself establish that Redis, the database, the checkpointer, the vector store, the browser runtime, or configured LLM providers are healthy and compatible. Readiness should remain capability-specific and fail closed; a provider being unavailable must be reported as degraded/unavailable rather than treated as a successful scan or proof.

### Observability is not yet an SLO system

Structured JSON logs and bounded worker lifecycle records are useful foundations. They are not a complete metrics/tracing system. Production operation still needs measurable queue latency, task duration, retry and redelivery rate, proof-promotion rate, failed-closed rate, scope-denial rate, storage errors, provider degradation, and per-engagement correlation without exposing secrets or sensitive payloads.

## Recommended deployment profiles

### Profile A — qualified controlled pilot

Use one API instance and one worker process or a deliberately bounded worker deployment. Use SQLite only as a single-writer local store, externally managed Redis over TLS, explicit authentication, strong secrets from a protected secret store, restricted CORS, JSON logs, and regular encrypted backups. Keep the PostgreSQL compose profile disabled. This profile is appropriate for an owner-authorized lab or a small internal pilot, not an unrestricted public SaaS service.

### Profile B — production-scale target

Before enabling multiple API or worker replicas, implement and independently qualify a transactional persistence backend, including migrations and all isolation-sensitive repositories. Then qualify distributed locking/idempotency, checkpoint recovery, memory/index durability, backup/restore, observability, ingress/egress policy, secret rotation, and rolling upgrades. Only after those tests pass should a production-scale status be considered.

## Acceptance gates for a future qualification

A future release may be assessed again only when all of the following are evidenced by replayable test artifacts:

1. The selected primary database backend is supported by the application capability contract and passes migration, concurrency, isolation, corruption, backup, and restore tests.
2. Two or more API/worker instances can process the same engagement without duplicate side effects, cross-client data, lost checkpoints, or weakened Action Authority.
3. Redis outage, worker crash, task redelivery, and result-backend loss are handled with bounded retries and idempotent state transitions.
4. Readiness distinguishes API liveness from dependency readiness and reports degraded optional providers honestly.
5. Logs, metrics, and traces are centrally collected with secret/PII redaction and engagement/client correlation.
6. Secret rotation, revocation, archive retention, deletion, and tenant-scoped recovery are rehearsed.
7. A release image is pinned, scanned, reproducibly built, and deployed through a tested rollback path.
8. Security qualification continues to require target-backed causal signal, an independent negative control, a sealed replayable ProofBundle, and successful replay. Findings, candidates, fixtures, LLM output, or benchmark labels alone never qualify confirmation.

## Final assessment

The project has a credible hardened control plane and is materially beyond a simple scanner. It is **not honest to label the current repository VIP production-ready** based on source tests or compose syntax alone. The correct current label is:

> **Engineering-ready for controlled, single-node authorized operation; not qualified for horizontally scaled production or multi-tenant SaaS deployment.**

This assessment intentionally preserves the existing fail-closed PostgreSQL capability guard and does not add speculative infrastructure. The next engineering work should be a separately scoped persistence qualification project, followed by deployment-level resilience and observability rehearsals—not a rewrite of the Target Brain, reasoners, experiment engine, or proof authority.

## Source references

1. [`docker-compose.yml`](../docker-compose.yml) — production profile, required secrets, external TLS Redis requirement, optional PostgreSQL profile, bind mounts, health check, and service topology.
2. [`Dockerfile`](../Dockerfile) — application image, health-check context, and runtime handoff configuration.
3. [`src/webpent/persistence/backend_capability.py`](../src/webpent/persistence/backend_capability.py) — fail-closed persistence capability report and current SQLite qualification boundary.
4. [`src/webpent/workers/pentest_worker.py`](../src/webpent/workers/pentest_worker.py) — Celery broker/backend setup, reliability settings, bounded task timeouts, and worker observability hooks.
5. [`src/webpent/workers/observability.py`](../src/webpent/workers/observability.py) — bounded worker lifecycle and dead-letter observability records.
6. [`docs/production_hardening.md`](production_hardening.md) — existing operational hardening profile reconciled by this assessment.
7. [`pyproject.toml`](../pyproject.toml) — declared FastAPI/Uvicorn, Celery/Redis, Chroma, and migration-related dependencies; declarations are not treated as qualification evidence.
8. [`src/webpent/shared/action_authority.py`](../src/webpent/shared/action_authority.py) and [`src/webpent/models/evidence.py`](../src/webpent/models/evidence.py) — preserved authorization and evidence/proof boundaries referenced by the deployment acceptance gates.

These are repository references, not independent production qualification evidence. A future qualification must attach replayable deployment test artifacts for the acceptance gates above.
