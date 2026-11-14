# Workers Ops Runbook — Celery Workers, Queues, Concurrency, Failure (Track 3.4)

**Date:** 2026-10-29 (RESIDUAL CLOSURE window, v0.26.0)
**Roadmap item:** المسار 3، البند 4 — "توثيق طريقة تشغيل العمال، والصفوف، والتزامن، وتقسيم الميزانية بين الحملات، وآلية التعامل مع تعطل العامل."

Until 0.25.0 this documentation did not exist, and the honest status of
distributed workers was recorded as NOT QUALIFIED in
`docs/integration/docker_celery_resume_report.md` (worker resume /
Redis multi-worker / Docker distributed ops). This runbook documents
what EXISTS and how to operate it, and restates the not-qualified
boundaries so nobody discovers them in production.

## 1. What the worker surface is

* `worker.py` (repo root) — the Celery worker entrypoint.
* `src/webpent/workers/pentest_worker.py` — the task payload: one
  engagement per task; the worker imports the full engine and runs the
  graph under the production spine contract.
* `src/webpent/api/workers_status.py` — the monitoring route
  (`/api/v1/workers/status`, `GET /api/v1/workers/health`) built on a
  lightweight celery `inspect()` bound to `WEBPENT_REDIS_URL` ONLY
  (an unconfigured broker never triggers a connection attempt).
* `src/webpent/dashboard/workers_page.html` — the light monitoring
  page (polls `/status` every 5 s, read-only).
* `src/webpent/workers/monitor_alerts.py` — stalled-worker detection +
  log alerts; scheduled by the API process when
  `WEBPENT_WORKER_ALERT_INTERVAL_S` is set (seconds; default 0 = off).

## 2. Running a worker (single-node, the qualified posture)

```bash
export WEBPENT_REDIS_URL="redis://<host>:6379/0"   # explicit, always
celery -A webpent.workers.pentest_worker worker --loglevel=INFO --concurrency=2
```

* `--concurrency` maps to worker processes; the ENGINE has its own
  cross-process concurrency governor (`production/concurrency_governor.py`,
  with optional file-lease backend `governor_cross_process`) — the
  Celery concurrency is transport-level, the governor is the authority
  on how many campaigns actually admit.
* The API container (docker-compose.yml, production profile) connects
  to the same broker; the workers profile is where scaling happens.

## 3. Budget splitting between campaigns

Budgets are enforced per campaign by the engine (mode presets +
dynamic step budget + cost ceilings) and per client/campaign by the
portfolio layer (`production/portfolio_manager.py`, Track 12.1: total /
per-client / per-campaign caps, fail-closed). Cross-process admission
is governed by `concurrency_governor.py`; per-campaign worker claims
are governed by `production/campaign_worker_claims.py` (0.25.0):
a RUNNING campaign holds a coordination claim; a second worker gets
`BUSY` (fail-closed) rather than double-running it.

## 4. Worker failure handling

* **Crash mid-engagement:** the campaign checkpoint survives in the
  checkpointer (`graph/checkpoints.py`); restart the worker and re-queue
  — the engine resumes from the last checkpoint state. What is NOT
  qualified (per the docker_celery_resume_report): automatic requeue of
  a task that vanished from the broker mid-flight across Redis restarts.
  Treat broker persistence as operator responsibility (Redis AOF or
  equivalent).
* **Stalled worker:** `detect_stalled_workers` flags no-heartbeat +
  no-active-engagement workers past `stalled_after_s` (default 900 s);
  alerts are log warnings via `check_stalled_and_alert`, scheduled when
  `WEBPENT_WORKER_ALERT_INTERVAL_S > 0`. The monitoring page shows the
  same classification live.
* **Worker cannot reach the DB:** startup preflight fails the worker
  (fail-closed) — it will not accept tasks in a broken posture.
* **Broker down:** the API's status route degrades to
  `available: false` honestly; the worker exits on connection loss and
  relies on the process supervisor (compose restart policy) to retry.

## 5. Not-qualified boundaries (unchanged, restated)

1. Multi-worker horizontal scale with automatic task rebalancing is
   NOT qualified — run ONE worker process (any concurrency) per
   deployment until the qualification matrix in
   `docs/integration/docker_celery_resume_report.md` is closed.
2. Cross-worker campaign claims (worker_coordination +
   campaign_worker_claims) are implemented and tested cross-process,
   but are feature-flagged off by default
   (`worker_coordination_enabled=false`); enable them only after
   reading their settings contract in `config/settings.py`.
3. Scheduled/beat-based campaign dispatch is NOT configured by
   default; `service/scheduler.py` exists but cron/beat wiring is an
   operator decision with explicit budget implications.
