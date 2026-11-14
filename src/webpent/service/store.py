"""Durable product-layer storage; never stores credentials or raw target bodies."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from webpent.service.models import (
    AlertEvent,
    CampaignSpec,
    HealthRun,
    SchedulerJob,
    canonical_json,
)


class ServiceStore:
    """Small SQLite control-plane store with atomic idempotency operations."""

    def __init__(self, path: str | Path = "/tmp/webpent-service/service.sqlite") -> None:
        self.path = Path(path).expanduser()
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    target_origin TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    budget_limit REAL NOT NULL,
                    max_actions INTEGER NOT NULL,
                    vault_namespace TEXT NOT NULL,
                    audit_namespace TEXT NOT NULL,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    retry_limit INTEGER NOT NULL DEFAULT 2,
                    window_start TEXT,
                    window_end TEXT,
                    last_error TEXT NOT NULL DEFAULT '',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS usage (
                    campaign_id TEXT PRIMARY KEY,
                    llm_calls INTEGER NOT NULL DEFAULT 0,
                    reported_tokens INTEGER NOT NULL DEFAULT 0,
                    cache_hits INTEGER NOT NULL DEFAULT 0,
                    cheap_model_calls INTEGER NOT NULL DEFAULT 0,
                    tokens_saved INTEGER NOT NULL DEFAULT 0,
                    actual_cost REAL NOT NULL DEFAULT 0.0,
                    FOREIGN KEY(campaign_id) REFERENCES campaigns(campaign_id)
                );
                CREATE TABLE IF NOT EXISTS findings (
                    campaign_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'unknown',
                    title TEXT NOT NULL DEFAULT '',
                    evidence_ref TEXT NOT NULL DEFAULT '',
                    cost REAL NOT NULL DEFAULT 0.0,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(campaign_id, finding_id, status)
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    idempotency_key TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scheduler_jobs (
                    job_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    due_at TEXT NOT NULL,
                    window_start TEXT,
                    window_end TEXT,
                    retry_limit INTEGER NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'scheduled',
                    last_error TEXT NOT NULL DEFAULT '',
                    claimed_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS health_runs (
                    run_id TEXT NOT NULL,
                    gate_name TEXT NOT NULL,
                    exit_code INTEGER NOT NULL,
                    ok INTEGER NOT NULL,
                    output_digest TEXT NOT NULL,
                    output_preview TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT NOT NULL,
                    source_digest TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(run_id, gate_name)
                );
                CREATE TABLE IF NOT EXISTS health_schedule (
                    job_name TEXT PRIMARY KEY,
                    last_run TEXT,
                    next_run TEXT NOT NULL
                );
                """
            )

    def create_campaign(self, spec: CampaignSpec, *, run_id: str | None = None,
                        vault_namespace: str | None = None,
                        audit_namespace: str | None = None,
                        created_at: str) -> dict[str, Any]:
        run_id = run_id or uuid.uuid4().hex
        vault_namespace = vault_namespace or f"vault:{spec.campaign_id}:{run_id}"
        audit_namespace = audit_namespace or f"audit:{spec.campaign_id}:{run_id}"
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO campaigns
                (campaign_id, run_id, target_url, target_origin, owner_id, state,
                 budget_limit, max_actions, vault_namespace, audit_namespace,
                 retry_limit, window_start, window_end, metadata_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'PLANNED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (spec.campaign_id, run_id, spec.target_url, spec.target_origin,
                 spec.owner_id, float(spec.budget_limit), int(spec.max_actions),
                 vault_namespace, audit_namespace, int(spec.retry_limit),
                 spec.window_start, spec.window_end, canonical_json(spec.metadata),
                 created_at, created_at),
            )
            conn.execute("INSERT INTO usage(campaign_id) VALUES (?)", (spec.campaign_id,))
        return self.get_campaign(spec.campaign_id)

    def get_campaign(self, campaign_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
        if row is None:
            raise KeyError(f"campaign_not_found:{campaign_id}")
        result = dict(row)
        result["metadata"] = json.loads(result.pop("metadata_json") or "{}")
        return result

    def list_campaigns(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM campaigns ORDER BY created_at").fetchall()
        return [self._campaign_row(row) for row in rows]

    @staticmethod
    def _campaign_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["metadata"] = json.loads(result.pop("metadata_json") or "{}")
        return result

    def update_campaign(self, campaign_id: str, **fields: Any) -> dict[str, Any]:
        allowed = {"state", "retry_count", "last_error", "updated_at", "window_start", "window_end"}
        clean = {key: value for key, value in fields.items() if key in allowed}
        if not clean:
            return self.get_campaign(campaign_id)
        assignments = ", ".join(f"{key}=?" for key in clean)
        values = [clean[key] for key in clean]
        values.append(campaign_id)
        with self._lock, self._connect() as conn:
            cursor = conn.execute(f"UPDATE campaigns SET {assignments} WHERE campaign_id=?", values)
            if cursor.rowcount != 1:
                raise KeyError(f"campaign_not_found:{campaign_id}")
        return self.get_campaign(campaign_id)

    def record_usage(self, campaign_id: str, *, calls: int = 0, reported_tokens: int = 0,
                     cache_hits: int = 0, cheap_model_calls: int = 0,
                     tokens_saved: int = 0, actual_cost: float = 0.0) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE usage SET llm_calls=llm_calls+?, reported_tokens=reported_tokens+?,
                cache_hits=cache_hits+?, cheap_model_calls=cheap_model_calls+?,
                tokens_saved=tokens_saved+?, actual_cost=actual_cost+?
                WHERE campaign_id=?""",
                (max(0, int(calls)), max(0, int(reported_tokens)), max(0, int(cache_hits)),
                 max(0, int(cheap_model_calls)), max(0, int(tokens_saved)), max(0.0, float(actual_cost)), campaign_id),
            )

    def get_usage(self, campaign_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM usage WHERE campaign_id=?", (campaign_id,)).fetchone()
        return dict(row) if row else {"campaign_id": campaign_id}

    def upsert_finding(self, campaign_id: str, finding: dict[str, Any], *, status: str,
                       cost: float = 0.0, created_at: str) -> None:
        finding_id = str(finding.get("finding_id") or finding.get("id") or "unknown")[:160]
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO findings
                (campaign_id, finding_id, status, severity, title, evidence_ref, cost, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (campaign_id, finding_id, status, str(finding.get("severity") or "unknown")[:32],
                 str(finding.get("title") or "")[:300], str(finding.get("evidence_ref") or "")[:160],
                 max(0.0, float(cost)), canonical_json(finding), created_at),
            )

    def list_findings(self, campaign_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM findings WHERE campaign_id=? ORDER BY created_at", (campaign_id,)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json") or "{}")
            result.append(item)
        return result

    def claim_alert(self, event: AlertEvent) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO alerts(idempotency_key,campaign_id,kind,payload_json,status,created_at) VALUES(?,?,?,?,?,?)",
                (event.idempotency_key, event.campaign_id, event.kind, canonical_json(event.payload), "pending", event.created_at),
            )
            return cursor.rowcount == 1

    def finish_alert(self, idempotency_key: str, *, status: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("UPDATE alerts SET status=? WHERE idempotency_key=?", (status[:32], idempotency_key))

    def list_alerts(self, campaign_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM alerts"
        args: tuple[Any, ...] = ()
        if campaign_id:
            query += " WHERE campaign_id=?"
            args = (campaign_id,)
        query += " ORDER BY created_at"
        with self._connect() as conn:
            rows = conn.execute(query, args).fetchall()
        return [dict(row) for row in rows]

    def schedule_job(self, job: SchedulerJob, *, created_at: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO scheduler_jobs(job_id,campaign_id,due_at,window_start,window_end,retry_limit,attempts,status,created_at)
                VALUES(?,?,?,?,?,?,?, ?, ?)""",
                (job.job_id, job.campaign_id, job.due_at, job.window_start, job.window_end,
                 job.retry_limit, job.attempts, job.status, created_at),
            )

    def due_jobs(self, now: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM scheduler_jobs WHERE status='scheduled' AND due_at<=? ORDER BY due_at", (now,)).fetchall()
        return [dict(row) for row in rows]

    def claim_job(self, job_id: str, *, now: str) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute("UPDATE scheduler_jobs SET status='running', claimed_at=? WHERE job_id=? AND status='scheduled'", (now, job_id))
            return cursor.rowcount == 1

    def finish_job(self, job_id: str, *, status: str, attempts: int, last_error: str = "", due_at: str | None = None) -> None:
        with self._lock, self._connect() as conn:
            if due_at is None:
                conn.execute("UPDATE scheduler_jobs SET status=?, attempts=?, last_error=? WHERE job_id=?", (status, attempts, last_error[:300], job_id))
            else:
                conn.execute("UPDATE scheduler_jobs SET status='scheduled', attempts=?, last_error=?, due_at=? WHERE job_id=?", (attempts, last_error[:300], due_at, job_id))

    def list_jobs(self, campaign_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM scheduler_jobs"
        args: tuple[Any, ...] = ()
        if campaign_id:
            query += " WHERE campaign_id=?"
            args = (campaign_id,)
        with self._connect() as conn:
            rows = conn.execute(query + " ORDER BY due_at", args).fetchall()
        return [dict(row) for row in rows]

    def save_health_run(self, result: HealthRun) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO health_runs
                (run_id,gate_name,exit_code,ok,output_digest,output_preview,started_at,ended_at,source_digest)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (result.run_id, result.gate_name, result.exit_code, int(result.ok), result.output_digest,
                 result.output_preview[:2000], result.started_at, result.ended_at, result.source_digest),
            )

    def list_health_runs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM health_runs ORDER BY ended_at DESC LIMIT ?", (max(1, min(1000, int(limit))),)).fetchall()
        return [dict(row) for row in rows]

    def get_health_schedule(self, job_name: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM health_schedule WHERE job_name=?", (job_name,)).fetchone()
        return dict(row) if row else None

    def set_health_schedule(self, job_name: str, *, last_run: str, next_run: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO health_schedule(job_name,last_run,next_run) VALUES(?,?,?) "
                "ON CONFLICT(job_name) DO UPDATE SET last_run=excluded.last_run,next_run=excluded.next_run",
                (job_name, last_run, next_run),
            )


__all__ = ["ServiceStore"]
