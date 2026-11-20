"""Durable application scheduler; separate from the research-loop scheduler."""
from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Callable
from typing import Any

from webpent.service.manager import CampaignManager
from webpent.service.models import SchedulerJob
from webpent.service.store import ServiceStore


class CampaignScheduler:
    def __init__(self, store: ServiceStore, manager: CampaignManager) -> None:
        self.store = store
        self.manager = manager

    @staticmethod
    def _parse(value: str) -> dt.datetime:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))

    def schedule(self, campaign_id: str, *, due_at: str, window_start: str | None = None,
                 window_end: str | None = None, retry_limit: int = 2) -> SchedulerJob:
        if retry_limit < 0 or retry_limit > 10:
            raise ValueError("retry_limit_out_of_range")
        self._parse(due_at)
        if window_start:
            self._parse(window_start)
        if window_end:
            self._parse(window_end)
        job = SchedulerJob(uuid.uuid4().hex, campaign_id, due_at, window_start, window_end, retry_limit)
        self.store.schedule_job(job, created_at=dt.datetime.now(dt.timezone.utc).isoformat())
        return job

    def tick(self, *, now: str | None = None,
             runner: Callable[[str], Any] | None = None,
             on_complete: Callable[[str], Any] | None = None) -> list[dict[str, Any]]:
        current = self._parse(now) if now else dt.datetime.now(dt.timezone.utc)
        current_text = current.isoformat()
        results: list[dict[str, Any]] = []
        for job in self.store.due_jobs(current_text):
            if not self.store.claim_job(job["job_id"], now=current_text):
                continue
            start = self._parse(job["window_start"]) if job.get("window_start") else None
            end = self._parse(job["window_end"]) if job.get("window_end") else None
            if start and current < start:
                self.store.finish_job(job["job_id"], status="scheduled", attempts=int(job["attempts"]), due_at=start.isoformat())
                results.append({"job_id": job["job_id"], "status": "window_not_open"})
                continue
            if end and current > end:
                self.store.finish_job(job["job_id"], status="expired", attempts=int(job["attempts"]), last_error="schedule_window_expired")
                results.append({"job_id": job["job_id"], "status": "expired"})
                continue
            attempts = int(job["attempts"]) + 1
            try:
                self.manager.start_campaign(job["campaign_id"])
                if runner:
                    runner(job["campaign_id"])
                self.manager.complete_campaign(job["campaign_id"])
                if on_complete:
                    on_complete(job["campaign_id"])
                self.store.finish_job(job["job_id"], status="completed", attempts=attempts)
                results.append({"job_id": job["job_id"], "status": "completed"})
            except Exception as exc:  # bounded retry; no truth fabrication
                if attempts <= int(job["retry_limit"]):
                    delay = min(3600, 2 ** max(0, attempts - 1) * 60)
                    due = (current + dt.timedelta(seconds=delay)).isoformat()
                    self.manager.transient_failure(job["campaign_id"], str(exc))
                    self.store.finish_job(job["job_id"], status="scheduled", attempts=attempts,
                                          last_error=str(exc), due_at=due)
                    results.append({"job_id": job["job_id"], "status": "retry_scheduled", "attempts": attempts})
                else:
                    self.manager.transient_failure(job["campaign_id"], str(exc))
                    self.store.finish_job(job["job_id"], status="failed", attempts=attempts, last_error=str(exc))
                    results.append({"job_id": job["job_id"], "status": "failed", "attempts": attempts})
        return results


__all__ = ["CampaignScheduler"]
