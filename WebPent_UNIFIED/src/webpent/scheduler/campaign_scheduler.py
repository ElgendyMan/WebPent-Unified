# src/webpent/scheduler/campaign_scheduler.py
"""Campaign scheduler: due-based wake-ups, no daemon (V3 §5).

The operator schedules a campaign ahead of time (one JSONL record) and
every ``run_due_campaigns`` call wakes exactly the campaigns whose
``next_due`` has passed. State per campaign (``last_run``, ``next_due``,
cumulative spend/findings/wallclock, stop reason) lives in ONE JSON
file written ATOMICALLY (tmp + ``os.replace``) after each campaign, so
the next invocation always reads a complete state even after a crash
mid-wake.

Schedules: ``once`` (a single run at ``start_at``), ``daily`` and
``weekly`` (periodic; ``next_due`` advances from the actual run time so
skipped windows never pile up into a burst).

SAFETY (written into the module, not just the plan):

  - flag gate first: ``enable_scheduler`` False raises before any
    store is read;
  - the kill switch is checked before waking ANY campaign — an
    engaged switch is a refusal, not a pause;
  - every due campaign's target is RE-CHECKED against the operator's
    scope enforcer at wake time (a target that fell out of scope stops
    the campaign with ``stop_reason: scope_changed`` — scope is judged
    at every wake, not only at creation);
  - every campaign runs inside THREE caps (budget USD, wallclock
    minutes, findings count) tracked cumulatively across runs; a cap
    hit is a CLEAN STOP, never an abort of the wake loop;
  - the runner is injected (``runner(campaign, state) -> RunOutcome``)
    — this module owns no execution and no network.

Flag-gated by ``enable_scheduler`` (default False); the state path is
required (default empty = misconfiguration refusal at the CLI).
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

__all__ = [
    "SCHEDULE_CHOICES",
    "SchedulerError",
    "ScheduledCampaign",
    "CampaignRunState",
    "CampaignScheduleStore",
    "SchedulerStateFile",
    "RunOutcome",
    "WakeReport",
    "parse_iso_utc",
    "next_due_after",
    "run_due_campaigns",
]

SCHEDULE_CHOICES = frozenset({"once", "daily", "weekly"})

REQUIRED_CAMPAIGN_FIELDS = (
    "campaign_id",
    "target_ref",
    "schedule",
    "start_at",
    "budget_usd_cap",
    "wallclock_minutes_cap",
    "max_findings_cap",
)


class SchedulerError(ValueError):
    """Raised when the scheduler cannot proceed fail-closed."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso_utc(value: str) -> datetime:
    """Parse an ISO-8601 timestamp; naive timestamps fail closed."""
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SchedulerError(f"scheduler_bad_timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise SchedulerError(f"scheduler_naive_timestamp: {value!r}")
    return parsed.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Scheduled campaign record.
# ---------------------------------------------------------------------------


@dataclass
class ScheduledCampaign:
    """One operator-scheduled campaign (JSONL record, fail-closed load)."""

    campaign_id: str
    target_ref: str
    schedule: str  # once | daily | weekly
    start_at: str  # ISO UTC
    budget_usd_cap: float
    wallclock_minutes_cap: float
    max_findings_cap: int
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.campaign_id.strip():
            raise SchedulerError("scheduler_bad_campaign_id")
        if not self.target_ref.strip():
            raise SchedulerError("scheduler_bad_target_ref")
        if self.schedule not in SCHEDULE_CHOICES:
            raise SchedulerError(
                f"scheduler_bad_schedule: {self.schedule!r} "
                f"(one of {sorted(SCHEDULE_CHOICES)})"
            )
        parse_iso_utc(self.start_at)  # refuses naive/unparseable
        try:
            budget = float(self.budget_usd_cap)
            wallclock = float(self.wallclock_minutes_cap)
            findings = int(self.max_findings_cap)
        except (TypeError, ValueError) as exc:
            raise SchedulerError("scheduler_bad_caps") from exc
        if budget < 0:
            raise SchedulerError("scheduler_bad_budget_cap")
        if wallclock <= 0 or findings <= 0:
            raise SchedulerError("scheduler_bad_caps")
        object.__setattr__(self, "budget_usd_cap", budget)
        object.__setattr__(self, "wallclock_minutes_cap", wallclock)
        object.__setattr__(self, "max_findings_cap", findings)
        if not self.created_at:
            object.__setattr__(self, "created_at", _now_iso())

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "target_ref": self.target_ref,
            "schedule": self.schedule,
            "start_at": self.start_at,
            "budget_usd_cap": self.budget_usd_cap,
            "wallclock_minutes_cap": self.wallclock_minutes_cap,
            "max_findings_cap": self.max_findings_cap,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScheduledCampaign":
        if not isinstance(data, dict):
            raise SchedulerError("scheduler_record_not_an_object")
        unknown = set(data) - set(REQUIRED_CAMPAIGN_FIELDS) - {"created_at"}
        if unknown:
            raise SchedulerError(f"scheduler_record_unknown_fields: {sorted(unknown)}")
        missing = set(REQUIRED_CAMPAIGN_FIELDS) - set(data)
        if missing:
            raise SchedulerError(f"scheduler_record_missing_fields: {sorted(missing)}")
        for key in REQUIRED_CAMPAIGN_FIELDS:
            if not isinstance(data[key], (str, int, float)):
                raise SchedulerError(f"scheduler_record_bad_type: {key}")
            if isinstance(data[key], str) and not data[key].strip():
                raise SchedulerError(f"scheduler_record_empty_field: {key}")
        return cls(
            campaign_id=str(data["campaign_id"]),
            target_ref=str(data["target_ref"]),
            schedule=str(data["schedule"]),
            start_at=str(data["start_at"]),
            budget_usd_cap=data["budget_usd_cap"],
            wallclock_minutes_cap=data["wallclock_minutes_cap"],
            max_findings_cap=data["max_findings_cap"],
            created_at=str(data.get("created_at", "")),
        )


# ---------------------------------------------------------------------------
# Per-campaign run state (one JSON file, atomic writes).
# ---------------------------------------------------------------------------


@dataclass
class CampaignRunState:
    """Cumulative state of one scheduled campaign across wakes."""

    campaign_id: str
    next_due: str
    last_run_at: str = ""
    status: str = "scheduled"  # scheduled | completed | stopped
    stop_reason: str = ""
    cumulative_spend_usd: float = 0.0
    total_findings: int = 0
    cumulative_wallclock_minutes: float = 0.0
    run_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "next_due": self.next_due,
            "last_run_at": self.last_run_at,
            "status": self.status,
            "stop_reason": self.stop_reason,
            "cumulative_spend_usd": self.cumulative_spend_usd,
            "total_findings": self.total_findings,
            "cumulative_wallclock_minutes": self.cumulative_wallclock_minutes,
            "run_count": self.run_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CampaignRunState":
        if not isinstance(data, dict):
            raise SchedulerError("scheduler_state_not_an_object")
        required = {"campaign_id", "next_due"}
        missing = required - set(data)
        if missing:
            raise SchedulerError(f"scheduler_state_missing_fields: {sorted(missing)}")
        try:
            numeric = float(data.get("cumulative_spend_usd", 0.0) or 0.0)
            findings = int(data.get("total_findings", 0) or 0)
            wallclock = float(data.get("cumulative_wallclock_minutes", 0.0) or 0.0)
            runs = int(data.get("run_count", 0) or 0)
        except (TypeError, ValueError) as exc:
            raise SchedulerError("scheduler_state_bad_type") from exc
        return cls(
            campaign_id=str(data["campaign_id"]),
            next_due=str(data["next_due"]),
            last_run_at=str(data.get("last_run_at", "")),
            status=str(data.get("status", "scheduled")),
            stop_reason=str(data.get("stop_reason", "")),
            cumulative_spend_usd=numeric,
            total_findings=findings,
            cumulative_wallclock_minutes=wallclock,
            run_count=runs,
        )


class SchedulerStateFile:
    """JSON state file with atomic writes (tmp + os.replace, same dir)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def get(self, campaign_id: str) -> CampaignRunState | None:
        if not self.path.exists():
            return None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SchedulerError(f"scheduler_state_unreadable: {exc}") from exc
        if not isinstance(data, dict):
            raise SchedulerError("scheduler_state_not_an_object")
        campaigns = data.get("campaigns", {})
        if not isinstance(campaigns, dict):
            raise SchedulerError("scheduler_state_bad_shape")
        record = campaigns.get(campaign_id)
        if record is None:
            return None
        return CampaignRunState.from_dict(record)

    def put(self, state: CampaignRunState) -> None:
        data: dict[str, Any] = {"campaigns": {}}
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and isinstance(loaded.get("campaigns"), dict):
                    data["campaigns"] = loaded["campaigns"]
            except (OSError, json.JSONDecodeError) as exc:
                raise SchedulerError(f"scheduler_state_unreadable: {exc}") from exc
        data["campaigns"][state.campaign_id] = state.to_dict()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".scheduler-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.write("\n")
            os.replace(tmp_name, self.path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise


# ---------------------------------------------------------------------------
# Campaign store (JSONL, append-only records).
# ---------------------------------------------------------------------------


class CampaignScheduleStore:
    """Append-only JSONL store of ScheduledCampaign records."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def add(self, campaign: ScheduledCampaign) -> None:
        if self.find(campaign.campaign_id) is not None:
            raise SchedulerError(
                f"scheduler_duplicate_campaign: {campaign.campaign_id}"
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(campaign.to_dict(), ensure_ascii=False) + "\n")

    def list(self) -> list[ScheduledCampaign]:
        if not self.path.exists():
            return []
        out: list[ScheduledCampaign] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(ScheduledCampaign.from_dict(json.loads(line)))
                except (SchedulerError, json.JSONDecodeError) as exc:
                    raise SchedulerError(
                        f"scheduler_store_bad_line:{lineno}:{exc}"
                    ) from exc
        return out

    def find(self, campaign_id: str) -> ScheduledCampaign | None:
        for campaign in self.list():
            if campaign.campaign_id == campaign_id:
                return campaign
        return None


# ---------------------------------------------------------------------------
# Due computation and the wake loop.
# ---------------------------------------------------------------------------


def next_due_after(campaign: ScheduledCampaign, last_run: datetime) -> str:
    """Next due timestamp for a periodic schedule (documented drift rule).

    ``next_due`` advances from the ACTUAL run time, so a wake that ran
    late (or was skipped) never piles missed windows into a burst of
    back-to-back runs. ``once`` campaigns have no next due — the wake
    loop completes them instead.
    """
    if campaign.schedule == "daily":
        return (last_run + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    if campaign.schedule == "weekly":
        return (last_run + timedelta(weeks=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raise SchedulerError(f"scheduler_bad_schedule: {campaign.schedule!r}")


@dataclass
class RunOutcome:
    """What one runner invocation reports back (injected — no execution here)."""

    completed: bool = True
    spend_usd: float = 0.0
    findings_count: int = 0
    wallclock_minutes: float = 0.0
    detail: str = ""


@dataclass
class WakeReport:
    """Summary of one ``run_due_campaigns`` call."""

    checked: int = 0
    woken: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)


RunnerFn = Callable[[ScheduledCampaign, CampaignRunState], RunOutcome]


def run_due_campaigns(
    store: CampaignScheduleStore,
    state_file: SchedulerStateFile,
    *,
    runner: RunnerFn,
    now: datetime | None = None,
    scope_checker: Callable[[str], bool] | None = None,
) -> WakeReport:
    """Wake every due campaign within its caps, fail-closed.

    Order per campaign: due check → scope re-check → cap pre-check →
    run → caps re-check → clean stop or next_due. State is written
    atomically after EACH campaign, so a crash mid-wake leaves a
    complete per-campaign state behind.
    """
    from webpent.config.settings import get_settings
    from webpent.safety.kill_switch import engaged as kill_switch_engaged

    if not get_settings().enable_scheduler:
        raise SchedulerError("scheduler_flag_off")
    if kill_switch_engaged():
        raise SchedulerError("scheduler_kill_switch_engaged")
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise SchedulerError("scheduler_naive_now")

    report = WakeReport(checked=0)
    for campaign in store.list():
        report.checked += 1
        state = state_file.get(campaign.campaign_id)
        if state is None:
            state = CampaignRunState(
                campaign_id=campaign.campaign_id,
                next_due=campaign.start_at,
            )
        if state.status != "scheduled":
            continue
        if parse_iso_utc(state.next_due) > now:
            report.skipped.append(
                {"campaign_id": campaign.campaign_id, "reason": "not_due",
                 "next_due": state.next_due}
            )
            continue

        # scope re-check at EVERY wake — scope is the operator's live
        # decision, not a creation-time snapshot
        if scope_checker is not None and not scope_checker(campaign.target_ref):
            state.status = "stopped"
            state.stop_reason = "scope_changed"
            state_file.put(state)
            report.woken.append(
                {"campaign_id": campaign.campaign_id, "action": "stopped",
                 "stop_reason": "scope_changed"}
            )
            continue

        # cap pre-checks: a cap already hit stops the campaign cleanly
        if state.cumulative_spend_usd >= campaign.budget_usd_cap:
            state.status = "stopped"
            state.stop_reason = "budget_cap"
            state_file.put(state)
            report.woken.append(
                {"campaign_id": campaign.campaign_id, "action": "stopped",
                 "stop_reason": "budget_cap"}
            )
            continue
        if state.cumulative_wallclock_minutes >= campaign.wallclock_minutes_cap:
            state.status = "stopped"
            state.stop_reason = "wallclock_cap"
            state_file.put(state)
            report.woken.append(
                {"campaign_id": campaign.campaign_id, "action": "stopped",
                 "stop_reason": "wallclock_cap"}
            )
            continue
        if state.total_findings >= campaign.max_findings_cap:
            state.status = "stopped"
            state.stop_reason = "findings_cap"
            state_file.put(state)
            report.woken.append(
                {"campaign_id": campaign.campaign_id, "action": "stopped",
                 "stop_reason": "findings_cap"}
            )
            continue

        try:
            outcome = runner(campaign, state)
        except Exception as exc:  # noqa: BLE001 — one runner failing must not corrupt state
            report.woken.append(
                {"campaign_id": campaign.campaign_id, "action": "runner_error",
                 "detail": f"{type(exc).__name__}: {exc}"}
            )
            continue

        state.last_run_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        state.run_count += 1
        try:
            state.cumulative_spend_usd += max(0.0, float(outcome.spend_usd))
            state.total_findings += max(0, int(outcome.findings_count))
            state.cumulative_wallclock_minutes += max(0.0, float(outcome.wallclock_minutes))
        except (TypeError, ValueError) as exc:
            raise SchedulerError(f"scheduler_bad_outcome: {exc}") from exc

        stop_reason = ""
        if state.cumulative_spend_usd > campaign.budget_usd_cap:
            stop_reason = "budget_cap"
        elif state.cumulative_wallclock_minutes > campaign.wallclock_minutes_cap:
            stop_reason = "wallclock_cap"
        elif state.total_findings > campaign.max_findings_cap:
            stop_reason = "findings_cap"

        if stop_reason:
            state.status = "stopped"
            state.stop_reason = stop_reason
            action = "stopped"
        elif campaign.schedule == "once":
            state.status = "completed"
            action = "completed"
        else:
            state.next_due = next_due_after(campaign, now)
            action = "ran"
        state_file.put(state)
        report.woken.append(
            {"campaign_id": campaign.campaign_id, "action": action,
             "stop_reason": state.stop_reason,
             "spend_usd": state.cumulative_spend_usd,
             "total_findings": state.total_findings}
        )
    return report
