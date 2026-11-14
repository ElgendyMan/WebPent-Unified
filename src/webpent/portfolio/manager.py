# src/webpent/portfolio/manager.py
"""webpent.portfolio.manager — ق11 portfolio_manager (FEATURE_PROPOSALS ق11).

Proposal contract (ق11، WebPent_FEATURE_PROPOSALS.md):

    fleet حقيقي متعدد الأهداف: production/worker_coordination +
    cross_process_leases + campaign_scheduler (legacy) — جدولة أهداف
    متعددة بأولويات وميزانيات منفصلة على workers Celery مع
    portfolio_manager كلوحة قيادة.

    ("A real multi-target fleet: production/worker_coordination +
    cross_process_leases + campaign_scheduler (legacy) — schedule
    multiple targets with separate priorities and budgets on Celery
    workers, with a portfolio_manager as the dashboard.")

New module — the fleet primitives are imported, never edited:
``scheduler.campaign_scheduler.ScheduledCampaign`` already owns
per-campaign caps and the wake cycle; ``production.worker_coordination.
WorkerCoordinator`` already owns cross-process claims. What was missing
is the PORTFOLIO layer above both:

* **Entries** — one :class:`PortfolioEntry` per target: priority
  (1 = highest … 5 = lowest), the target's own budget caps (USD,
  wallclock minutes, findings cap) and its linked campaign id.
* **Waves** — :meth:`PortfolioManager.plan_wave` produces the
  operator-inspectable launch order: priority-ascending, FIFO within a
  priority, fleet-capacity-bounded, with an explicit ``skipped`` list
  (reason per target: paused / exhausted / capped) — nothing is ever
  silently dropped. Each planned target carries the
  ``work_unit_id`` the WorkerCoordinator claim path expects
  (``portfolio:{campaign_id}:{target_ref}``), so claiming stays the
  coordinator's job.
* **Outcomes** — :meth:`PortfolioManager.record_outcome` accumulates
  spend per target and fails CLOSED at the caps: a target that crossed
  its budget/wallclock/findings cap is paused with the reason recorded;
  it cannot be re-planned until the operator resumes it.
* **Dashboard** — :meth:`PortfolioManager.dashboard` is the لوحة قيادة:
  fleet totals, per-target spend-vs-cap, next-in-line order, and the
  utilization ratio (planned vs capacity) — read-only, JSON-safe.

Postures inherited unchanged: fail-closed validation
(``PortfolioError`` on bad entries), no network (the scheduler/workers
own all execution), injected clock for deterministic waves.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "PortfolioEntry",
    "PortfolioError",
    "PortfolioManager",
    "PlanWave",
    "FleetDashboard",
]

PRIORITIES = frozenset({1, 2, 3, 4, 5})
_ENTRY_STATES = frozenset({"active", "paused", "exhausted"})

# Work-unit id vocabulary the WorkerCoordinator claim path uses.
WORK_UNIT_PREFIX = "portfolio"


class PortfolioError(ValueError):
    """Raised for invalid portfolio operations (fail-closed)."""


def _now_iso(now: Callable[[], datetime] | None) -> str:
    clock = now or (lambda: datetime.now(timezone.utc))
    return clock().isoformat(timespec="seconds")


@dataclass
class PortfolioEntry:
    """One target in the portfolio, with its own priority + budgets.

    ``campaign_id`` links the entry to the ScheduledCampaign record the
    scheduler owns (the portfolio does not duplicate scheduling — it
    orders and budgets it).
    """

    target_ref: str
    campaign_id: str
    priority: int = 3
    budget_usd_cap: float = 0.0
    wallclock_minutes_cap: float = 0.0
    max_findings_cap: int = 0
    state: str = "active"
    pause_reason: str = ""
    spent_usd: float = 0.0
    spent_wallclock_minutes: float = 0.0
    findings: int = 0
    created_at: str = ""

    def __post_init__(self) -> None:
        target = str(self.target_ref or "").strip()
        campaign = str(self.campaign_id or "").strip()
        if not target or not campaign:
            raise PortfolioError("portfolio_entry_requires_target_and_campaign")
        if self.priority not in PRIORITIES:
            raise PortfolioError(
                f"portfolio_bad_priority: {self.priority!r} (1..5, 1=highest)"
            )
        try:
            budget = float(self.budget_usd_cap)
            wallclock = float(self.wallclock_minutes_cap)
            findings = int(self.max_findings_cap)
        except (TypeError, ValueError) as exc:
            raise PortfolioError("portfolio_bad_caps") from exc
        if budget < 0 or wallclock < 0 or findings < 0:
            raise PortfolioError("portfolio_bad_caps_negative")
        if self.state not in _ENTRY_STATES:
            raise PortfolioError(f"portfolio_bad_state: {self.state!r}")
        object.__setattr__(self, "target_ref", target)
        object.__setattr__(self, "campaign_id", campaign)
        object.__setattr__(self, "budget_usd_cap", budget)
        object.__setattr__(self, "wallclock_minutes_cap", wallclock)
        object.__setattr__(self, "max_findings_cap", findings)

    @property
    def budget_exhausted(self) -> bool:
        if self.budget_usd_cap and self.spent_usd >= self.budget_usd_cap:
            return True
        if self.wallclock_minutes_cap and (
            self.spent_wallclock_minutes >= self.wallclock_minutes_cap
        ):
            return True
        if self.max_findings_cap and self.findings >= self.max_findings_cap:
            return True
        return False

    def remaining(self) -> dict[str, float | None]:
        return {
            "usd": (self.budget_usd_cap - self.spent_usd) if self.budget_usd_cap else None,
            "wallclock_minutes": (
                self.wallclock_minutes_cap - self.spent_wallclock_minutes
            )
            if self.wallclock_minutes_cap
            else None,
            "findings": (self.max_findings_cap - self.findings)
            if self.max_findings_cap
            else None,
        }

    def work_unit_id(self) -> str:
        return f"{WORK_UNIT_PREFIX}:{self.campaign_id}:{self.target_ref}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_ref": self.target_ref,
            "campaign_id": self.campaign_id,
            "priority": self.priority,
            "budget_usd_cap": self.budget_usd_cap,
            "wallclock_minutes_cap": self.wallclock_minutes_cap,
            "max_findings_cap": self.max_findings_cap,
            "state": self.state,
            "pause_reason": self.pause_reason,
            "spent_usd": round(self.spent_usd, 4),
            "spent_wallclock_minutes": round(self.spent_wallclock_minutes, 4),
            "findings": self.findings,
            "remaining": self.remaining(),
            "work_unit_id": self.work_unit_id(),
            "created_at": self.created_at,
        }


@dataclass
class PlanWave:
    """One launch plan: ordered admissions + explicit skips."""

    wave_id: str
    created_at: str
    planned: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    capacity: int = 0

    @property
    def utilization(self) -> float:
        return (len(self.planned) / self.capacity) if self.capacity else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "wave_id": self.wave_id,
            "created_at": self.created_at,
            "capacity": self.capacity,
            "utilization": round(self.utilization, 4),
            "planned": list(self.planned),
            "skipped": list(self.skipped),
        }


@dataclass
class FleetDashboard:
    """Read-only fleet view (the لوحة قيادة projection)."""

    generated_at: str
    totals: dict[str, Any] = field(default_factory=dict)
    targets: list[dict[str, Any]] = field(default_factory=list)
    next_in_line: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "totals": dict(self.totals),
            "targets": list(self.targets),
            "next_in_line": list(self.next_in_line),
            "advisory_only": True,
        }


class PortfolioManager:
    """Order + budget many targets across the worker fleet."""

    def __init__(self, *, now: Callable[[], datetime] | None = None) -> None:
        self._entries: dict[str, PortfolioEntry] = {}
        self._now = now
        self._wave_counter = 0

    # ------------------------------------------------------------------
    # entry lifecycle
    # ------------------------------------------------------------------

    def add(self, entry: PortfolioEntry) -> PortfolioEntry:
        """Register a target. Re-adding a target replaces its caps and
        priority but PRESERVES accumulated spend and operator state."""
        if not isinstance(entry, PortfolioEntry):
            raise PortfolioError("portfolio_entry_type_invalid")
        existing = self._entries.get(entry.target_ref)
        if existing is not None:
            entry.spent_usd = existing.spent_usd
            entry.spent_wallclock_minutes = existing.spent_wallclock_minutes
            entry.findings = existing.findings
            if entry.state == "active" and existing.state != "active":
                entry.state = existing.state
                entry.pause_reason = existing.pause_reason
            if not entry.created_at:
                entry.created_at = existing.created_at
        if not entry.created_at:
            entry.created_at = _now_iso(self._now)
        self._entries[entry.target_ref] = entry
        return entry

    def get(self, target_ref: str) -> PortfolioEntry | None:
        return self._entries.get(str(target_ref or "").strip())

    def list(self) -> list[PortfolioEntry]:
        return sorted(
            self._entries.values(),
            key=lambda e: (e.priority, e.created_at, e.target_ref),
        )

    def pause(self, target_ref: str, *, reason: str = "operator_paused") -> bool:
        entry = self._require(target_ref)
        entry.state = "paused"
        entry.pause_reason = reason
        return True

    def resume(self, target_ref: str) -> bool:
        entry = self._require(target_ref)
        if entry.budget_exhausted:
            entry.state = "exhausted"
            entry.pause_reason = "budget_cap_reached"
            raise PortfolioError("portfolio_resume_exhausted_target")
        entry.state = "active"
        entry.pause_reason = ""
        return True

    def _require(self, target_ref: str) -> PortfolioEntry:
        entry = self.get(target_ref)
        if entry is None:
            raise PortfolioError(f"portfolio_unknown_target: {target_ref!r}")
        return entry

    # ------------------------------------------------------------------
    # outcomes — spend accounting + fail-closed caps
    # ------------------------------------------------------------------

    def record_outcome(self, target_ref: str, outcome: Mapping[str, Any]) -> dict[str, Any]:
        """Accumulate one outcome; pause the target at any cap.

        Accepted keys: ``cost_usd`` (or ``budget_spent_usd``),
        ``wallclock_minutes``, ``findings_confirmed`` (or
        ``findings``). Negative values are refused (fail-closed); an
        unknown target is a PortfolioError, never a silent record.
        """
        entry = self._require(target_ref)

        def _number(*keys: str) -> float:
            for key in keys:
                if key in outcome:
                    try:
                        value = float(outcome[key])
                    except (TypeError, ValueError) as exc:
                        raise PortfolioError("portfolio_outcome_bad_number") from exc
                    if value < 0:
                        raise PortfolioError("portfolio_outcome_negative")
                    return value
            return 0.0

        entry.spent_usd += _number("cost_usd", "budget_spent_usd")
        entry.spent_wallclock_minutes += _number("wallclock_minutes")
        entry.findings += int(_number("findings_confirmed", "findings"))
        if entry.budget_exhausted and entry.state == "active":
            entry.state = "exhausted"
            entry.pause_reason = "budget_cap_reached"
        return entry.as_dict()

    # ------------------------------------------------------------------
    # waves — the launch plan
    # ------------------------------------------------------------------

    def plan_wave(self, *, capacity: int, wave_id: str | None = None) -> PlanWave:
        """Order the launchable targets for one fleet wake.

        Order: priority ascending (1 first), FIFO within a priority
        (created_at), target_ref as the final tiebreak. Eligibility:
        state == ``active`` and not budget-exhausted. Everyone else is
        recorded in ``skipped`` WITH a reason. Capacity bounds the
        admissions; the wave records the fleet utilization.
        """
        if capacity < 0:
            raise PortfolioError("portfolio_bad_capacity")
        self._wave_counter += 1
        wave = PlanWave(
            wave_id=wave_id or f"wave-{self._wave_counter:04d}",
            created_at=_now_iso(self._now),
            capacity=int(capacity),
        )
        for entry in self.list():
            if entry.state != "active":
                wave.skipped.append(
                    {
                        "target_ref": entry.target_ref,
                        "reason": f"state_{entry.state}",
                        "detail": entry.pause_reason,
                    }
                )
                continue
            if entry.budget_exhausted:
                entry.state = "exhausted"
                entry.pause_reason = "budget_cap_reached"
                wave.skipped.append(
                    {"target_ref": entry.target_ref, "reason": "budget_cap_reached", "detail": ""}
                )
                continue
            if len(wave.planned) >= capacity:
                wave.skipped.append(
                    {
                        "target_ref": entry.target_ref,
                        "reason": "fleet_capacity_full",
                        "detail": f"capacity={capacity}",
                    }
                )
                continue
            wave.planned.append(
                {
                    "target_ref": entry.target_ref,
                    "campaign_id": entry.campaign_id,
                    "priority": entry.priority,
                    "work_unit_id": entry.work_unit_id(),
                    "remaining": entry.remaining(),
                }
            )
        return wave

    # ------------------------------------------------------------------
    # dashboard
    # ------------------------------------------------------------------

    def dashboard(self, *, preview_depth: int = 5) -> FleetDashboard:
        entries = self.list()
        states: dict[str, int] = {"active": 0, "paused": 0, "exhausted": 0}
        total_spent = 0.0
        total_cap = 0.0
        for entry in entries:
            states[entry.state] = states.get(entry.state, 0) + 1
            total_spent += entry.spent_usd
            total_cap += entry.budget_usd_cap
        next_in_line = [
            e.target_ref for e in entries if e.state == "active" and not e.budget_exhausted
        ][: max(0, int(preview_depth))]
        return FleetDashboard(
            generated_at=_now_iso(self._now),
            totals={
                "targets": len(entries),
                "active": states["active"],
                "paused": states["paused"],
                "exhausted": states["exhausted"],
                "total_spent_usd": round(total_spent, 4),
                "total_budget_usd_cap": round(total_cap, 4),
                "budget_utilization": round(total_spent / total_cap, 4) if total_cap else 0.0,
            },
            targets=[e.as_dict() for e in entries],
            next_in_line=next_in_line,
        )
