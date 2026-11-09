"""Economist — the portfolio manager (NC-ECON-1, U-ECON-10).

Manages a portfolio of 5-50 targets through a four-state machine
(L-3: deterministic; L-8: ARCHIVED reactivation is manual only).

State machine (documented in ``docs/econ/portfolio_state_machine.md``):

    ACTIVE    intensive work (top of the budget map)
    WATCHING  CEM only (middle)
    DORMANT   rare periodic monitoring (bottom)
    ARCHIVED  swept (repeated campaign failures)

Transitions (the ONLY legal edges — anything else is rejected):

    From       To         Trigger
    WATCHING   ACTIVE     signal-high from CEM
    ACTIVE     WATCHING   EV_per_hour fell 50% for a week
    WATCHING   DORMANT    no change for 60 days
    DORMANT    ARCHIVED   3 consecutive failed campaigns
    ARCHIVED   WATCHING   operator reactivates manually

Every transition carries a reason (DoD) and is logged to a local JSONL
file with redact() on identifiers (L-4). ``auto_transition`` applies
the four automatic edges from injected observations; the manual edge
only happens through an explicit ``transition`` call. Corrupt/missing
portfolio YAML loads as an empty portfolio (fail-soft). Advisory only
(L-1): the manager plans, nothing here reports anything.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from webpent.econ.market_kb import Target

_LOG = logging.getLogger(__name__)

ACTIVE = "ACTIVE"
WATCHING = "WATCHING"
DORMANT = "DORMANT"
ARCHIVED = "ARCHIVED"

STATES = (ACTIVE, WATCHING, DORMANT, ARCHIVED)

#: the only legal edges of the state machine
LEGAL_TRANSITIONS: dict[tuple[str, str], str] = {
    (WATCHING, ACTIVE): "signal-high from CEM",
    (ACTIVE, WATCHING): "EV_per_hour fell 50% for a week",
    (WATCHING, DORMANT): "no change for 60 days",
    (DORMANT, ARCHIVED): "3 consecutive failed campaigns",
    (ARCHIVED, WATCHING): "operator reactivated manually",
}

MAX_TARGETS = 50
MIN_TARGETS = 5
DEFAULT_LOG_PATH = "download/econ/portfolio_transitions.jsonl"

#: share of the daily hours by state (mirrors U-ECON-6 pools)
PLAN_HOURS: dict[str, float] = {ACTIVE: 0.60, WATCHING: 0.30, DORMANT: 0.10, ARCHIVED: 0.0}


def _float_or(value: Any, default: float) -> float:
    """Coerce to float; fall back to ``default`` on garbage (R2-econ-07)."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int_or(value: Any, default: int) -> int:
    """Coerce to int; fall back to ``default`` on garbage (R2-econ-07)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerced_numeric_fields(row: dict) -> list[str]:
    """Names of present-but-corrupt numeric fields in one row (R2-econ-07).

    Absent/empty fields are fine (they carry defaults); only values that
    are present AND unparseable count as coerced.
    """
    bad: list[str] = []
    for name, cast in (
        ("ev_per_hour", float),
        ("total_findings", int),
        ("total_payout_usd", float),
    ):
        raw = row.get(name)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            continue
        try:
            cast(raw)
        except (TypeError, ValueError):
            bad.append(name)
    return bad


@dataclass
class PortfolioTarget:
    target: Target
    state: str = WATCHING
    last_transition: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ev_per_hour: float = 0.0
    total_findings: int = 0
    total_payout_usd: float = 0.0


@dataclass
class Transition:
    """One recorded edge traversal, with its reason (L-4)."""

    target_id: str
    from_state: str
    to_state: str
    reason: str
    timestamp: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat(),
            "advisory": True,
        }


@dataclass
class Portfolio:
    targets: dict[str, PortfolioTarget] = field(default_factory=dict)

    def by_state(self, state: str) -> list[PortfolioTarget]:
        return sorted(
            (t for t in self.targets.values() if t.state == state),
            key=lambda t: t.target.target_id,
        )


@dataclass
class AutoContext:
    """Injected observations for one auto-transition pass (L-2, L-4)."""

    now: datetime
    high_signals: dict[str, bool] = field(default_factory=dict)   # CEM signal-high
    ev_per_hour_now: dict[str, float] = field(default_factory=dict)
    ev_per_hour_week_ago: dict[str, float] = field(default_factory=dict)
    consecutive_campaign_failures: dict[str, int] = field(default_factory=dict)


@dataclass
class DailyPlan:
    """One day's hour split across the portfolio (advisory)."""

    date: datetime
    total_hours: float
    hours_by_state: dict[str, float] = field(default_factory=dict)
    targets_by_state: dict[str, list[str]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "date": self.date.isoformat(),
            "total_hours": round(self.total_hours, 4),
            "hours_by_state": {k: round(v, 4) for k, v in self.hours_by_state.items()},
            "targets_by_state": self.targets_by_state,
            "advisory": True,
        }


class PortfolioManager:
    """Loads, transitions and logs the target portfolio. Advisory only."""

    def __init__(self, *, now: datetime | None = None, log_path: Any = DEFAULT_LOG_PATH) -> None:
        self._now = now or datetime.now(timezone.utc)
        if self._now.tzinfo is None:
            self._now = self._now.replace(tzinfo=timezone.utc)
        self.log_path = Path(str(log_path))

    # ------------------------------------------------------------------ load
    def load(self, path: Path) -> Portfolio:
        """Load portfolio.yaml; corrupt/missing/oversized -> empty (fail-soft)."""
        portfolio = Portfolio()
        if path is None:
            return portfolio
        try:
            import yaml

            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return portfolio
        except Exception as exc:
            _LOG.warning("portfolio unreadable; loading empty: %s", exc)
            return portfolio
        rows = raw.get("targets") if isinstance(raw, dict) else raw
        if not isinstance(rows, list):
            return portfolio
        for row in rows[:MAX_TARGETS]:
            if not isinstance(row, dict):
                continue
            with contextlib.suppress(Exception):
                target = Target(
                    target_id=str(row.get("target_id") or ""),
                    program_id=str(row.get("program_id") or ""),
                )
                if not target.target_id:
                    continue
                state = str(row.get("state") or WATCHING).upper()
                if state not in STATES:
                    state = WATCHING
                last = row.get("last_transition")
                last_ts = self._now
                if isinstance(last, datetime):  # PyYAML parses ISO stamps natively
                    last_ts = last
                elif isinstance(last, str) and last.strip():
                    with contextlib.suppress(ValueError):
                        last_ts = datetime.fromisoformat(last.replace("Z", "+00:00"))
                if last_ts.tzinfo is None:
                    # R2-econ-01: PyYAML/fromisoformat can yield naive
                    # stamps; auto_transition subtracts them from an aware
                    # now() -> TypeError. Normalize to UTC at the border.
                    last_ts = last_ts.replace(tzinfo=timezone.utc)
                # R2-econ-07: each numeric field is coerced on its own so
                # one corrupt value keeps the target instead of erasing
                # it from daily_plan and the alerts entirely.
                portfolio.targets[target.target_id] = PortfolioTarget(
                    target=target,
                    state=state,
                    last_transition=last_ts,
                    ev_per_hour=_float_or(row.get("ev_per_hour"), 0.0),
                    total_findings=_int_or(row.get("total_findings"), 0),
                    total_payout_usd=_float_or(row.get("total_payout_usd"), 0.0),
                )
                coerced = _coerced_numeric_fields(row)
                if coerced:
                    _LOG.warning(
                        "target %s: corrupt numeric field(s) %s coerced to defaults",
                        target.target_id,
                        ", ".join(coerced),
                    )
        return portfolio

    # ------------------------------------------------------------------ save
    def save(self, portfolio: Portfolio, path: Path) -> None:
        """Write the portfolio back to YAML atomically (RT-02).

        Preserves the seven round-trip fields per target; a failed write
        leaves the previous file untouched (tempfile + os.replace).
        """
        rows = []
        for tid in sorted(portfolio.targets):
            pt = portfolio.targets[tid]
            rows.append({
                "target_id": pt.target.target_id,
                "program_id": pt.target.program_id,
                "state": pt.state,
                "ev_per_hour": float(pt.ev_per_hour),
                "total_findings": int(pt.total_findings),
                "total_payout_usd": float(pt.total_payout_usd),
                "last_transition": pt.last_transition.isoformat(),
            })
        import yaml

        text = yaml.safe_dump({"targets": rows}, sort_keys=False, allow_unicode=True)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
            os.replace(tmp_name, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise

    # ------------------------------------------------------------------ move
    def transition(
        self, portfolio: Portfolio, target_id: str, new_state: str, reason: str
    ) -> Portfolio:
        """Apply one edge of the state machine; illegal edges raise."""
        target_id = str(target_id or "")[:120]
        new_state = str(new_state or "").upper()
        if target_id not in portfolio.targets:
            raise ValueError(f"unknown target {target_id!r}")
        entry = portfolio.targets[target_id]
        if new_state not in STATES:
            raise ValueError(f"unknown state {new_state!r}")
        if new_state == entry.state:
            raise ValueError(f"{target_id} is already {new_state}")
        if (entry.state, new_state) not in LEGAL_TRANSITIONS:
            raise ValueError(
                f"illegal transition {entry.state} -> {new_state}; legal edges: "
                + ", ".join(f"{a}->{b}" for (a, b) in LEGAL_TRANSITIONS)
            )
        if not str(reason or "").strip():
            raise ValueError("every transition needs a reason (DoD)")
        old = entry.state
        entry.state = new_state
        entry.last_transition = self._now
        self._log(Transition(target_id, old, new_state, str(reason)[:200], self._now))
        return portfolio

    def _log(self, tr: Transition) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(tr.as_dict(), ensure_ascii=False)
            self.log_path.open("a", encoding="utf-8").write(line + "\n")
        except OSError as exc:
            _LOG.warning("transition log write failed: %s", exc)

    # ----------------------------------------------------------- auto moves
    def auto_transition(self, portfolio: Portfolio, ctx: AutoContext) -> list[Transition]:
        """Apply the four automatic edges from injected observations."""
        now = ctx.now if ctx.now.tzinfo else ctx.now.replace(tzinfo=timezone.utc)
        applied: list[Transition] = []
        for tid, entry in sorted(portfolio.targets.items()):
            if entry.last_transition.tzinfo is None:
                # R2-econ-01: belt-and-braces — a target built outside
                # load() may still carry a naive stamp.
                entry.last_transition = entry.last_transition.replace(
                    tzinfo=timezone.utc
                )
            old = entry.state

            # WATCHING -> ACTIVE: CEM signal-high
            if old == WATCHING and ctx.high_signals.get(tid) is True:
                entry.state, entry.last_transition = ACTIVE, now
                applied.append(Transition(tid, old, ACTIVE, "signal-high from CEM", now))

            # ACTIVE -> WATCHING: EV/hour fell 50%+ for a week
            elif old == ACTIVE:
                ev_now = ctx.ev_per_hour_now.get(tid)
                ev_before = ctx.ev_per_hour_week_ago.get(tid)
                if (
                    ev_now is not None
                    and ev_before is not None
                    and ev_before > 0
                    and ev_now <= 0.5 * ev_before
                ):
                    entry.state, entry.last_transition = WATCHING, now
                    applied.append(
                        Transition(
                            tid, old, WATCHING,
                            f"EV_per_hour fell to {ev_now:.1f} from {ev_before:.1f} "
                            "over a week",
                            now,
                        )
                    )

            # WATCHING -> DORMANT: no change for 60 days
            elif old == WATCHING and now - entry.last_transition >= timedelta(days=60):
                stale_days = (now - entry.last_transition).days  # before mutation (RT-05)
                entry.state, entry.last_transition = DORMANT, now
                applied.append(
                    Transition(
                        tid, old, DORMANT,
                        f"no change for {stale_days} days",
                        now,
                    )
                )

            # DORMANT -> ARCHIVED: 3 consecutive failed campaigns
            elif old == DORMANT and ctx.consecutive_campaign_failures.get(tid, 0) >= 3:
                entry.state, entry.last_transition = ARCHIVED, now
                applied.append(
                    Transition(
                        tid, old, ARCHIVED, "3 consecutive failed campaigns", now
                    )
                )

            # ARCHIVED -> WATCHING never happens automatically (L-8)
        for tr in applied:
            self._log(tr)
        return applied

    # ----------------------------------------------------------------- plan
    def daily_plan(self, portfolio: Portfolio, total_hours: float) -> DailyPlan:
        """Split one day's hours across states (ACTIVE 60/30/10 pools)."""
        if total_hours is None or float(total_hours) <= 0:
            raise ValueError("total_hours must be > 0")
        hours = {
            ACTIVE: PLAN_HOURS[ACTIVE] * float(total_hours),
            WATCHING: PLAN_HOURS[WATCHING] * float(total_hours),
            DORMANT: PLAN_HOURS[DORMANT] * float(total_hours),
            ARCHIVED: 0.0,
        }
        by_state = {
            s: [t.target.target_id for t in portfolio.by_state(s)] for s in STATES
        }
        return DailyPlan(
            date=self._now, total_hours=float(total_hours),
            hours_by_state=hours, targets_by_state=by_state,
        )


__all__ = [
    "ACTIVE",
    "ARCHIVED",
    "AutoContext",
    "DailyPlan",
    "DORMANT",
    "LEGAL_TRANSITIONS",
    "Portfolio",
    "PortfolioManager",
    "PortfolioTarget",
    "STATES",
    "Transition",
    "WATCHING",
]
