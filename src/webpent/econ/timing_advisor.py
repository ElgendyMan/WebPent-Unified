"""Economist — the timing advisor (NC-ECON-1, U-ECON-5) ⭐.

The charter's six timing actions, decided by an ordered, deterministic
rule matrix (L-3); the full matrix is documented in
``docs/econ/decision_matrix.md`` and mirrored in the docstring below:

    1. DEFER         deadline already passed (the window is gone;
                     re-evaluate at the next cycle)
    2. REPORT_NOW    strong, complete finding with a bounty deadline inside
                     the deadline window
    3. IMPROVE_FIRST strong EV but weak PoC or thin evidence: polish
                     before sending; prerequisites are listed
    4. COLLECT_MORE  EV is positive but evidence is thin: gather more
                     proof points first
    5. HOLD          complete enough to send, but the program is slow
                     (p90 beyond the threshold) or dup risk is high:
                     wait for a better moment
    6. REPORT_SOON   everything complete, no urgency: send within days

Every decision carries {action, rationale, deadline, prerequisites,
confidence, timestamp} (L-4) and is advisory only (L-1): nothing is
sent by anything here.
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.econ.market_kb import MarketKB
from webpent.econ.roi_optimizer import Finding, FindingValuation

_LOG = logging.getLogger(__name__)

REPORT_NOW = "REPORT_NOW"
REPORT_SOON = "REPORT_SOON"
IMPROVE_FIRST = "IMPROVE_FIRST"
COLLECT_MORE = "COLLECT_MORE"
HOLD = "HOLD"
DEFER = "DEFER"

TIMING_DEFAULTS: dict[str, Any] = {
    "deadline_window_hours": 48.0,
    "complete_evidence_points": 3,
    "slow_program_p90_days": 30.0,
    "hold_dup_risk": 0.5,
}


def load_timing_params(path: Any) -> dict[str, Any]:
    """Load the timing block of roi_params.yaml; corrupt/missing -> defaults."""
    config = dict(TIMING_DEFAULTS)
    if path is None:
        return config
    try:
        import yaml

        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return config
    except Exception as exc:
        _LOG.warning("timing params unreadable; using defaults: %s", exc)
        return config
    if not isinstance(raw, dict):
        return config
    timing = raw.get("timing") if isinstance(raw.get("timing"), dict) else raw
    for key in list(TIMING_DEFAULTS):
        if timing.get(key) is None:
            continue
        with contextlib.suppress(TypeError, ValueError):
            config[key] = max(0.0, float(timing[key]))
    return config


@dataclass
class TimingContext:
    """Timing inputs, injected; nothing is fetched (L-2).

    ``saturation_pct`` carries the U-ECON-8 saturation index (0-100)
    when the caller has one: when present, the HOLD rule judges
    duplicate risk on the saturation-adjusted P_dup (kb dup_rate x
    saturation/100, clamped to [0, 1]), mirroring the ROI optimizer
    (docs/econ/decision_matrix.md rule 5); when absent the raw KB
    dup_rate is used exactly as before (R2-econ-10).
    """

    now: float
    deadline_ts: float | None = None
    poc_ready: bool = False
    evidence_points: int = 0
    saturation_pct: float | None = None

    def sanitized(self) -> TimingContext:
        deadline = None
        if self.deadline_ts is not None:
            with contextlib.suppress(TypeError, ValueError):
                deadline = float(self.deadline_ts)
        saturation = None
        if self.saturation_pct is not None:
            with contextlib.suppress(TypeError, ValueError):
                saturation = min(100.0, max(0.0, float(self.saturation_pct)))
        return TimingContext(
            now=float(self.now),
            deadline_ts=deadline,
            poc_ready=bool(self.poc_ready),
            evidence_points=max(0, int(self.evidence_points or 0)),
            saturation_pct=saturation,
        )


@dataclass
class TimingDecision:
    """Full transparency record of one timing decision (L-4)."""

    action: str
    rationale: str
    deadline: float | None
    prerequisites: list[str] = field(default_factory=list)
    confidence: float = 1.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "rationale": self.rationale,
            "deadline": self.deadline,
            "prerequisites": list(self.prerequisites),
            "confidence": round(self.confidence, 3),
            "timestamp": self.timestamp.isoformat(),
            "advisory": True,
        }


class TimingAdvisor:
    """Ordered deterministic rule matrix over one finding's timing."""

    def __init__(self, kb: MarketKB, *, params_path: Any = None) -> None:
        self._kb = kb
        self._params_path = params_path
        self.params = load_timing_params(params_path)

    def decide(
        self, finding: Finding, valuation: FindingValuation, ctx: TimingContext
    ) -> TimingDecision:
        finding = finding.sanitized()
        ctx = ctx.sanitized()
        from webpent.econ.roi_optimizer import load_roi_params

        submit = float(load_roi_params(self._params_path)["submit_threshold_usd"])

        window = float(self.params["deadline_window_hours"]) * 3600.0
        complete_points = int(self.params["complete_evidence_points"])
        slow_p90 = float(self.params["slow_program_p90_days"])
        hold_dup = float(self.params["hold_dup_risk"])
        strong = valuation.ev_usd >= submit

        deadline = ctx.deadline_ts
        ts = datetime.fromtimestamp(ctx.now, tz=timezone.utc)
        program_p90 = (
            self._kb.get_response_time(finding.program_id).p90_days
            if self._kb.has_program(finding.program_id) else 0.0
        )
        dup_risk = self._kb.get_dup_rate(finding.program_id) if self._kb.has_program(
            finding.program_id
        ) else 0.5
        if ctx.saturation_pct is not None:
            # R2-econ-10: judge HOLD on the saturation-adjusted P_dup like
            # the ROI optimizer does (decision_matrix rule 5); ctx has
            # been sanitized, so saturation_pct is already within 0-100.
            dup_risk = min(1.0, max(0.0, dup_risk * (ctx.saturation_pct / 100.0)))

        def decision(
            action: str, why: str, prereqs: list[str] | None = None, conf: float = 1.0
        ) -> TimingDecision:
            return TimingDecision(
                action=action,
                rationale=why,
                deadline=deadline,
                prerequisites=prereqs or [],
                confidence=conf,
                timestamp=ts,
            )

        # 1. DEFER — the window is gone
        if deadline is not None and ctx.now > deadline:
            return decision(
                DEFER, "bounty deadline already passed; re-evaluate next cycle", conf=0.4
            )

        # 2. REPORT_NOW — deadline imminent and the finding is strong+complete
        complete = ctx.poc_ready and ctx.evidence_points >= complete_points
        if (
            deadline is not None
            and deadline - ctx.now <= window
            and strong
            and complete
        ):
            return decision(
                REPORT_NOW,
                f"strong finding (EV {valuation.ev_usd:.0f}USD) with deadline inside "
                f"the {self.params['deadline_window_hours']:.0f}h window",
            )
        # 3. IMPROVE_FIRST — strong EV but the report is not ready
        if strong and not complete:
            prereqs = []
            if not ctx.poc_ready:
                prereqs.append("produce a minimal reproducible PoC")
            if ctx.evidence_points < complete_points:
                prereqs.append(
                    f"collect {complete_points - ctx.evidence_points} more evidence points"
                )
            return decision(
                IMPROVE_FIRST,
                f"EV {valuation.ev_usd:.0f}USD is strong but the report is not "
                "submission-ready yet",
                prereqs,
            )
        # 4. COLLECT_MORE — positive EV, thin evidence
        if valuation.ev_usd > 0 and ctx.evidence_points < complete_points:
            return decision(
                COLLECT_MORE,
                f"only {ctx.evidence_points} evidence point(s); collect at least "
                f"{complete_points} before deciding",
                [f"collect {complete_points - ctx.evidence_points} more evidence points"],
                conf=0.7,
            )
        # 5. HOLD — sendable, but the moment is wrong
        if program_p90 > slow_p90 or dup_risk > hold_dup:
            reasons = []
            if program_p90 > slow_p90:
                reasons.append(f"program p90 response is {program_p90:.0f} days")
            if dup_risk > hold_dup:
                reasons.append(f"dup risk {dup_risk:.2f} is high")
            return decision(
                HOLD,
                "finding is complete but waiting wins: " + " and ".join(reasons),
                conf=0.6,
            )
        # 6. REPORT_SOON — complete, no urgency
        return decision(
            REPORT_SOON,
            f"finding complete (EV {valuation.ev_usd:.0f}USD); no deadline pressure: "
            "submit within days",
            conf=0.9,
        )


__all__ = [
    "COLLECT_MORE",
    "DEFER",
    "HOLD",
    "IMPROVE_FIRST",
    "REPORT_NOW",
    "REPORT_SOON",
    "TIMING_DEFAULTS",
    "TimingAdvisor",
    "TimingContext",
    "TimingDecision",
]
