"""Economist — the ROI optimizer (NC-ECON-1, U-ECON-4).

The charter formula, verbatim (L-3: deterministic, no randomness, no LLM):

    EV(finding) = P_accept x payout x (1 - P_dup) x timing_bonus
                  / (effort + reputation_risk)

Component table (source and range per component):

    Component        Source                                    Range
    P_accept         vuln registry base rate (or severity      0-1
                     default from config/econ/roi_params.yaml)
    payout           market_kb severity curve typical, USD     >= 0
    P_dup            market_kb dup_rate x saturation           0-1
    timing_bonus     injected from U-ECON-5 context            0.5-1.5
    effort           hours estimate                            >= 0
    reputation_risk  injected risk of a poor-quality report    >= 0

Every valuation carries {ev_usd, ev_range, recommendation, components,
confidence, rationale, timestamp} (L-4). ``batch_value`` is exactly
``value`` applied per item — batch never invents its own economics.
Thresholds load from ``config/econ/roi_params.yaml``; corrupt/missing
degrades to defaults. Advisory only (L-1).
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.autonomous.hunt_contracts import redact
from webpent.econ.market_kb import MarketKB

_LOG = logging.getLogger(__name__)

DEFAULTS: dict[str, Any] = {
    "submit_threshold_usd": 100.0,
    "improve_threshold_usd": 25.0,
    "default_accept_by_severity": {
        "critical": 0.85,
        "high": 0.70,
        "medium": 0.50,
        "low": 0.30,
    },
    "default_class_weight": 1.0,
}


def load_roi_params(path: Any) -> dict[str, Any]:
    """Load roi_params.yaml; corrupt/missing -> defaults (fail-soft)."""
    config = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULTS.items()}
    if path is None:
        return config
    try:
        import yaml

        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return config
    except Exception as exc:
        _LOG.warning("roi params unreadable; using defaults: %s", exc)
        return config
    if not isinstance(raw, dict):
        return config
    roi = raw.get("roi") if isinstance(raw.get("roi"), dict) else raw
    with contextlib.suppress(TypeError, ValueError):
        if roi.get("submit_threshold_usd") is not None:
            config["submit_threshold_usd"] = max(0.0, float(roi["submit_threshold_usd"]))
        if roi.get("improve_threshold_usd") is not None:
            config["improve_threshold_usd"] = max(0.0, float(roi["improve_threshold_usd"]))
    by_sev = roi.get("default_accept_by_severity")
    if isinstance(by_sev, dict):
        parsed = {}
        for sev, rate in by_sev.items():
            with contextlib.suppress(TypeError, ValueError):
                parsed[str(sev)[:20]] = min(1.0, max(0.0, float(rate)))
        if parsed:
            config["default_accept_by_severity"] = parsed
    return config


@dataclass
class Finding:
    """A candidate report, as the economist sees it."""

    finding_id: str
    vuln_class: str
    severity: str
    program_id: str
    endpoint: str = ""
    effort_hours: float = 1.0
    reputation_risk: float = 0.0
    class_accept_rate: float | None = None  # injected from the vuln registry

    def sanitized(self) -> Finding:
        effort = max(0.0, float(self.effort_hours or 1.0))
        risk = max(0.0, float(self.reputation_risk or 0.0))
        accept = None
        if self.class_accept_rate is not None:
            with contextlib.suppress(TypeError, ValueError):
                accept = min(1.0, max(0.0, float(self.class_accept_rate)))
        return Finding(
            finding_id=redact(str(self.finding_id or ""))[:120],
            vuln_class=str(self.vuln_class or "")[:40].upper(),
            severity=str(self.severity or "")[:20].lower(),
            program_id=str(self.program_id or "")[:120],
            endpoint=redact(str(self.endpoint or ""))[:200],
            effort_hours=effort,
            reputation_risk=risk,
            class_accept_rate=accept,
        )


@dataclass
class FindingValuation:
    """Full transparency record of one EV computation (L-4)."""

    finding_id: str
    ev_usd: float
    ev_range: tuple[float, float]
    recommendation: str
    components: dict[str, float] = field(default_factory=dict)
    confidence: float = 1.0
    rationale: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "ev_usd": round(self.ev_usd, 2),
            "ev_range": [round(self.ev_range[0], 2), round(self.ev_range[1], 2)],
            "recommendation": self.recommendation,
            "components": {k: round(v, 4) for k, v in self.components.items()},
            "confidence": round(self.confidence, 3),
            "rationale": self.rationale,
            "timestamp": self.timestamp.isoformat(),
            "advisory": True,
        }


@dataclass
class ValueContext:
    """Everything valuation needs beyond the finding itself, injected."""

    now: float
    timing_bonus: float = 1.0  # U-ECON-5 wires this later
    saturation: float | None = None  # U-ECON-8 fills this later

    def sanitized(self) -> ValueContext:
        bonus = min(1.5, max(0.5, float(self.timing_bonus or 1.0)))
        saturation = None
        if self.saturation is not None:
            saturation = min(100.0, max(0.0, float(self.saturation)))
        return ValueContext(float(self.now), bonus, saturation)


class ROIOptimizer:
    """Deterministic EV(finding) valuation. Advisory only."""

    def __init__(self, kb: MarketKB, *, params_path: Any = None) -> None:
        self._kb = kb
        self.params = load_roi_params(params_path)

    def _p_accept(self, finding: Finding) -> float:
        if finding.class_accept_rate is not None:
            return finding.class_accept_rate
        return float(
            self.params["default_accept_by_severity"].get(
                finding.severity,
                self.params["default_accept_by_severity"].get("medium", 0.5),
            )
        )

    def value(self, finding: Finding, ctx: ValueContext) -> FindingValuation:
        finding = finding.sanitized() if isinstance(finding, Finding) else Finding(
            str(finding or ""), "", "medium", ""
        ).sanitized()
        ctx = ctx.sanitized()

        curve = self._kb.get_payout_range(finding.program_id, finding.severity)
        payout = curve.typical
        dup_base = self._kb.get_dup_rate(finding.program_id) if self._kb.has_program(
            finding.program_id
        ) else 0.5
        saturation_factor = (ctx.saturation / 100.0) if ctx.saturation is not None else 1.0
        p_dup = min(1.0, max(0.0, dup_base * saturation_factor))
        p_accept = self._p_accept(finding)
        denom = finding.effort_hours + finding.reputation_risk
        ev = p_accept * payout * (1.0 - p_dup) * ctx.timing_bonus / denom if denom > 0 else 0.0

        # honest range: EV recomputed at the curve's min and max payouts
        ev_min = (
            p_accept * curve.minimum * (1.0 - p_dup) * ctx.timing_bonus / denom
            if denom > 0 else 0.0
        )
        ev_max = (
            p_accept * curve.maximum * (1.0 - p_dup) * ctx.timing_bonus / denom
            if denom > 0 else 0.0
        )

        submit = float(self.params["submit_threshold_usd"])
        improve = float(self.params["improve_threshold_usd"])
        if ev >= submit:
            recommendation = "submit"
        elif ev >= improve:
            recommendation = "improve_first"
        else:
            recommendation = "skip"

        confidence = 1.0
        if not self._kb.has_program(finding.program_id):
            confidence -= 0.3  # payout curve came from the global fallback
        if finding.class_accept_rate is None:
            confidence -= 0.1  # accept rate is the severity default

        rationale = (
            f"P_accept {p_accept:.2f} x payout {payout:.0f}USD x (1-P_dup {p_dup:.2f}) "
            f"{1.0 - p_dup:.2f} x timing {ctx.timing_bonus:.2f} / effort "
            f"{finding.effort_hours:.2f} + risk {finding.reputation_risk:.2f} "
            f"= {ev:.2f}USD ({recommendation})"
        )
        return FindingValuation(
            finding_id=finding.finding_id,
            ev_usd=ev,
            ev_range=(ev_min, ev_max),
            recommendation=recommendation,
            components={
                "p_accept": p_accept,
                "payout_usd": payout,
                "p_dup": p_dup,
                "timing_bonus": ctx.timing_bonus,
                "effort_hours": finding.effort_hours,
                "reputation_risk": finding.reputation_risk,
            },
            confidence=max(0.0, confidence),
            rationale=rationale,
            timestamp=datetime.fromtimestamp(ctx.now, tz=timezone.utc),
        )

    def batch_value(self, findings: list[Finding], ctx: ValueContext) -> list[FindingValuation]:
        """Value each finding independently; batch adds nothing else (L-3)."""
        return [self.value(f, ctx) for f in list(findings)[:256]]


__all__ = [
    "DEFAULTS",
    "Finding",
    "FindingValuation",
    "ROIOptimizer",
    "ValueContext",
    "load_roi_params",
]
