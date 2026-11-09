"""THE PRISM — U-PRISM-12, the Metrics Engine (v89).

"Metrics or it didn't happen" (PRISM-L-10). Every metric carries its
methodology, every comparison states what improved and by how much, and
an engine without data refuses to compute instead of inventing numbers.
Deterministic (PRISM-L-9): time is always passed in, never sampled.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from webpent.prism.errors import PrismLawError

# every metric and the exact way it is computed (PRISM-L-10)
METRICS_METHODOLOGY = {
    "signal_to_noise": "mean evidence score of accepted observations ÷ "
                       "max(mean score of rejected, 0.05), clamped [0, 10]",
    "acceptance": "accepted observations ÷ total observations",
    "avg_time_per_finding": "total hours ÷ max(1, accepted observations)",
    "rabbit_holes_avoided": "count of observations flagged avoided",
    "time_saved_hours": "rabbit_holes_avoided × max_time_hours (from "
                        "config/prism/curiosity_params.yaml; default 0.5 h)",
    "avg_evidence_score": "mean evidence score across the phase",
    "improvement_pct": "(after − before) ÷ before × 100, 0.0 when "
                       "before is 0",
}


@dataclass(frozen=True)
class Observation:
    phase: str                    # "before" | "after"
    accepted: bool
    time_hours: float
    evidence_score: float
    rabbit_hole_avoided: bool = False
    recorded_on: str = ""         # ISO date, e.g. "2026-10-18"

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "accepted": self.accepted,
            "time_hours": round(self.time_hours, 6),
            "evidence_score": round(self.evidence_score, 6),
            "rabbit_hole_avoided": self.rabbit_hole_avoided,
            "recorded_on": self.recorded_on,
        }


@dataclass(frozen=True)
class PrismMetrics:
    signal_to_noise_before: float
    signal_to_noise_after: float
    acceptance_before: float
    acceptance_after: float
    avg_time_per_finding_before: float
    avg_time_per_finding_after: float
    rabbit_holes_avoided: int
    time_saved_hours: float
    avg_evidence_score_before: float
    avg_evidence_score_after: float
    improvement_pct: float
    methodology: dict[str, str] = field(
        default_factory=lambda: dict(METRICS_METHODOLOGY)
    )

    def to_dict(self) -> dict[str, Any]:
        data = dict(self.__dict__)
        data["methodology"] = dict(self.methodology)
        return {k: (round(v, 6) if isinstance(v, float) else v)
                for k, v in data.items()}


@dataclass(frozen=True)
class ComparisonReport:
    acceptance_delta_pct: float
    evidence_score_delta: float
    time_delta_hours: float
    rabbit_holes_avoided_delta: int
    verdict: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "acceptance_delta_pct": round(self.acceptance_delta_pct, 6),
            "evidence_score_delta": round(self.evidence_score_delta, 6),
            "time_delta_hours": round(self.time_delta_hours, 6),
            "rabbit_holes_avoided_delta": self.rabbit_holes_avoided_delta,
            "verdict": self.verdict,
        }


def _clamp(value: float, low: float, high: float) -> float:
    return min(high, max(low, value))


def _phase_stats(observations: list[Observation]) -> dict[str, float]:
    total = len(observations)
    accepted = [o for o in observations if o.accepted]
    rejected = [o for o in observations if not o.accepted]
    acceptance = len(accepted) / total if total else 0.0
    signal = (sum(o.evidence_score for o in accepted) / len(accepted)
              if accepted else 0.0)
    noise = (sum(o.evidence_score for o in rejected) / len(rejected)
             if rejected else 0.0)
    snr = _clamp(signal / max(noise, 0.05), 0.0, 10.0) if accepted else 0.0
    avg_time = (sum(o.time_hours for o in accepted) / len(accepted)
                if accepted else 0.0)
    avg_score = (sum(o.evidence_score for o in observations) / total
                 if total else 0.0)
    return {
        "snr": snr,
        "acceptance": acceptance,
        "avg_time": avg_time,
        "avg_score": avg_score,
    }


class MetricsEngine:
    """Before/after measurement of what Prism changed (U-PRISM-12)."""

    # fallback when no config is provided; the single source of truth for
    # the configured value is config/prism/curiosity_params.yaml
    DEFAULT_TIME_SAVED_HOURS = 0.5

    def __init__(self, config_path: Path | str | None = None) -> None:
        self._observations: list[Observation] = []
        self._time_saved_per_rabbit_hole = self.DEFAULT_TIME_SAVED_HOURS
        if config_path is not None:
            path = Path(config_path)
            if not path.is_file():
                raise PrismLawError(
                    f"metrics config not found: {path}", law="PRISM-L-4"
                )
            config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            rabbit_hole = config.get("rabbit_hole")
            value = (
                rabbit_hole.get("max_time_hours")
                if isinstance(rabbit_hole, dict) else None
            )
            if not isinstance(value, (int, float)) or value <= 0:
                raise PrismLawError(
                    "metrics config: 'max_time_hours' must be a positive "
                    "number",
                    law="PRISM-L-1",
                )
            self._time_saved_per_rabbit_hole = float(value)

    @property
    def time_saved_per_rabbit_hole(self) -> float:
        return self._time_saved_per_rabbit_hole

    def record(self, observation: Observation) -> None:
        if observation.phase not in ("before", "after"):
            raise PrismLawError(
                f"observation phase must be 'before' or 'after', got "
                f"{observation.phase!r}",
                law="PRISM-L-10",
            )
        self._observations.append(observation)

    def compute(self, now: datetime, period_days: int = 30) -> PrismMetrics:
        if period_days <= 0:
            raise PrismLawError(
                "period_days must be positive", law="PRISM-L-10"
            )
        cutoff = (now - timedelta(days=period_days)).date().isoformat()
        recent = [o for o in self._observations
                  if not o.recorded_on or o.recorded_on >= cutoff]
        if not recent:
            raise PrismLawError(
                "no metrics without data (PRISM-L-10): record "
                "observations before computing",
                law="PRISM-L-10",
            )
        before = _phase_stats(
            [o for o in recent if o.phase == "before"])
        after = _phase_stats(
            [o for o in recent if o.phase == "after"])
        if before["acceptance"] == 0.0 and after["acceptance"] == 0.0:
            raise PrismLawError(
                "no accepted observations in either phase; improvement "
                "is undefined (PRISM-L-10)",
                law="PRISM-L-10",
            )
        before_acc, after_acc = before["acceptance"], after["acceptance"]
        improvement = (
            (after_acc - before_acc) / before_acc * 100.0
            if before_acc > 0 else 0.0
        )
        avoided = sum(1 for o in recent if o.rabbit_hole_avoided)
        return PrismMetrics(
            signal_to_noise_before=before["snr"],
            signal_to_noise_after=after["snr"],
            acceptance_before=before_acc,
            acceptance_after=after_acc,
            avg_time_per_finding_before=before["avg_time"],
            avg_time_per_finding_after=after["avg_time"],
            rabbit_holes_avoided=avoided,
            time_saved_hours=avoided * self._time_saved_per_rabbit_hole,
            avg_evidence_score_before=before["avg_score"],
            avg_evidence_score_after=after["avg_score"],
            improvement_pct=improvement,
        )

    def compare_to_baseline(self, baseline: PrismMetrics,
                            current: PrismMetrics) -> ComparisonReport:
        acceptance_delta = (
            (current.acceptance_after - baseline.acceptance_before)
            / baseline.acceptance_before * 100.0
            if baseline.acceptance_before > 0 else 0.0
        )
        evidence_delta = (
            current.avg_evidence_score_after
            - baseline.avg_evidence_score_before
        )
        time_delta = (
            current.avg_time_per_finding_after
            - baseline.avg_time_per_finding_before
        )
        holes_delta = (
            current.rabbit_holes_avoided - baseline.rabbit_holes_avoided
        )
        if acceptance_delta > 0 or evidence_delta > 0:
            verdict = "improved"
        elif acceptance_delta < 0 or evidence_delta < 0:
            verdict = "regressed"
        else:
            verdict = "flat"
        return ComparisonReport(
            acceptance_delta_pct=acceptance_delta,
            evidence_score_delta=evidence_delta,
            time_delta_hours=time_delta,
            rabbit_holes_avoided_delta=holes_delta,
            verdict=verdict,
        )

    def export(self, path: Path, now: datetime,
               period_days: int = 30) -> None:
        metrics = self.compute(now, period_days)
        payload = {
            "metrics": metrics.to_dict(),
            "observations": [o.to_dict() for o in self._observations],
            "methodology": dict(METRICS_METHODOLOGY),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )

    @classmethod
    def load(cls, path: Path) -> MetricsEngine:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        engine = cls()
        for raw in data.get("observations", []):
            engine.record(Observation(
                phase=raw["phase"],
                accepted=raw["accepted"],
                time_hours=float(raw["time_hours"]),
                evidence_score=float(raw["evidence_score"]),
                rabbit_hole_avoided=bool(raw.get(
                    "rabbit_hole_avoided", False)),
                recorded_on=str(raw.get("recorded_on", "")),
            ))
        return engine


__all__ = [
    "METRICS_METHODOLOGY", "ComparisonReport", "MetricsEngine",
    "Observation", "PrismMetrics",
]
