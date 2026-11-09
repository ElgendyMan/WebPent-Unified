"""Judgment Council — U-JC-7: the Confidence Calibrator.

Confidence is a number, not a mood (JC-L-6). The calibrator stores
(predicted confidence, actual outcome) pairs, computes the Brier score
(mean squared error of the predictions; 0 = perfect), buckets them in 0.1
wide bands, detects drift (|mean predicted - mean actual| > 0.1 with at
least 20 samples) and offers ``adjust()`` — which does nothing until the
20-sample minimum is met, so early data cannot silently distort the
council's confidence.
"""

from __future__ import annotations

import json
import logging
import math
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from webpent.jc.contracts import clamp01

_LOG = logging.getLogger(__name__)

MIN_SAMPLES = 20
DRIFT_THRESHOLD = 0.1
BUCKET_WIDTH = 0.1
DEFAULT_WINDOW_DAYS = 30


@dataclass
class CalibrationReport:
    """One calibration snapshot (L-4 envelope)."""

    brier_score: float
    n_samples: int
    buckets: dict[str, dict[str, float]]
    drift_detected: bool
    recommendation: str
    mean_predicted: float = 0.0
    mean_actual: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "brier_score": round(self.brier_score, 4),
            "n_samples": self.n_samples,
            "buckets": self.buckets,
            "drift_detected": self.drift_detected,
            "recommendation": self.recommendation,
            "mean_predicted": round(self.mean_predicted, 4),
            "mean_actual": round(self.mean_actual, 4),
            "advisory": True,
        }


class ConfidenceCalibrator:
    """Records predicted vs actual and reports calibration health."""

    def __init__(self, path: Any, *, min_samples: int = MIN_SAMPLES) -> None:
        self.path = Path(str(path))
        self.min_samples = int(min_samples)

    # ------------------------------------------------------------- record
    def record(self, predicted: float, actual: bool, *,
               ts: float | None = None) -> None:
        """Append one (predicted, actual) pair to the JSONL log."""
        import time

        row = {
            "predicted": round(clamp01(predicted), 4),
            "actual": 1 if actual else 0,
            "ts": time.time() if ts is None else float(ts),
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        except OSError as exc:
            _LOG.warning("calibration record failed: %s", exc)

    # -------------------------------------------------------------- reads
    def _rows(self, window_days: int, now_ts: float) -> list[dict]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        cutoff = now_ts - max(1, int(window_days)) * 86400.0
        rows = []
        for line in lines:
            row = None
            with suppress(ValueError):
                row = json.loads(line)
            if not isinstance(row, dict):
                continue
            # R2-jc-05: a valid-JSON row with a corrupt "ts" is skipped,
            # not fatal — the module already tolerates corrupt JSON lines.
            try:
                ts = float(row.get("ts", 0.0) or 0.0)
            except (TypeError, ValueError):
                continue
            if ts >= cutoff:
                rows.append(row)
        return rows

    # ------------------------------------------------------------- report
    def report(self, window_days: int = DEFAULT_WINDOW_DAYS, *,
               now_ts: float | None = None) -> CalibrationReport:
        """Brier score, buckets, drift flag and a recommendation."""
        import time

        now_ts = time.time() if now_ts is None else float(now_ts)
        rows = self._rows(window_days, now_ts)
        n = len(rows)
        if n == 0:
            return CalibrationReport(
                brier_score=0.0, n_samples=0, buckets={},
                drift_detected=False,
                recommendation="no calibration data yet; record outcomes as they land",
            )
        predicted = [clamp01(r.get("predicted"), 0.5) for r in rows]
        actual = [1 if r.get("actual") == 1 else 0 for r in rows]
        brier = sum((p - a) ** 2 for p, a in zip(predicted, actual,
                                                 strict=False)) / n
        mean_pred = sum(predicted) / n
        mean_act = sum(actual) / n

        buckets: dict[str, dict[str, float]] = {}
        for p, a in zip(predicted, actual, strict=False):
            # R2-jc-04: 0.3/0.1 == 2.999... in IEEE-754, so int() truncated
            # predictions 0.3/0.6/0.7 into the bucket below; round the
            # quotient before flooring.
            low = min(
                0.9,
                max(0.0, math.floor(round(p / BUCKET_WIDTH, 9)) * BUCKET_WIDTH),
            )
            key = f"{low:.1f}-{low + BUCKET_WIDTH:.1f}"
            b = buckets.setdefault(key, {"predicted": 0.0, "actual": 0.0, "n": 0})
            b["predicted"] += p
            b["actual"] += a
            b["n"] += 1
        for b in buckets.values():
            b["predicted"] = round(b["predicted"] / b["n"], 4)
            b["actual"] = round(b["actual"] / b["n"], 4)
        buckets = dict(sorted(buckets.items()))

        drift = n >= self.min_samples and abs(mean_pred - mean_act) > DRIFT_THRESHOLD
        if n < self.min_samples:
            recommendation = (
                f"only {n}/{self.min_samples} samples; no adjustment until the minimum"
            )
        elif drift:
            recommendation = (
                f"drift detected: mean predicted {mean_pred:.2f} vs mean "
                f"actual {mean_act:.2f}; recalibrate via adjust()"
            )
        else:
            recommendation = "calibration within threshold; no action needed"
        return CalibrationReport(
            brier_score=brier,
            n_samples=n,
            buckets=buckets,
            drift_detected=drift,
            recommendation=recommendation,
            mean_predicted=mean_pred,
            mean_actual=mean_act,
        )

    # ------------------------------------------------------------- adjust
    def adjust(self, raw_confidence: float, *, now_ts: float | None = None) -> float:
        """Shift a confidence toward observed reality; no-op below minimum."""
        import time

        now_ts = time.time() if now_ts is None else float(now_ts)
        raw = clamp01(raw_confidence)
        rows = self._rows(DEFAULT_WINDOW_DAYS, now_ts)
        if len(rows) < self.min_samples:
            return raw
        predicted = [clamp01(r.get("predicted"), 0.5) for r in rows]
        actual = [1 if r.get("actual") == 1 else 0 for r in rows]
        shift = (sum(actual) / len(actual)) - (sum(predicted) / len(predicted))
        return clamp01(raw + shift)


__all__ = ["BUCKET_WIDTH", "DRIFT_THRESHOLD", "MIN_SAMPLES",
           "CalibrationReport", "ConfidenceCalibrator"]
