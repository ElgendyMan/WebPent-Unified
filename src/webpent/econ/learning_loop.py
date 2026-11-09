"""Economist — the learning loop optimizer (NC-ECON-1, U-ECON-11) ⭐.

Analyzes the operator's own submission history over time and turns it
into four kinds of advisory insights (L-3: deterministic; L-2: the
journal is a local JSONL file, nothing is fetched):

    1. class_focus    per vuln class: accepted / total submitted
    2. program_focus  per program: average accepted payout
    3. timing_adjust  average days from submission to acceptance
    4. dup_pattern    duplicate rejections grouped by endpoint signature

Statistical significance (DoD): NO insight is produced from fewer than
``MIN_DATA_POINTS`` (10) records in its group — a 2/2 acceptance rate
says nothing. Each insight carries {kind, recommendation, confidence,
data_points, rationale, timestamp} (L-4) and every one is logged to a
local JSONL file. ``apply_to_scheduler`` produces a SchedulerDelta —
a pure data record of suggested multipliers. It mutates nothing,
calls nothing, sends nothing: the scheduler (or the operator) decides
what to do with it (L-1, L-8). Empty or corrupt journal -> no insights,
never an exception.
"""

from __future__ import annotations

import contextlib
import json
import logging
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

MIN_DATA_POINTS = 10  # charter: no recommendations on fewer than 10 records
DEFAULT_JOURNAL = "download/econ/submissions.jsonl"
DEFAULT_LOG = "download/econ/learning_insights.jsonl"

KIND_CLASS_FOCUS = "class_focus"
KIND_PROGRAM_FOCUS = "program_focus"
KIND_TIMING_ADJUST = "timing_adjust"
KIND_DUP_PATTERN = "dup_pattern"

#: acceptance-rate band for the class_focus recommendation
FOCUS_INCREASE_BELOW = 0.75  # accepted/total above this -> increase focus
FOCUS_DECREASE_ABOVE = 0.25  # accepted/total below this -> decrease focus
DUP_HIGH_RATE = 0.4  # duplicate share above this -> adjust P_dup
SLOW_ACCEPTANCE_DAYS = 30.0  # mean time-to-acceptance above this -> timing
BUDGET_SHIFT_EDGE = 1.25  # program mean payout above 1.25x global -> shift


@dataclass
class SubmissionRecord:
    """One resolved submission, as the loop reads it from the journal."""

    finding_id: str
    vuln_class: str
    program_id: str
    submitted_at: datetime
    resolved_at: datetime | None
    status: str  # "accepted" | "rejected" | "duplicate"
    payout_usd: float = 0.0
    endpoint_signature: str = ""

    @property
    def days_to_resolve(self) -> float | None:
        if self.resolved_at is None:
            return None
        return (self.resolved_at - self.submitted_at).total_seconds() / 86400.0


@dataclass
class LearningInsight:
    kind: str  # class_focus | program_focus | timing_adjust | dup_pattern
    recommendation: str
    confidence: float
    data_points: int
    rationale: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "recommendation": self.recommendation,
            "confidence": round(self.confidence, 3),
            "data_points": self.data_points,
            "rationale": self.rationale,
            "timestamp": self.timestamp.isoformat(),
            "advisory": True,
        }


@dataclass
class SchedulerDelta:
    """Suggested multiplier changes — pure data, applies itself to nothing."""

    class_focus_multipliers: dict[str, float] = field(default_factory=dict)
    program_budget_multipliers: dict[str, float] = field(default_factory=dict)
    timing_bias_days: float = 0.0
    dup_rate_adjustments: dict[str, float] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "class_focus_multipliers": dict(self.class_focus_multipliers),
            "program_budget_multipliers": dict(self.program_budget_multipliers),
            "timing_bias_days": round(self.timing_bias_days, 3),
            "dup_rate_adjustments": dict(self.dup_rate_adjustments),
            "timestamp": self.timestamp.isoformat(),
            "advisory": True,
        }


def _parse_record(row: Any) -> SubmissionRecord | None:
    if not isinstance(row, dict):
        return None
    try:
        submitted = row.get("submitted_at")
        if not isinstance(submitted, str) or not submitted.strip():
            return None
        sub_at = datetime.fromisoformat(submitted.strip().replace("Z", "+00:00"))
        if sub_at.tzinfo is None:
            sub_at = sub_at.replace(tzinfo=timezone.utc)
        resolved = row.get("resolved_at")
        res_at = None
        if isinstance(resolved, str) and resolved.strip():
            res_at = datetime.fromisoformat(resolved.strip().replace("Z", "+00:00"))
            if res_at.tzinfo is None:
                res_at = res_at.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    status = str(row.get("status") or "").lower()
    if status not in ("accepted", "rejected", "duplicate"):
        return None
    with contextlib.suppress(TypeError, ValueError):  # RT-04: fail-soft on bad numbers
        payout = float(row.get("payout_usd") or 0.0)
        return SubmissionRecord(
            finding_id=redact(str(row.get("finding_id") or ""))[:120],
            vuln_class=str(row.get("vuln_class") or "")[:40].upper(),
            program_id=str(row.get("program_id") or "")[:120],
            submitted_at=sub_at,
            resolved_at=res_at,
            status=status,
            payout_usd=payout,
            endpoint_signature=redact(str(row.get("endpoint_signature") or ""))[:200],
        )
    return None


class LearningLoop:
    """Deterministic performance analysis over the submission journal."""

    def __init__(
        self,
        journal_path: Any = DEFAULT_JOURNAL,
        *,
        log_path: Any = DEFAULT_LOG,
        now: datetime | None = None,
    ) -> None:
        self.journal_path = Path(str(journal_path))
        self.log_path = Path(str(log_path))
        self._now = now or datetime.now(timezone.utc)
        if self._now.tzinfo is None:
            self._now = self._now.replace(tzinfo=timezone.utc)

    # ----------------------------------------------------------------- load
    def _records(self, period_days: int) -> list[SubmissionRecord]:
        cutoff = self._now - timedelta(days=float(period_days))
        try:
            lines = self.journal_path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        except OSError as exc:
            _LOG.warning("journal unreadable; no insights: %s", exc)
            return []
        out = []
        # R2-econ-04: the journal is append-only, so keeping the HEAD of
        # the file would silently exclude the newest submissions once it
        # grows past the cap; keep the TAIL instead.
        for line in lines[-4096:]:
            row: Any = None
            with contextlib.suppress(ValueError):
                row = json.loads(line)
            rec = _parse_record(row)
            if rec is not None and rec.submitted_at >= cutoff:
                out.append(rec)
        return out

    # -------------------------------------------------------------- analyze
    def analyze(self, period_days: int = 90) -> list[LearningInsight]:
        """Four insight kinds, each gated on >= MIN_DATA_POINTS records."""
        records = self._records(period_days)
        insights: list[LearningInsight] = []
        insights.extend(self._class_focus(records))
        insights.extend(self._program_focus(records))
        insights.extend(self._timing(records))
        insights.extend(self._dup_pattern(records))
        self._log(insights)
        return insights

    def _class_focus(self, records: list[SubmissionRecord]) -> list[LearningInsight]:
        by_class: dict[str, list[SubmissionRecord]] = {}
        for rec in records:
            if rec.vuln_class:
                by_class.setdefault(rec.vuln_class, []).append(rec)
        out = []
        for vuln_class, group in sorted(by_class.items()):
            total = len(group)
            accepted = sum(1 for r in group if r.status == "accepted")
            if total < MIN_DATA_POINTS:
                continue  # statistical significance threshold (DoD)
            rate = accepted / total
            if rate >= FOCUS_INCREASE_BELOW:
                rec_text = "increase focus"
            elif rate <= FOCUS_DECREASE_ABOVE:
                rec_text = "decrease focus"
            else:
                rec_text = "hold focus"
            out.append(
                LearningInsight(
                    kind=KIND_CLASS_FOCUS,
                    recommendation=f"{rec_text} on {vuln_class}",
                    confidence=min(1.0, total / (2 * MIN_DATA_POINTS)),
                    data_points=total,
                    rationale=(
                        f"{vuln_class}: {accepted}/{total} accepted "
                        f"({rate:.0%}); threshold band "
                        f"{FOCUS_DECREASE_ABOVE:.0%}-{FOCUS_INCREASE_BELOW:.0%}"
                    ),
                    timestamp=self._now,
                )
            )
        return out

    def _program_focus(self, records: list[SubmissionRecord]) -> list[LearningInsight]:
        payouts: dict[str, list[float]] = {}
        for rec in records:
            if rec.program_id and rec.status == "accepted" and rec.payout_usd > 0:
                payouts.setdefault(rec.program_id, []).append(rec.payout_usd)
        if not payouts:
            return []
        all_means = [statistics.mean(v) for v in payouts.values() if len(v) >= MIN_DATA_POINTS]
        if not all_means:
            return []
        global_mean = statistics.mean(all_means)
        out = []
        for program_id, values in sorted(payouts.items()):
            if len(values) < MIN_DATA_POINTS:
                continue
            mean = statistics.mean(values)
            if mean >= BUDGET_SHIFT_EDGE * global_mean:
                rec_text = "shift more budget here"
            elif mean <= global_mean / BUDGET_SHIFT_EDGE:
                rec_text = "shift budget away"
            else:
                rec_text = "hold budget"
            out.append(
                LearningInsight(
                    kind=KIND_PROGRAM_FOCUS,
                    recommendation=f"{rec_text}: {program_id}",
                    confidence=min(1.0, len(values) / (2 * MIN_DATA_POINTS)),
                    data_points=len(values),
                    rationale=(
                        f"{program_id}: mean accepted payout {mean:.0f}USD vs "
                        f"portfolio mean {global_mean:.0f}USD"
                    ),
                    timestamp=self._now,
                )
            )
        return out

    def _timing(self, records: list[SubmissionRecord]) -> list[LearningInsight]:
        days = [
            r.days_to_resolve
            for r in records
            if r.status == "accepted" and r.days_to_resolve is not None
        ]
        if len(days) < MIN_DATA_POINTS:
            return []
        mean = statistics.mean(days)
        if mean > SLOW_ACCEPTANCE_DAYS:
            rec_text = (
                f"slow acceptance ({mean:.0f}d mean): bias the timing advisor "
                "toward REPORT_SOON earlier and prefer faster programs"
            )
        else:
            rec_text = f"acceptance is fast ({mean:.0f}d mean): keep current timing"
        return [
            LearningInsight(
                kind=KIND_TIMING_ADJUST,
                recommendation=rec_text,
                confidence=min(1.0, len(days) / (2 * MIN_DATA_POINTS)),
                data_points=len(days),
                rationale=(
                    f"mean time-to-acceptance {mean:.1f} days over {len(days)} "
                    f"accepted submissions (threshold {SLOW_ACCEPTANCE_DAYS:.0f})"
                ),
                timestamp=self._now,
            )
        ]

    def _dup_pattern(self, records: list[SubmissionRecord]) -> list[LearningInsight]:
        dups = [r for r in records if r.status == "duplicate"]
        if len(dups) < MIN_DATA_POINTS:
            return []
        submissions = [r for r in records if r.status in ("accepted", "rejected", "duplicate")]
        dup_rate = len(dups) / max(1, len(submissions))
        by_prefix: dict[str, int] = {}
        for r in dups:
            parts = [p for p in r.endpoint_signature.split("/") if p][:2]
            prefix = "/" + "/".join(parts) if parts else "/"
            by_prefix[prefix] = by_prefix.get(prefix, 0) + 1
        hot_prefix, hot_count = max(by_prefix.items(), key=lambda kv: (kv[1], kv[0]))
        hot_share = hot_count / len(dups)
        out = [
            LearningInsight(
                kind=KIND_DUP_PATTERN,
                recommendation=(
                    f"adjust P_dup estimates upward (dup rate {dup_rate:.0%} of "
                    f"submissions; {hot_count}/{len(dups)} duplicates share the "
                    f"prefix {hot_prefix})"
                ),
                confidence=min(1.0, len(dups) / (2 * MIN_DATA_POINTS)),
                data_points=len(dups),
                rationale=(
                    f"top duplicate pattern: endpoint prefix {hot_prefix} carries "
                    f"{hot_share:.0%} of duplicates; same endpoint and same vuln "
                    f"family get found by others first"
                ),
                timestamp=self._now,
            )
        ]
        return out

    # ----------------------------------------------------------- scheduler
    def apply_to_scheduler(self, insights: list[LearningInsight]) -> SchedulerDelta:
        """Translate insights into a pure advisory SchedulerDelta (L-1)."""
        delta = SchedulerDelta(timestamp=self._now)
        for ins in insights:
            if ins.kind == KIND_CLASS_FOCUS:
                parts = ins.recommendation.split()
                if len(parts) >= 2:
                    direction, vuln_class = parts[0], parts[-1]
                    mult = {"increase": 1.25, "decrease": 0.75, "hold": 1.0}.get(direction)
                    if mult is not None:
                        delta.class_focus_multipliers[vuln_class] = mult
            elif ins.kind == KIND_PROGRAM_FOCUS:
                # recommendation shape: "<shift text>: <program_id>"
                program = ins.recommendation.rsplit(": ", 1)[-1]
                if "more budget" in ins.recommendation:
                    delta.program_budget_multipliers[program] = 1.25
                elif "away" in ins.recommendation:
                    delta.program_budget_multipliers[program] = 0.75
                else:
                    delta.program_budget_multipliers[program] = 1.0
            elif ins.kind == KIND_TIMING_ADJUST and "slow" in ins.recommendation:
                with contextlib.suppress(ValueError):
                    mean_text = ins.rationale.split("mean time-to-acceptance ")[1]
                    mean_days = float(mean_text.split(" days")[0])
                    delta.timing_bias_days = min(7.0, max(0.0, mean_days - SLOW_ACCEPTANCE_DAYS))
            elif ins.kind == KIND_DUP_PATTERN:
                dup_rate = 0.5 if ins.data_points >= 2 * MIN_DATA_POINTS else 0.25
                delta.dup_rate_adjustments["*"] = dup_rate
        return delta

    # ----------------------------------------------------------------- log
    def _log(self, insights: list[LearningInsight]) -> None:
        if not insights:
            return
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as fh:
                for ins in insights:
                    fh.write(json.dumps(ins.as_dict(), ensure_ascii=False) + "\n")
        except OSError as exc:
            _LOG.warning("insight log write failed: %s", exc)


__all__ = [
    "BUDGET_SHIFT_EDGE",
    "DUP_HIGH_RATE",
    "FOCUS_DECREASE_ABOVE",
    "FOCUS_INCREASE_BELOW",
    "KIND_CLASS_FOCUS",
    "KIND_DUP_PATTERN",
    "KIND_PROGRAM_FOCUS",
    "KIND_TIMING_ADJUST",
    "LearningInsight",
    "MIN_DATA_POINTS",
    "SchedulerDelta",
    "SubmissionRecord",
    "LearningLoop",
]
