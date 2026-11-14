"""U-VERDICT-6 — the Metrics and Verdict Calculator.

Computes every campaign KPI from the recorded state and applies the
final-verdict decision table. The verdict is a function of the data,
not of hope: the same state always produces the same outcome
(deterministic, PRISM-L-9 in spirit).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from verdict_tool.tracking import VerdictState

OUTCOMES = ("GO", "GO_CAUTIOUS", "IMPROVE", "NO-GO")


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    value = datetime.fromisoformat(ts)
    if value.tzinfo is None:
        value = value.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return value


def _hours_between(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    return max(0.0, (end - start).total_seconds() / 3600.0)


@dataclass
class VerdictMetrics:
    # findings
    total_findings: int
    confirmed_findings: int
    false_positives: int
    inconclusive: int
    fp_rate: float
    # submissions
    submitted: int
    accepted: int
    rejected: int
    duplicates: int
    under_review: int
    acceptance_rate: float
    # timing
    time_to_first_finding_hours: float | None
    time_to_first_accepted_days: float | None
    # pre-registration accuracy
    predicted_findings_range: tuple[int, int] | None
    predicted_acceptance_range: tuple[float, float] | None
    predictions_accurate: dict[str, bool]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["predicted_findings_range"] = (
            list(self.predicted_findings_range)
            if self.predicted_findings_range else None
        )
        payload["predicted_acceptance_range"] = (
            list(self.predicted_acceptance_range)
            if self.predicted_acceptance_range else None
        )
        return payload


class VerdictCalculator:
    """KPI computation and the final-verdict decision table (U-VERDICT-6)."""

    def compute(self, state: VerdictState) -> VerdictMetrics:
        findings = state.findings
        classified = [f for f in findings if f.get("classification")]
        confirmed = sum(
            1 for f in classified
            if f["classification"] == "confirmed"
        )
        fps = sum(
            1 for f in classified
            if f["classification"] == "false_positive"
        )
        inconclusive = sum(
            1 for f in classified
            if f["classification"] == "inconclusive"
        )
        fp_rate = fps / len(classified) if classified else 0.0

        submitted = len(state.submissions)
        by_status = dict.fromkeys(("accepted", "rejected", "duplicate", "under_review"), 0)
        accepted_times: list[datetime] = []
        for entry in state.watch:
            status = entry.get("status")
            if status in by_status:
                by_status[status] += 1
            if status == "accepted":
                when = _parse(entry.get("updated_at"))
                if when:
                    accepted_times.append(when)

        submission_times = [
            _parse(s.get("submitted_at")) for s in state.submissions
        ]
        submission_times = [t for t in submission_times if t]
        first_accepted = min(accepted_times) if accepted_times else None
        first_submission = min(submission_times) if submission_times else None
        days_to_accepted: float | None = None
        if first_accepted and first_submission:
            days_to_accepted = max(
                0.0,
                (first_accepted - first_submission).total_seconds() / 86400.0,
            )

        run_starts = [
            _parse(r.get("started_at")) for r in state.runs
        ]
        run_starts = [t for t in run_starts if t]
        finding_times = [
            _parse(f.get("registered_at")) for f in findings
        ]
        finding_times = [t for t in finding_times if t]
        hours_to_finding = _hours_between(
            min(run_starts) if run_starts else None,
            min(finding_times) if finding_times else None,
        )

        predicted_findings: tuple[int, int] | None = None
        predicted_acceptance: tuple[float, float] | None = None
        if state.predicted_findings_range \
                and len(state.predicted_findings_range) == 2:
            predicted_findings = (
                int(state.predicted_findings_range[0]),
                int(state.predicted_findings_range[1]),
            )
        if state.predicted_acceptance_range \
                and len(state.predicted_acceptance_range) == 2:
            predicted_acceptance = (
                float(state.predicted_acceptance_range[0]),
                float(state.predicted_acceptance_range[1]),
            )

        predictions_accurate: dict[str, bool] = {}
        if predicted_findings is not None:
            predictions_accurate["findings"] = (
                predicted_findings[0] <= len(findings) <= predicted_findings[1]
            )
        if predicted_acceptance is not None:
            rate = (by_status["accepted"] / submitted) if submitted else 0.0
            predictions_accurate["acceptance"] = (
                predicted_acceptance[0] <= rate <= predicted_acceptance[1]
            )

        return VerdictMetrics(
            total_findings=len(findings),
            confirmed_findings=confirmed,
            false_positives=fps,
            inconclusive=inconclusive,
            fp_rate=round(fp_rate, 6),
            submitted=submitted,
            accepted=by_status["accepted"],
            rejected=by_status["rejected"],
            duplicates=by_status["duplicate"],
            under_review=by_status["under_review"],
            acceptance_rate=round(
                by_status["accepted"] / submitted if submitted else 0.0, 6
            ),
            time_to_first_finding_hours=(
                round(hours_to_finding, 4)
                if hours_to_finding is not None else None
            ),
            time_to_first_accepted_days=(
                round(days_to_accepted, 4)
                if days_to_accepted is not None else None
            ),
            predicted_findings_range=predicted_findings,
            predicted_acceptance_range=predicted_acceptance,
            predictions_accurate=predictions_accurate,
        )

    @staticmethod
    def final_verdict(metrics: VerdictMetrics) -> tuple[str, str]:
        """The decision table. Deterministic: same metrics, same outcome."""
        if metrics.accepted >= 3:
            return ("GO", "3+ accepted findings — tool is validated")
        if metrics.accepted == 2:
            return ("GO_CAUTIOUS",
                    "2 accepted — validated but improve quality")
        if metrics.accepted == 1 and metrics.under_review >= 2:
            return ("IMPROVE", "Insufficient signal — wait for more data")
        if metrics.accepted == 1:
            return ("IMPROVE", "1 accepted — focus on core quality")
        if metrics.duplicates >= 3:
            return ("IMPROVE", "Too many duplicates — fix timing/intel")
        return ("NO-GO", "0 accepted — core needs redesign")

    def generate_report(self, metrics: VerdictMetrics,
                        state: VerdictState | None = None) -> str:
        outcome, reasoning = self.final_verdict(metrics)
        lines = [
            "# Verdict Metrics Report",
            "",
            "## Findings",
            f"- total: {metrics.total_findings}",
            f"- confirmed: {metrics.confirmed_findings}",
            f"- false positives: {metrics.false_positives}",
            f"- inconclusive: {metrics.inconclusive}",
            f"- FP rate: {metrics.fp_rate:.1%}",
            "",
            "## Submissions",
            f"- submitted: {metrics.submitted}",
            f"- accepted: {metrics.accepted}",
            f"- rejected: {metrics.rejected}",
            f"- duplicates: {metrics.duplicates}",
            f"- under review: {metrics.under_review}",
            f"- acceptance rate: {metrics.acceptance_rate:.1%}",
            "",
            "## Timing",
            f"- time to first finding: "
            f"{metrics.time_to_first_finding_hours} hours",
            f"- time to first acceptance: "
            f"{metrics.time_to_first_accepted_days} days",
            "",
            "## Pre-registration",
            f"- predicted findings range: {metrics.predicted_findings_range}",
            f"- predicted acceptance range: "
            f"{metrics.predicted_acceptance_range}",
            f"- predictions accurate: {metrics.predictions_accurate}",
            "",
            "## Final Verdict",
            f"**{outcome}** — {reasoning}",
        ]
        if state is not None and state.final_verdict:
            lines += ["",
                      f"(recorded outcome in state: "
                      f"{state.final_verdict.get('outcome')})"]
        return "\n".join(lines) + "\n"


__all__ = ["OUTCOMES", "VerdictCalculator", "VerdictMetrics"]
