"""TruthValidator — U-CAMPAIGN-15.

Checks a report's claims against the recorded phase results it claims
to describe. Inflated or deflated findings totals, outcome counts that
do not match the recorded statuses, and budget totals that do not
match the recorded spend are all flagged as issue strings. A
consistent report passes silently (empty list). The validator reads;
it never mutates its inputs and never raises on disagreement — it
reports it.
"""
from __future__ import annotations

from typing import Any

from webpent.campaign.executor.phase_runner import PhaseResult


class TruthValidator:
    """Validates report claims against the recorded results."""

    def validate(
        self,
        report: Any,
        phase_results: list[PhaseResult],
    ) -> list[str]:
        issues: list[str] = []

        recorded_findings = sum(
            len(result.findings) for result in phase_results)
        if report.findings_total != recorded_findings:
            issues.append(
                f"findings_total {report.findings_total} does not match "
                f"the recorded {recorded_findings}"
            )

        recorded_outcome: dict[str, int] = {}
        for result in phase_results:
            status_name = result.status.value
            recorded_outcome[status_name] = (
                recorded_outcome.get(status_name, 0) + 1)
        for claimed_status, claimed_count in report.outcome.items():
            recorded_count = recorded_outcome.get(claimed_status, 0)
            if claimed_count != recorded_count:
                issues.append(
                    f"outcome '{claimed_status}' claims {claimed_count} "
                    f"against the recorded {recorded_count}"
                )

        recorded_requests = sum(
            result.requests_used for result in phase_results)
        if report.budget_requests_used != recorded_requests:
            issues.append(
                f"budget_requests_used {report.budget_requests_used} does "
                f"not match the recorded {recorded_requests}"
            )

        return issues
