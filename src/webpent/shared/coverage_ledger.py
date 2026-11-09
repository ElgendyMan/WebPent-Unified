"""Runtime coverage projection for campaign and proof outcomes.

This module is intentionally a projection only. It does not authorize actions,
execute requests, or promote findings. A campaign becomes ``tested`` only when
an executor/proof outcome records an explicit attempt; confirmation remains
owned by the proof engine and validator chain.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from webpent.models.evidence import redact_sensitive

_TERMINAL_STATUSES = {
    "tool_confirmed",
    "candidate",
    "human_review_only",
    "clean",
    "not_scanned",
    "blocked_by_precondition",
    "policy_block",
    "infrastructure_failure",
    "inconclusive",
}

#: UM-DR-31.1 R6/F20: producer-vocabulary raw statuses that the
#: projection deliberately reconciles onto "not_scanned" — the pinned
#: ``shared/campaigns.py`` spellings ("not_observed"/"tested") and the
#: fixture-pinned "tool_unconfirmed" (a claimed-but-unbacked tool status:
#: no backing proof outcome ⇒ the honest downgrade IS an open gap, the
#: pinned test_umdr30_coverage_gap_report contract). Anything else
#: unrecognized is projected as the explicit non-gap "unknown_status".
_RAW_LEDGER_STATUS_ALIASES = frozenset({"not_observed", "tested", "tool_unconfirmed"})


def _text(value: Any) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return clean[:200]


def _nonnegative_int(value: Any) -> int:
    try:
        return max(0, min(1_000_000, int(value or 0)))
    except (TypeError, ValueError):
        return 0


def _status_for_outcome(outcome: Mapping[str, Any]) -> str:
    raw = _text(outcome.get("status")).lower()
    if raw in {"confirmed", "tool_confirmed"}:
        return "tool_confirmed"
    if raw in {"candidate", "needs_human_review"}:
        return "candidate"
    if raw in {"human_review_only", "human-review-only", "manual_review_only"}:
        return "human_review_only"
    if raw in {"clean", "negative"}:
        return "clean"
    if raw in {"blocked_by_precondition", "blocked_by_scope"}:
        return "blocked_by_precondition"
    if raw in {"policy_block", "blocked_by_policy"}:
        return "policy_block"
    if raw in {"infrastructure_failure", "tool_unavailable"}:
        return "infrastructure_failure"
    if raw in {"inconclusive", "budget_exhausted", "executed", "ready", "stopped"}:
        return "inconclusive"
    return "not_scanned"


class CoverageIntelligence:
    """Bounded coverage intelligence facade; projection only, never authority."""

    def __init__(self, *, version: int = 1) -> None:
        self.version = max(1, min(10, int(version)))

    def project(self, state: Mapping[str, Any]) -> dict[str, Any]:
        projected = _project_coverage_ledger(state)
        projected["version"] = self.version
        projected["source"] = "coverage_intelligence_projection"
        return projected

    def gaps(self, state: Mapping[str, Any]) -> list[dict[str, Any]]:
        projection = self.project(state)
        return [
            entry
            for entry in projection.get("entries", [])
            if isinstance(entry, Mapping) and entry.get("status") in {
                "not_scanned",
                "blocked_by_precondition",
                "policy_block",
                "infrastructure_failure",
                "inconclusive",
                "human_review_only",
                # The projection deliberately preserves "missing-validator"
                # (instead of the not_scanned fallback) and tags those entries
                # with "deterministic-validator-unavailable"; omitting them
                # here would hide exactly the classes the coverage engine
                # exists to close (critique C2).
                "missing-validator",
            }
        ]

    def metrics(self, state: Mapping[str, Any]) -> dict[str, Any]:
        """Compute coverage metrics from explicit campaign outcomes only."""
        projection = self.project(state)
        entries = [entry for entry in projection.get("entries", []) if isinstance(entry, Mapping)]
        tested = [
            entry
            for entry in entries
            if entry.get("attempts", 0) > 0
            and entry.get("status") not in {"not_scanned", "inconclusive"}
        ]
        confirmed = [entry for entry in entries if entry.get("status") == "tool_confirmed"]
        blocked = [
            entry
            for entry in entries
            if entry.get("status")
            in {"blocked_by_precondition", "policy_block", "infrastructure_failure"}
        ]
        total = len(entries)
        return {
            "version": self.version,
            "campaign_count": total,
            "tested_count": len(tested),
            "confirmed_count": len(confirmed),
            "blocked_count": len(blocked),
            "gap_count": len(self.gaps(state)),
            "tested_ratio": round(len(tested) / total, 6) if total else 0.0,
            "confirmation_ratio": round(len(confirmed) / total, 6) if total else 0.0,
            "source": "explicit_campaign_outcomes",
        }


def _project_coverage_ledger(state: Mapping[str, Any]) -> dict[str, Any]:
    """Project explicit proof outcomes into a report-safe coverage ledger."""
    campaign_ledger = state.get("campaign_ledger") or {}
    raw_entries = campaign_ledger.get("entries", []) if isinstance(campaign_ledger, Mapping) else []
    outcomes = list(state.get("proof_outcomes") or [])
    outcomes.extend(state.get("campaign_task_outcomes") or [])
    by_campaign: dict[str, list[Mapping[str, Any]]] = {}
    for raw in outcomes:
        if not isinstance(raw, Mapping):
            continue
        key = _text(raw.get("campaign_key") or raw.get("vulnerability_class"))
        if key:
            by_campaign.setdefault(key, []).append(raw)

    entries: list[dict[str, Any]] = []
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, Mapping):
            continue
        key = _text(raw_entry.get("key"))
        if not key:
            continue
        attempts = by_campaign.get(key, [])
        latest = attempts[-1] if attempts else None
        raw_status = _text(raw_entry.get("status"))
        status = raw_status or "not_scanned"
        if latest is not None:
            status = _status_for_outcome(latest)
        gaps = list(raw_entry.get("gaps") or []) if isinstance(raw_entry, Mapping) else []
        if status not in _TERMINAL_STATUSES and status != "missing-validator":
            # UM-DR-31.1 R6/F20 fail-closed projection: only the
            # producer-vocabulary aliases ("not_observed"/"tested" — the
            # pinned ``campaigns.py`` spellings) reconcile to the
            # actionable "not_scanned". ANY other unrecognized status is
            # projected as the explicit, observable, NON-gap
            # "unknown_status" — never silently normalized into an
            # executable research opportunity.
            if status in _RAW_LEDGER_STATUS_ALIASES:
                status = "not_scanned"
            else:
                status = "unknown_status"
                gaps.append("unrecognized-status")
        if status == "not_scanned" and not attempts:
            gaps.append("no-executor-outcome")
        if status == "missing-validator":
            gaps.append("deterministic-validator-unavailable")
        if status == "human_review_only":
            gaps.append("human-review-only-validator")
        entry = {
            "id": int(raw_entry.get("id", len(entries) + 1) or len(entries) + 1),
            "key": key,
            "status": status,
            "attempts": len(attempts),
            "evidence_complete": bool(latest.get("evidence_complete")) if latest else False,
            "proof_action_id": _text(latest.get("action_id")) if latest else None,
            "task_id": _text(latest.get("task_id")) if latest else None,
            "reason": _text(latest.get("note")) if latest else None,
            "gaps": sorted({_text(gap) for gap in gaps if gap}),
        }
        entries.append(entry)

    summary: dict[str, int] = {}
    for entry in entries:
        status = str(entry["status"])
        summary[status] = summary.get(status, 0) + 1
    imported_observations = [
        item
        for item in state.get("autopentestx_observations") or []
        if isinstance(item, Mapping)
    ]
    imported_sources = sorted(
        {
            _text(item.get("tool_name"))
            for item in imported_observations
            if _text(item.get("tool_name"))
        }
    )
    research_gaps = [
        item for item in state.get("knowledge_gaps") or [] if isinstance(item, Mapping)
    ]
    research_actions = [
        item
        for item in state.get("smart_information_actions") or []
        if isinstance(item, Mapping)
    ]
    research_session = state.get("research_session") or {}
    if not isinstance(research_session, Mapping):
        research_session = {}
    session_actions = [
        item
        for item in research_session.get("next_best_actions") or []
        if isinstance(item, Mapping)
    ]
    target_understanding = state.get("target_understanding") or {}
    if not isinstance(target_understanding, Mapping):
        target_understanding = {}
    raw_target_gaps = target_understanding.get("coverage_gaps")
    target_gap_count = len(raw_target_gaps) if isinstance(raw_target_gaps, list) else 0
    target_dimensions = {
        "endpoint_count": _nonnegative_int(target_understanding.get("endpoint_count")),
        "form_count": _nonnegative_int(target_understanding.get("form_count")),
        "identity_count": _nonnegative_int(target_understanding.get("identity_count")),
        "object_candidate_count": _nonnegative_int(
            target_understanding.get("object_candidate_count")
        ),
        "workflow_candidate_count": _nonnegative_int(
            target_understanding.get("workflow_candidate_count")
        ),
        "coverage_gap_count": target_gap_count,
    }
    return {
        "version": 1,
        "source": "proof_engine_projection",
        "entries": entries,
        "summary": summary,
        "attempt_count": sum(int(entry["attempts"]) for entry in entries),
        "research_coverage": {
            "open_gap_count": sum(
                1 for gap in research_gaps if _text(gap.get("status")).lower() != "resolved"
            ),
            "gap_count": len(research_gaps),
            "planned_information_action_count": len(research_actions),
            "executed_information_action_count": sum(
                1
                for item in session_actions
                if _text(item.get("outcome")).lower() not in {"", "planned"}
            ),
            "positive_evidence_count": len(research_session.get("positive_evidence_ledger") or []),
            "negative_evidence_count": len(research_session.get("negative_evidence_ledger") or []),
            "failed_path_count": len(research_session.get("failed_paths") or []),
            "promising_path_count": len(research_session.get("promising_paths") or []),
            "decision_trace_count": len(state.get("research_decision_trace") or []),
            "gap_ids": sorted(
                {
                    _text(gap.get("gap_id"))
                    for gap in research_gaps
                    if _text(gap.get("gap_id"))
                }
            ),
            "target_understanding": target_dimensions,
            "client_id": _text(research_session.get("client_id")),
            "engagement_id": _text(research_session.get("engagement_id")),
            "source": "research_intelligence_projection",
        },
        "imported_observations": {
            "count": len(imported_observations),
            "sources": imported_sources,
            "confirmation_authority": "webpent_validator",
            "counts_as_attempt": False,
        },
    }


def project_coverage_ledger(state: Mapping[str, Any]) -> dict[str, Any]:
    """Backward-compatible projection entrypoint."""
    return CoverageIntelligence().project(state)


__all__ = ["CoverageIntelligence", "project_coverage_ledger"]
