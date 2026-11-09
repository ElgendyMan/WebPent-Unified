"""UM-DR-30 Workstream F §8 — campaign-runtime coverage gap map.

The ``CoverageMap`` / ``CoverageGapDetector`` facades were zero-importer
orphans (UM-DR-29 qualification matrix: coverage_intelligence = UNIT_TESTED,
"Coverage Gap Map not produced by campaign runtime today"). This module
closes that wiring gap: a flag-gated LangGraph node that projects the REAL
final campaign state through the shared coverage ledger and returns an
explicit, bounded, advisory gap report on a declared state channel.

Why this is a recall lever: a campaign that cannot see where it did NOT
look cannot compensate for it. The gap report makes untested coverage
cells (not_scanned, blocked_by_precondition, policy_block,
infrastructure_failure, inconclusive, human_review_only,
missing-validator) explicit to the operator and to future replanning —
without touching a single confirmation rule (precision is preserved by
construction: the report contains no finding vocabulary at all).

Contract:

- Fail-closed: the builder wires the node only when
  ``enable_coverage_gap_report`` is on; the node itself re-checks the
  flag (double-gate, the stateful_discovery precedent).
- Fail-soft: any projection failure produces an error-shaped report —
  a campaign outcome is never affected by observability.
- Advisory only: the report never mutates findings, never gates
  promotion, never grants authority. The causal guard stays the sole
  confirmation authority.
- Bounded: gap entries are capped; the ledger projection is
  key/status-shaped by construction (no raw evidence, no credentials,
  no secrets).
- Last-write-wins channel semantics: the node is wired exactly once per
  campaign pass (REPORTER → COVERAGE_GAP_REPORT → REFLECTION).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

#: Stable LangGraph node name (also the state-channel key is
#: ``coverage_gap_report``; the node name carries the wire provenance).
COVERAGE_GAP_REPORT_NODE_NAME = "coverage_gap_report"

#: Hard cap on emitted gap entries — the observability surface must stay
#: readable; the projection itself remains bounded by the ledger.
_MAX_GAP_ENTRIES = 200

#: The ledger's open statuses (mirrored from CoverageGapDetector._OPEN so
#: the report is self-describing for operators reading raw state).
_OPEN_STATUSES = (
    "not_scanned",
    "blocked_by_precondition",
    "policy_block",
    "infrastructure_failure",
    "inconclusive",
    "human_review_only",
    "missing-validator",
)


def build_coverage_gap_report(state: dict[str, Any]) -> dict[str, Any]:
    """Project the campaign state into an explicit coverage gap report.

    Deterministic, read-only, network-free. Never raises: a projection
    failure yields an error-shaped report (fail-soft observability).
    """
    report: dict[str, Any] = {
        "generated_by": "coverage_gap_report",
        "window": "UM-DR-30",
        "open_statuses": list(_OPEN_STATUSES),
        "gap_count": 0,
        "gaps": [],
    }
    try:
        from webpent.coverage.coverage_map import CoverageMap
        from webpent.coverage.gap_detector import CoverageGapDetector

        coverage_map = CoverageMap()
        detector = CoverageGapDetector(coverage_map=coverage_map)

        projection = coverage_map.project(state)
        metrics = coverage_map.metrics(state)
        gaps = detector.detect(state)

        report["gaps"] = [dict(gap) for gap in gaps[:_MAX_GAP_ENTRIES]]
        report["gap_count"] = len(gaps)
        report["truncated"] = len(gaps) > _MAX_GAP_ENTRIES
        report["coverage_metrics"] = metrics
        report["projection_entries"] = len(
            projection.get("entries", [])
        ) if isinstance(projection, dict) else 0
        # Redaction note: the ledger projection is key/status-shaped by
        # construction; no raw evidence is copied into the report.
        report["status"] = "ok"
    except Exception as exc:  # noqa: BLE001 — observability must be fail-soft
        logger.warning("Coverage gap report failed closed to error shape: %s", exc)
        report["status"] = "error"
        report["reason"] = "the coverage projection failed closed"
    return report


def coverage_gap_report_node(state: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node — emit the advisory coverage gap report.

    Double-gated fail-closed: if the flag is off at runtime (a legacy
    checkpoint replay, a mid-campaign settings reload), the node is a
    no-op. The report is advisory data only — it never touches findings.
    """
    try:
        from webpent.config.settings import get_settings

        if not get_settings().enable_coverage_gap_report:
            return {}
    except Exception:  # noqa: BLE001 — settings failure = not enabled
        return {}
    return {"coverage_gap_report": build_coverage_gap_report(state)}


def wire_coverage_gap_report(
    graph: Any,
    *,
    after_node: str = "reporter",
    before_node: str = "reflection",
) -> None:
    """Add the coverage_gap_report node between ``after_node`` and
    ``before_node`` (production defaults: the builder's NODE_REPORTER /
    NODE_REFLECTION constants).

    Additive only — the existing after→before edge stays in place;
    LangGraph super-step semantics make ``before_node`` wait for both
    branches, so the gap report is computed after the reporter's document
    is sealed and lands on the declared state channel for the operator,
    the API, and future replanning to read. Mirrors the
    ``wire_family_execution`` precedent.
    """
    try:
        from langgraph.graph import END, START, StateGraph  # noqa: F401
    except Exception:
        return  # optional layer; the builder gates the call anyway
    graph.add_node(COVERAGE_GAP_REPORT_NODE_NAME, coverage_gap_report_node)
    graph.add_edge(after_node, COVERAGE_GAP_REPORT_NODE_NAME)
    graph.add_edge(COVERAGE_GAP_REPORT_NODE_NAME, before_node)


__all__ = [
    "COVERAGE_GAP_REPORT_NODE_NAME",
    "build_coverage_gap_report",
    "coverage_gap_report_node",
    "wire_coverage_gap_report",
]
