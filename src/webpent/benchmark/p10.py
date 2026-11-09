"""Strict, redacted P10 benchmark evaluation primitives.

This module is pure: it performs no network, browser, credential, or target I/O.
It evaluates caller-supplied summaries only after independent ground-truth
approval and isolated live-run metadata are present.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

_ALLOWED_MAPPING = {"approved"}
_ALLOWED_ORACLE = {"ready", "approved_oracle_pending_full_set_metrics"}


def _text(value: Any, limit: int = 160) -> str:
    return " ".join(str(value or "").split())[:limit]


def _ids(values: Any) -> frozenset[str]:
    if values is None or isinstance(values, (str, bytes)):
        return frozenset()
    try:
        items = values
        result = {_text(value) for value in items}
    except TypeError:
        return frozenset()
    return frozenset(value for value in result if value)


@dataclass(frozen=True)
class P10GroundTruth:
    case_id: str
    category: str
    expected: bool
    mapping_status: str
    oracle_status: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> P10GroundTruth:
        return cls(
            case_id=_text(value.get("case_id")),
            category=_text(value.get("category")),
            expected=bool(value.get("expected", False)),
            mapping_status=_text(value.get("mapping_status")),
            oracle_status=_text(value.get("oracle_status")),
        )


@dataclass(frozen=True)
class P10Run:
    run_id: str
    workspace_id: str
    artifact_namespace: str
    target_ref: str
    candidate_case_ids: frozenset[str]
    executed_case_ids: frozenset[str]
    proof_case_ids: frozenset[str]
    replay_case_ids: frozenset[str]
    target_unchanged: bool
    findings_are_live: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> P10Run:
        return cls(
            run_id=_text(value.get("run_id")),
            workspace_id=_text(value.get("workspace_id")),
            artifact_namespace=_text(value.get("artifact_namespace")),
            target_ref=_text(value.get("target_ref"), 320),
            candidate_case_ids=_ids(value.get("candidate_case_ids")),
            executed_case_ids=_ids(value.get("executed_case_ids")),
            proof_case_ids=_ids(value.get("proof_case_ids")),
            replay_case_ids=_ids(value.get("replay_case_ids")),
            target_unchanged=bool(value.get("target_unchanged", False)),
            findings_are_live=bool(value.get("findings_are_live", False)),
        )

    @property
    def confirmed_case_ids(self) -> frozenset[str]:
        return self.proof_case_ids & self.replay_case_ids


def _empty_metrics() -> dict[str, Any]:
    return {
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "precision": None,
        "recall": None,
        "case_coverage": None,
        "class_coverage": None,
        "false_positive_case_ids": [],
        "false_negative_case_ids": [],
    }


def evaluate_p10(
    ground_truth: Sequence[P10GroundTruth],
    runs: Sequence[P10Run],
    *,
    minimum_approved_cases: int = 10,
    minimum_approved_classes: int = 6,
    minimum_runs: int = 3,
) -> dict[str, Any]:
    """Evaluate strict P10 status from independent, already-redacted inputs."""
    reasons: list[str] = []
    case_by_id = {case.case_id: case for case in ground_truth if case.case_id}
    expected = {
        case_id: case
        for case_id, case in case_by_id.items()
        if case.expected
    }
    approved = {
        case_id: case
        for case_id, case in expected.items()
        if case.mapping_status in _ALLOWED_MAPPING
        and case.oracle_status in _ALLOWED_ORACLE
    }
    approved_classes = {case.category.lower() for case in approved.values() if case.category}
    partial_oracle_cases = {
        case_id
        for case_id, case in approved.items()
        if case.oracle_status == "approved_oracle_pending_full_set_metrics"
    }
    if len(approved) < minimum_approved_cases:
        reasons.append("approved_ground_truth_cases_below_minimum")
    if len(approved_classes) < minimum_approved_classes:
        reasons.append("approved_vulnerability_classes_below_minimum")
    if len(runs) < minimum_runs:
        reasons.append("minimum_isolated_runs_not_met")

    if any(not set(approved).issubset(run.executed_case_ids) for run in runs):
        reasons.append("approved_case_set_not_exercised_in_all_runs")

    run_ids = [run.run_id for run in runs]
    workspace_ids = [run.workspace_id for run in runs]
    namespaces = [run.artifact_namespace for run in runs]
    if not all(run_ids) or len(set(run_ids)) != len(run_ids):
        reasons.append("run_ids_not_unique")
    if not all(workspace_ids) or len(set(workspace_ids)) != len(workspace_ids):
        reasons.append("workspaces_not_isolated")
    if not all(namespaces) or len(set(namespaces)) != len(namespaces):
        reasons.append("artifact_namespaces_not_isolated")
    if not all(run.target_unchanged for run in runs):
        reasons.append("target_mutation_detected_or_unproven")
    if not all(run.findings_are_live for run in runs):
        reasons.append("live_findings_not_proven_for_all_runs")
    target_refs = {run.target_ref for run in runs if run.target_ref}
    if len(target_refs) != 1:
        reasons.append("target_ref_not_consistent")

    metrics = _empty_metrics()
    if not reasons:
        confirmed = {case_id for run in runs for case_id in run.confirmed_case_ids}
        true_positives = confirmed & set(approved)
        false_positives = confirmed - set(approved)
        false_negatives = set(approved) - confirmed
        tp = len(true_positives)
        fp = len(false_positives)
        fn = len(false_negatives)
        found_classes = {
            approved[case_id].category.lower()
            for case_id in true_positives
            if approved[case_id].category
        }
        metrics = {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
            "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
            "case_coverage": round(tp / len(approved), 4) if approved else 0.0,
            "class_coverage": (
                round(len(found_classes) / len(approved_classes), 4)
                if approved_classes
                else 0.0
            ),
            "false_positive_case_ids": sorted(false_positives),
            "false_negative_case_ids": sorted(false_negatives),
        }
    else:
        reasons.insert(0, "p10_metrics_withheld_until_all_gates_pass")

    return {
        "p10_passed": not reasons,
        "blocking_reasons": sorted(set(reasons)),
        "ground_truth_cases": len(expected),
        "approved_ground_truth_cases": len(approved),
        "approved_vulnerability_classes": len(approved_classes),
        "partial_oracle_approved_cases": len(partial_oracle_cases),
        "not_scored_expected_cases": len(expected) - len(approved),
        "run_count": len(runs),
        "metrics": metrics,
    }


__all__ = ["P10GroundTruth", "P10Run", "evaluate_p10"]
