"""Deterministic detection metrics for DCVU case evaluations."""

from __future__ import annotations

from collections import defaultdict

from .contracts import CaseEvaluation, MetricResult, Verdict


def compute_metrics(evaluations: tuple[CaseEvaluation, ...]) -> tuple[MetricResult, ...]:
    """Compute metrics only from accepted, proof-replayable evaluations."""
    grouped: dict[str, list[CaseEvaluation]] = defaultdict(list)
    for evaluation in evaluations:
        grouped[evaluation.ground_truth.case.target_id].append(evaluation)
    results: list[MetricResult] = []
    for target_id, items in sorted(grouped.items()):
        scored = [
            item
            for item in items
            if item.ground_truth.case.disposition.value == "accepted"
            and item.proof_complete
            and item.replay_verified
            and len(item.observations) == 3
        ]
        tp = sum(item.verdict is Verdict.TRUE_POSITIVE for item in scored)
        fp = sum(item.verdict is Verdict.FALSE_POSITIVE for item in scored)
        fn = sum(item.verdict is Verdict.FALSE_NEGATIVE for item in scored)
        tn = sum(item.verdict is Verdict.TRUE_NEGATIVE for item in scored)
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = (
            (2 * precision * recall / (precision + recall))
            if precision is not None and recall is not None and precision + recall
            else None
        )
        positive_truth = {
            item.ground_truth.case.vulnerability_class
            for item in scored
            if item.ground_truth.exists
        }
        detected_classes = {
            item.ground_truth.case.vulnerability_class
            for item in scored
            if item.verdict is Verdict.TRUE_POSITIVE
        }
        proof_completeness = (
            sum(item.proof_complete and item.replay_verified for item in items) / len(items)
            if items
            else None
        )
        results.append(
            MetricResult(
                target_id=target_id,
                attempted_cases=len(items),
                scored_cases=len(scored),
                true_positive=tp,
                false_positive=fp,
                false_negative=fn,
                true_negative=tn,
                precision=precision,
                recall=recall,
                f1=f1,
                class_coverage=(len(detected_classes) / len(positive_truth))
                if positive_truth
                else None,
                proof_completeness=proof_completeness,
                scoring_eligible=bool(scored) and len(scored) == len(items),
                notes=("fixture_backed_offline_metrics", "not_official_qualification"),
            )
        )
    return tuple(results)


def attach_metrics(run):
    """Return the run after attaching metrics; governance remains fail-closed."""
    run.metrics = list(compute_metrics(tuple(run.evaluations)))
    run.validate()
    return run
