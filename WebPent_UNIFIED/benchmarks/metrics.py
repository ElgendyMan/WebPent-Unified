"""Deterministic benchmark metrics for evidence-gated findings."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

_STATUS_ALIASES = {
    "tool-confirmed": "confirmed",
    "confirmed": "confirmed",
    "candidate": "candidate",
    "needs human review": "needs_human_review",
    "needs_human_review": "needs_human_review",
    "not scanned": "not_scanned",
    "not_scanned": "not_scanned",
    "inconclusive": "inconclusive",
}
_FAILURE_STATUSES = {"failed", "error", "timeout", "terminated", "tool_failed"}
_RECOVERY_STATUSES = {"recovered", "fallback", "alternative_action", "retried_successfully"}
_REVIEWER_CONFIRMED = {"confirmed", "tool-confirmed", "true", "yes", "agree", "agreed"}
_REVIEWER_REJECTED = {
    "rejected",
    "false",
    "no",
    "candidate",
    "unconfirmed",
    "not confirmed",
    "needs_human_review",
    "needs human review",
}


def _run_records(run: Mapping[str, Any], *names: str) -> list[Mapping[str, Any]]:
    for name in names:
        value = run.get(name)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, Mapping)]
    return []


def _run_status(item: Mapping[str, Any]) -> str:
    raw = str(item.get("status") or item.get("confidence_level") or "").strip().lower()
    return _STATUS_ALIASES.get(raw, raw)


def _is_verified_confirmation(item: Mapping[str, Any]) -> bool:
    return _run_status(item) == "confirmed" and is_confirmed_with_required_controls(item)


def _run_key(item: Mapping[str, Any]) -> str:
    explicit = str(
        item.get("canonical_key")
        or item.get("finding_key")
        or item.get("key")
        or item.get("id")
        or ""
    ).strip()
    if explicit:
        return explicit
    return "|".join(
        str(item.get(field) or "").strip()
        for field in ("vuln_class", "method", "url", "target_param")
    )


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _reviewer_verdict(value: Any) -> bool | None:
    """Normalize an explicit human verdict without inferring one from code."""
    if isinstance(value, bool):
        return value
    normalized = str(value or "").strip().lower()
    if normalized in _REVIEWER_CONFIRMED:
        return True
    if normalized in _REVIEWER_REJECTED:
        return False
    return None


def _human_agreement(
    reviewer_decisions: Mapping[str, Any] | None,
    findings: Iterable[Mapping[str, Any]],
) -> dict[str, Any] | None:
    """Compare explicit reviewer verdicts with strict agent verdicts.

    A reviewer payload is optional and is never synthesized from status, LLM
    output, ground truth, or proof fields. Unknown/invalid reviewer entries are
    ignored rather than treated as agreement.
    """
    if not reviewer_decisions:
        return None
    strict_keys = {
        _run_key(item)
        for item in findings
        if _run_key(item) and _is_verified_confirmation(item)
    }
    reviewed: list[tuple[str, bool]] = []
    for raw_key, raw_verdict in list(reviewer_decisions.items())[:256]:
        key = str(raw_key or "").strip()[:160]
        verdict = _reviewer_verdict(raw_verdict)
        if key and verdict is not None:
            reviewed.append((key, verdict))
    if not reviewed:
        return None
    agreed = sum((key in strict_keys) == verdict for key, verdict in reviewed)
    return {
        "reviewed_count": len(reviewed),
        "agreed_count": agreed,
        "agreement_rate": _ratio(agreed, len(reviewed)),
    }


def _cost_efficiency(
    *,
    strict_confirmed: int,
    requests: int,
    actions: int,
    cost_usd: float,
) -> dict[str, Any]:
    """Return bounded efficiency metrics with a strict-confirmation denominator."""
    if strict_confirmed <= 0:
        return {
            "requests_per_strict_confirmed": None,
            "actions_per_strict_confirmed": None,
            "cost_usd_per_strict_confirmed": None,
            "unavailable_reason": "no_strict_confirmed_findings",
        }
    return {
        "requests_per_strict_confirmed": round(requests / strict_confirmed, 6),
        "actions_per_strict_confirmed": round(actions / strict_confirmed, 6),
        "cost_usd_per_strict_confirmed": round(cost_usd / strict_confirmed, 6),
        "unavailable_reason": None,
    }


def summarize_run(
    run: Mapping[str, Any],
    *,
    ground_truth: Iterable[Mapping[str, Any]] = (),
    reviewer_decisions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Summarize one captured artifact bundle without executing anything."""
    findings = _run_records(run, "findings")
    confirmed = [item for item in findings if _is_verified_confirmation(item)]
    confirmed_unverified = sum(
        _run_status(item) == "confirmed" and not _is_verified_confirmation(item)
        for item in findings
    )
    confirmed_keys = {_run_key(item) for item in confirmed if _run_key(item)}
    truth_keys = {_run_key(item) for item in ground_truth if _run_key(item)}
    surfaces = _run_records(run, "discovered", "surface", "observations")
    events = _run_records(run, "tool_events", "actions")
    failures = [
        item
        for item in events
        if bool(item.get("failed"))
        or str(item.get("status") or "").strip().lower() in _FAILURE_STATUSES
    ]
    recovered = [
        item
        for item in events
        if bool(item.get("recovered"))
        or str(item.get("recovery_status") or "").strip().lower() in _RECOVERY_STATUSES
    ]
    proof_count = sum(
        bool(item.get("proof_bundle") or item.get("evidence_bundle")) for item in confirmed
    )
    replay_count = sum(
        bool(item.get("replay_success"))
        or bool(
            isinstance(item.get("proof_bundle"), Mapping)
            and isinstance(item["proof_bundle"].get("replay"), Mapping)
            and item["proof_bundle"]["replay"].get("reproducible") is True
        )
        for item in confirmed
    )
    strict_confirmed = len(confirmed_keys)
    action_count = max(0, int(run.get("actions_count") or len(events)))
    request_count = max(0, int(run.get("requests") or 0))
    cost_usd = max(0.0, float(run.get("cost_usd") or 0.0))
    surface_keys = {
        str(item.get("url") or item.get("endpoint") or item.get("path") or "").strip()
        for item in surfaces
    }
    duplicate_count = len([_run_key(item) for item in findings]) - len(
        {_run_key(item) for item in findings if _run_key(item)}
    )
    result: dict[str, Any] = {
        "case_id": str(run.get("case_id") or run.get("run_id") or "unnamed"),
        "comparison_group": str(run.get("comparison_group") or ""),
        "confirmed": len(confirmed),
        "strict_confirmed": strict_confirmed,
        "confirmed_unverified": confirmed_unverified,
        "candidates": sum(_run_status(item) == "candidate" for item in findings),
        "needs_human_review": sum(_run_status(item) == "needs_human_review" for item in findings),
        "not_scanned": sum(_run_status(item) == "not_scanned" for item in findings),
        "unique_endpoints": len(surface_keys - {""}),
        "proof_bundle_coverage": _ratio(proof_count, len(confirmed)),
        "replay_success_rate": _ratio(replay_count, len(confirmed)),
        "precision": _ratio(len(confirmed_keys & truth_keys), len(confirmed_keys))
        if truth_keys
        else None,
        "recall": _ratio(len(confirmed_keys & truth_keys), len(truth_keys)) if truth_keys else None,
        "tool_failures": len(failures),
        "recovery_rate": _ratio(len(recovered), len(failures)) if failures else 1.0,
        "duplicates": max(0, duplicate_count),
        "requests": request_count,
        "actions": action_count,
        "duration_seconds": float(run.get("duration_seconds") or 0.0),
        "cost_usd": cost_usd,
        "scope_violations": int(run.get("scope_violations") or 0),
        "human_agreement": _human_agreement(reviewer_decisions, findings),
        "cost_efficiency": _cost_efficiency(
            strict_confirmed=strict_confirmed,
            requests=request_count,
            actions=action_count,
            cost_usd=cost_usd,
        ),
        "metric_assumptions": [
            "strict_confirmed requires explicit confirmed status, causal signal, "
            "completed negative control, and sealed proof bundle",
            "human_agreement uses only separately supplied reviewer decisions",
            "cost_efficiency denominators are unique strict_confirmed finding keys",
        ],
    }
    if truth_keys:
        result.update(
            {
                "true_positives": len(confirmed_keys & truth_keys),
                "false_positives": len(confirmed_keys - truth_keys),
                "ground_truth_positive_count": len(truth_keys),
            }
        )
    return result


def compare_runs(
    runs: Iterable[Mapping[str, Any]],
    *,
    ground_truth: Iterable[Mapping[str, Any]] = (),
    reviewer_decisions: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare offline captures and measure repeatability only when replicated."""
    run_list = list(runs)
    truth = list(ground_truth)
    summaries = [
        summarize_run(
            run,
            ground_truth=truth,
            reviewer_decisions=(reviewer_decisions or {}).get(
                str(run.get("case_id") or run.get("run_id") or "")
            ),
        )
        for run in run_list
    ]
    groups: dict[str, list[set[str]]] = {}
    for run in run_list:
        group = str(run.get("comparison_group") or "").strip()
        if group:
            groups.setdefault(group, []).append(
                {
                    _run_key(item)
                    for item in _run_records(run, "findings")
                    if _is_verified_confirmation(item) and _run_key(item)
                }
            )
    repeatability: dict[str, float | None] = {}
    for group, key_sets in groups.items():
        if len(key_sets) < 2:
            repeatability[group] = None
            continue
        union = set().union(*key_sets)
        intersection = set.intersection(*key_sets)
        repeatability[group] = _ratio(len(intersection), len(union))
    baseline = next(
        (
            summary
            for run, summary in zip(run_list, summaries, strict=True)
            if run.get("is_baseline") is True
        ),
        None,
    )
    deltas: list[dict[str, Any]] = []
    if baseline is not None:
        for summary in summaries:
            if summary is baseline:
                continue
            deltas.append(
                {
                    "case_id": summary["case_id"],
                    "confirmed_delta": summary["confirmed"] - baseline["confirmed"],
                    "unique_endpoints_delta": summary["unique_endpoints"]
                    - baseline["unique_endpoints"],
                    "tool_failures_delta": summary["tool_failures"] - baseline["tool_failures"],
                    "duplicates_delta": summary["duplicates"] - baseline["duplicates"],
                }
            )
    return {"runs": summaries, "repeatability": repeatability, "deltas_vs_baseline": deltas}




@dataclass(frozen=True)
class BenchmarkMetrics:
    """Precision/recall metrics over canonical expected and observed keys."""

    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)

    def as_dict(self) -> dict[str, Any]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 6),
            "recall": round(self.recall, 6),
            "f1": round(self.f1, 6),
        }


def finding_key(item: Mapping[str, Any]) -> str:
    """Return a stable benchmark key without using title text as identity."""
    return str(item.get("key") or item.get("finding_key") or item.get("id") or "").strip()


def is_confirmed_with_required_controls(item: Mapping[str, Any]) -> bool:
    """Accept only an explicit confirmed finding with all evidence gates closed."""
    status = str(item.get("status") or item.get("confidence_level") or "").lower()
    return (
        status in {"confirmed", "tool-confirmed"}
        and bool(item.get("causal_signal"))
        and bool(item.get("negative_control_complete"))
        and bool(item.get("proof_bundle_sealed"))
    )


def compute_metrics(
    expected: Iterable[Mapping[str, Any]],
    observed: Iterable[Mapping[str, Any]],
    *,
    confirmed_only: bool = True,
) -> BenchmarkMetrics:
    """Compute set metrics over stable keys; duplicates do not inflate recall."""
    expected_keys = {finding_key(item) for item in expected if finding_key(item)}
    observed_keys = {
        finding_key(item)
        for item in observed
        if finding_key(item)
        and (not confirmed_only or is_confirmed_with_required_controls(item))
    }
    return BenchmarkMetrics(
        true_positives=len(expected_keys & observed_keys),
        false_positives=len(observed_keys - expected_keys),
        false_negatives=len(expected_keys - observed_keys),
    )


__all__ = [
    "BenchmarkMetrics",
    "compute_metrics",
    "finding_key",
    "is_confirmed_with_required_controls",
    "summarize_run",
    "compare_runs",
]
