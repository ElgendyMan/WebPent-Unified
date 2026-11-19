"""Deterministic trust aggregation for human-reviewed findings."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

_ACCEPTED = {"accepted", "Tool-Confirmed", "tool-confirmed"}
_REJECTED = {"rejected", "false_positive", "duplicate"}
_UNCERTAIN = {"needs_more_evidence", "Needs Human Review", "Pending", "AI-Assessed"}


def _value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _source_key(item: Any) -> str:
    vuln_class = str(_value(item, "vuln_class", "unknown") or "unknown")
    tool_name = str(_value(item, "tool_name", "unknown") or "unknown")
    provenance = _value(item, "hint_provenance", []) or []
    if not isinstance(provenance, list):
        provenance = []
    allowed_sources = {
        "heuristic",
        "memory_pattern",
        "llm_intent",
        "policy_assumption",
    }
    source = next(
        (str(value) for value in provenance if str(value) in allowed_sources),
        "unknown",
    )
    return f"{vuln_class}|{tool_name}|{source}"


def build_trust_matrix(findings: Iterable[Any]) -> dict[str, Any]:
    """Build a report-safe matrix; no raw evidence or URLs are retained."""
    counters: dict[str, dict[str, int]] = defaultdict(lambda: {
        "accepted": 0,
        "rejected": 0,
        "uncertain": 0,
        "sample_count": 0,
    })
    for finding in findings:
        key = _source_key(finding)
        decision = str(_value(finding, "human_review_decision", "") or "")
        confidence = str(_value(finding, "confidence_level", "Pending") or "Pending")
        if decision in _ACCEPTED or confidence in _ACCEPTED:
            bucket = "accepted"
        elif decision in _REJECTED:
            bucket = "rejected"
        elif decision in _UNCERTAIN or not decision:
            bucket = "uncertain"
        else:
            bucket = "uncertain"
        counters[key][bucket] += 1
        counters[key]["sample_count"] += 1

    entries: dict[str, Any] = {}
    for key, counts in sorted(counters.items()):
        accepted = counts["accepted"]
        rejected = counts["rejected"]
        uncertain = counts["uncertain"]
        # Laplace smoothing keeps an unreviewed/small sample near neutral.
        denominator = accepted + rejected + uncertain + 2
        reliability = (accepted + 1.0 + 0.5 * uncertain) / denominator
        entries[key] = {
            **counts,
            "reliability": round(max(0.05, min(0.95, reliability)), 4),
            "confidence": "calibrated" if counts["sample_count"] >= 3 else "limited",
        }
    return {
        "schema_version": 1,
        "entries": entries,
        "sample_count": sum(item["sample_count"] for item in counters.values()),
        "policy": (
            "Human feedback calibrates trust only; it never authorizes "
            "execution or promotes findings."
        ),
    }


def trust_adjustment(matrix: dict[str, Any] | None, item: Any) -> float:
    """Return a small bounded adjustment for ranking/explanation only."""
    if not matrix:
        return 0.0
    key = _source_key(item)
    entry = (matrix.get("entries") or {}).get(key) or {}
    reliability = float(entry.get("reliability", 0.5))
    sample_count = int(entry.get("sample_count", 0))
    if sample_count < 3:
        return 0.0
    return round(max(-0.05, min(0.05, (reliability - 0.5) * 0.1)), 4)


__all__ = ["build_trust_matrix", "trust_adjustment"]
