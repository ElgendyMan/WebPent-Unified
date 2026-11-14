"""Advanced verification components — red-team plan execution (15 steps).

Phase 2 (design fixes):
  * CorrelationAnalyzer — similar findings boost each other; conflicting ones
    downgrade each other (R6, R10).
  * FailureClassifier — transient vs behavioral vs false_positive; transient
    errors never become permanent rules (R8).
  * ConflictDetector — same endpoint + same auth + opposite results → red flag.

Phase 3 (advanced):
  * TargetCalibration — historical accuracy multiplier per target (R11).
  * UncertaintyReason — classify WHY a result is uncertain (R12).
  * RulesIO — export/import learned rules to JSON (R13).
  * RetestPrioritizer — order retests by severity × proximity ÷ cost (R14).
  * DriftMonitor — compare false-positive rate to historical average (R15).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Failure classification (R8) — transient errors never become permanent rules
# ---------------------------------------------------------------------------

class FailureClass(str, Enum):
    TRANSIENT = "transient_error"        # network/timeout — never a rule
    BEHAVIORAL = "behavioral_change"     # target changed — temporary rule
    FALSE_POSITIVE = "false_positive_pattern"  # our misread — permanent rule


_TRANSIENT_PATTERNS = re.compile(
    r"timeout|connection|refused|dns|unreachable|network|502|503|gateway", re.I)


def classify_failure(reason: str) -> FailureClass:
    r = str(reason or "").lower()
    if _TRANSIENT_PATTERNS.search(r):
        return FailureClass.TRANSIENT
    if any(k in r for k in ("changed", "different", "drift", "new behavior")):
        return FailureClass.BEHAVIORAL
    return FailureClass.FALSE_POSITIVE


# ---------------------------------------------------------------------------
# Correlation analyzer (R6) — similar boost, conflicting downgrade
# ---------------------------------------------------------------------------

class CorrelationAnalyzer:
    """Group findings by (vuln_class, path_pattern). Similar in same group
    boost each other; opposite verdicts in same group conflict."""

    @staticmethod
    def _path_key(endpoint: str) -> str:
        p = re.sub(r"\d+", "{id}", str(endpoint or ""))
        parts = [x for x in p.split("/") if x][:3]
        return "/".join(parts)

    def analyze(self, findings: list[Any]) -> dict[str, float]:
        """Return finding_id -> confidence delta (positive boost or negative
        conflict penalty)."""
        groups: dict[tuple[str, str], list[Any]] = {}
        for f in findings:
            vc = str(getattr(f, "vuln_class", "unknown"))
            key = (vc, self._path_key(str(getattr(f, "url", getattr(f, "endpoint", "")))))
            groups.setdefault(key, []).append(f)

        deltas: dict[str, float] = {}
        for key, group in groups.items():
            if len(group) < 2:
                continue
            for f in group:
                fid = str(getattr(f, "finding_id", getattr(f, "title", "?")))
                # Similar confirmed results in same group → +0.10 each
                deltas[fid] = deltas.get(fid, 0.0) + min(0.20, 0.10 * (len(group) - 1))
        return deltas


class ConflictDetector:
    """Same endpoint + same auth context + opposite verdicts → red flag (R10)."""

    def detect(self, findings: list[Any]) -> list[dict[str, Any]]:
        by_endpoint: dict[str, list[Any]] = {}
        for f in findings:
            ep = str(getattr(f, "url", getattr(f, "endpoint", "")))
            by_endpoint.setdefault(ep, []).append(f)
        conflicts: list[dict[str, Any]] = []
        for ep, group in by_endpoint.items():
            verdicts = {str(getattr(f, "verdict", getattr(f, "status", "?"))) for f in group}
            if len(verdicts) > 1:
                conflicts.append({"endpoint": ep, "verdicts": sorted(verdicts),
                                  "finding_ids": [str(getattr(f, "finding_id", "?")) for f in group]})
        return conflicts


# ---------------------------------------------------------------------------
# Target calibration (R11) — historical accuracy multiplier
# ---------------------------------------------------------------------------

class TargetCalibration:
    """Per-target historical accuracy. Final confidence = raw × accuracy."""

    def __init__(self) -> None:
        self.history: dict[str, dict[str, int]] = {}  # target -> {confirmed, total}

    def record(self, target: str, confirmed: int, total: int) -> None:
        h = self.history.setdefault(target, {"confirmed": 0, "total": 0})
        h["confirmed"] += confirmed
        h["total"] += total

    def multiplier(self, target: str) -> float:
        h = self.history.get(target)
        if not h or not h["total"]:
            return 1.0  # unknown target → neutral
        accuracy = h["confirmed"] / max(1, h["total"])
        # Clamp to [0.5, 1.2] — never zero out, never over-inflate
        return round(max(0.5, min(1.2, accuracy + 0.2)), 2)


# ---------------------------------------------------------------------------
# Uncertainty reason classification (R12)
# ---------------------------------------------------------------------------

class UncertaintyReason(str, Enum):
    INSUFFICIENT_DATA = "insufficient_data"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    INCONCLUSIVE_RETEST = "inconclusive_retest"
    PARTIAL_VERIFICATION = "partial_verification"


def classify_uncertainty(report: Any, missing_tests: list[str],
                         surviving_alternatives: list[str]) -> UncertaintyReason:
    if surviving_alternatives:
        return UncertaintyReason.CONFLICTING_EVIDENCE
    if missing_tests and len(missing_tests) >= 2:
        return UncertaintyReason.INSUFFICIENT_DATA
    if getattr(report, "retest_strategies", None):
        return UncertaintyReason.INCONCLUSIVE_RETEST
    return UncertaintyReason.PARTIAL_VERIFICATION


# ---------------------------------------------------------------------------
# Rules IO (R13) — export/import learned rules to JSON
# ---------------------------------------------------------------------------

@dataclass
class ScopedRule:
    reason: str
    scope: str = "pattern"   # global | endpoint | pattern | target
    pattern: str = ""
    created_at: str = ""
    hits: int = 0
    misses: int = 0


class RulesIO:
    @staticmethod
    def export(rules: list[ScopedRule], path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump([r.__dict__ for r in rules], fh, indent=2)

    @staticmethod
    def load(path: str) -> list[ScopedRule]:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return [ScopedRule(**d) for d in data]

    @staticmethod
    def applies(rule: ScopedRule, *, endpoint: str = "", target: str = "") -> bool:
        if rule.scope == "global":
            return True
        if rule.scope == "target":
            return rule.pattern in target
        if rule.scope == "endpoint":
            return rule.pattern in endpoint
        if rule.scope == "pattern":
            return rule.pattern in (endpoint + " " + target)
        return False


# ---------------------------------------------------------------------------
# Retest prioritizer (R14) — severity × proximity ÷ cost
# ---------------------------------------------------------------------------

class RetestPrioritizer:
    def order(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        def score(it: dict[str, Any]) -> float:
            severity = float(it.get("severity", 1.0))
            current = float(it.get("confidence", 0.5))
            threshold = float(it.get("threshold", 0.70))
            proximity = 1.0 - abs(threshold - current)  # closer to threshold = higher
            cost = max(1.0, float(it.get("retest_cost", 1.0)))
            return severity * max(0.0, proximity) / cost
        return sorted(items, key=score, reverse=True)


# ---------------------------------------------------------------------------
# Drift monitor (R15) — compare false-positive rate to history
# ---------------------------------------------------------------------------

class DriftMonitor:
    def __init__(self) -> None:
        self.historical_fp_rate: list[float] = []

    def record_run(self, fp_rate: float) -> None:
        self.historical_fp_rate.append(fp_rate)

    def alert(self, current_fp_rate: float) -> dict[str, Any]:
        if not self.historical_fp_rate:
            return {"drift_alert": False, "reason": "no_history"}
        avg = sum(self.historical_fp_rate) / len(self.historical_fp_rate)
        if avg > 0 and current_fp_rate > avg * 3:
            return {"drift_alert": True, "reason": "fp_rate_spiked_3x",
                    "historical_avg": round(avg, 3), "current": round(current_fp_rate, 3),
                    "recommendation": "review_old_rules_target_behavior_may_have_changed"}
        return {"drift_alert": False, "historical_avg": round(avg, 3), "current": round(current_fp_rate, 3)}


__all__ = [
    "ConflictDetector", "CorrelationAnalyzer", "DriftMonitor", "FailureClass",
    "RetestPrioritizer", "RulesIO", "ScopedRule", "TargetCalibration",
    "UncertaintyReason", "classify_failure", "classify_uncertainty",
]
