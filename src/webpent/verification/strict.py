"""Strict validation layer — red-team 15-step plan execution.

Phase 1 (core logic honesty):
  * StrictCalibrationStore — validates values before saving (accuracy 0-1,
    positive counts). Never writes corrupt data.
  * StrictDriftMonitor — < N runs → explicit "insufficient_history" result,
    never divides by zero. Uses mean + stddev when available.
  * StrictAlternativeCheck — returns (executed, result, confidence, note)
    per check, never a bare True/False.

Phase 2 (robustness & honesty):
  * strict_load_rules — structured result: rules/loaded/ignored/errors/success.
  * validate_translation_keys — ensures every code-side reason has a
    translation; missing → explicit error, never silent KeyError.
  * StrictLogger — invalid level → defaults to ERROR + warning.
  * consistent_quality_summary — enforces total == confirmed+review+excluded,
    auto-corrects and logs inconsistency.

Phase 3 (structure):
  * validate_constants — ensures all used constants exist and are in range.
  * StrictReferenceData — checks reference values give distinct responses.
"""
from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, field
from typing import Any

from webpent.verification.robust import (
    CENTRAL_CONSTANTS, LOGGER, UNCERTAINTY_TRANSLATIONS, UnifiedLogger,
)


# ---------------------------------------------------------------------------
# Phase 1 — Strict calibration (step 1-3): validate before saving
# ---------------------------------------------------------------------------

class StrictCalibrationStore:
    """Never writes corrupt calibration data. Accuracy must be 0.0-1.0,
    counts must be positive ints."""

    def __init__(self, path: str = "data/calibration_history.json") -> None:
        self.path = path
        self.history: list[dict[str, Any]] = []

    def record_run(self, target: str, confirmed: int, total: int) -> tuple[bool, str]:
        if not isinstance(confirmed, int) or confirmed < 0:
            return False, "invalid_confirmed_count"
        if not isinstance(total, int) or total <= 0:
            return False, "invalid_total_count"
        if confirmed > total:
            return False, "confirmed_exceeds_total"
        accuracy = confirmed / total
        if not (0.0 <= accuracy <= 1.0):
            return False, "accuracy_out_of_range"
        self.history.append({"target": target, "confirmed": confirmed, "total": total,
                             "accuracy": round(accuracy, 3)})
        return True, "ok"

    def multiplier(self, target: str) -> float:
        relevant = [h for h in self.history if h["target"] == target]
        if not relevant:
            return 1.0
        avg = sum(h["accuracy"] for h in relevant[-5:]) / len(relevant[-5:])
        return round(max(0.5, min(1.2, avg + 0.2)), 2)


# ---------------------------------------------------------------------------
# Phase 1 — Strict drift (step 1-4): never divide by zero
# ---------------------------------------------------------------------------

class StrictDriftMonitor:
    """< N runs → explicit insufficient_history. Never divides by zero."""

    def __init__(self) -> None:
        self.history: list[float] = []

    def record_run(self, fp_rate: float) -> None:
        self.history.append(float(fp_rate))

    def alert(self, current_fp_rate: float) -> dict[str, Any]:
        n = CENTRAL_CONSTANTS["DRIFT_BASELINE_RUNS"]
        if len(self.history) < n:
            return {"drift_alert": False, "reason": f"insufficient_history_need_{n}_runs",
                    "available": len(self.history)}
        baseline = self.history[-n:]
        mean = sum(baseline) / n
        variance = sum((x - mean) ** 2 for x in baseline) / n
        stddev = math.sqrt(variance)
        threshold = CENTRAL_CONSTANTS["DRIFT_THRESHOLD_MULTIPLIER"]
        if mean > 0 and current_fp_rate > mean * threshold:
            return {"drift_alert": True, "reason": "fp_rate_spiked",
                    "baseline_mean": round(mean, 3), "baseline_stddev": round(stddev, 3),
                    "current": round(current_fp_rate, 3)}
        return {"drift_alert": False, "baseline_mean": round(mean, 3),
                "baseline_stddev": round(stddev, 3), "current": round(current_fp_rate, 3)}


# ---------------------------------------------------------------------------
# Phase 1 — Strict alternative checks (step 1-1): structured results
# ---------------------------------------------------------------------------

@dataclass
class AlternativeCheckResult:
    name: str
    executed: bool
    result: bool
    confidence: float
    note: str


class StrictAlternativeCheck:
    """Each check returns structured (executed, result, confidence, note).
    Never a bare constant. If a check cannot run, executed=False with note."""

    def check_rate_limit(self, recent_request_count: int) -> AlternativeCheckResult:
        if recent_request_count <= 0:
            return AlternativeCheckResult("rate_limit", executed=False, result=False,
                                           confidence=0.0, note="no_request_history_available")
        is_likely = recent_request_count > 10
        return AlternativeCheckResult("rate_limit", executed=True, result=is_likely,
                                      confidence=0.8 if is_likely else 0.9,
                                      note=f"recent_request_count={recent_request_count}")

    def check_transient(self, retries_succeeded: int | None) -> AlternativeCheckResult:
        if retries_succeeded is None:
            return AlternativeCheckResult("transient_error", executed=False, result=False,
                                           confidence=0.0, note="no_retry_data_available")
        return AlternativeCheckResult("transient_error", executed=True,
                                      result=retries_succeeded > 0,
                                      confidence=0.85,
                                      note=f"retries_succeeded={retries_succeeded}")


# ---------------------------------------------------------------------------
# Phase 2 — Structured safe load (step 2-1): never silent
# ---------------------------------------------------------------------------

def strict_load_rules(path: str) -> dict[str, Any]:
    """Returns structured result: rules/loaded_count/ignored_count/errors/success.
    Never silent — every problem is reported."""
    result: dict[str, Any] = {"rules": [], "loaded_count": 0, "ignored_count": 0,
                              "errors": [], "success": True}
    if not os.path.exists(path):
        result["success"] = False
        result["errors"].append(f"file_not_found: {path}")
        return result
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        result["success"] = False
        result["errors"].append(f"parse_error: {exc}")
        return result
    if not isinstance(data, list):
        result["success"] = False
        result["errors"].append("root_is_not_a_list")
        return result
    required = {"reason", "scope"}
    for i, item in enumerate(data):
        if isinstance(item, dict) and required.issubset(item.keys()):
            result["rules"].append({k: item[k] for k in ("reason", "scope", "pattern") if k in item})
            result["loaded_count"] += 1
        else:
            result["ignored_count"] += 1
            result["errors"].append(f"entry_{i}_malformed")
    if result["ignored_count"]:
        result["success"] = False
    return result


# ---------------------------------------------------------------------------
# Phase 2 — Translation key validation (step 2-2)
# ---------------------------------------------------------------------------

_KNOWN_REASONS = {"insufficient_data", "conflicting_evidence", "inconclusive_retest",
                  "partial_verification", "max_retries"}


def validate_translation_keys() -> tuple[bool, list[str]]:
    """Ensure every code-side reason has a translation. Returns (ok, missing)."""
    missing = [r for r in _KNOWN_REASONS if r not in UNCERTAINTY_TRANSLATIONS]
    return (len(missing) == 0, missing)


# ---------------------------------------------------------------------------
# Phase 2 — Strict logger (step 2-4)
# ---------------------------------------------------------------------------

class StrictLogger(UnifiedLogger):
    """Invalid level → defaults to ERROR + warning. Never silent."""

    def log(self, level: str, module: str, message: str) -> str:
        lvl = str(level or "").upper()
        if lvl not in self.LEVELS:
            entry = super().log("WARN", "logger", f"invalid_log_level: {level!r} defaulting to ERROR")
            self.entries.append(entry)
            lvl = "ERROR"
        return super().log(lvl, module, message)


# ---------------------------------------------------------------------------
# Phase 2 — Consistent quality summary (step 2-5)
# ---------------------------------------------------------------------------

def consistent_quality_summary(*, total: int, confirmed: int, needs_review: int,
                               excluded: int) -> dict[str, Any]:
    """Enforce total == confirmed + needs_review + excluded. Auto-correct and
    log inconsistency. Never returns inconsistent numbers."""
    computed = confirmed + needs_review + excluded
    if computed != total:
        LOGGER.warn("quality_summary",
                    f"inconsistent_counts: total={total} but sum={computed} — correcting total")
        total = computed
    return {"total_discoveries": total, "fully_confirmed": confirmed,
            "needs_manual_review": needs_review, "excluded_as_false_positive": excluded,
            "counts_consistent": True}


# ---------------------------------------------------------------------------
# Phase 3 — Constants validator (step 3-4)
# ---------------------------------------------------------------------------

def validate_constants() -> tuple[bool, list[str]]:
    """Ensure all required constants exist and are in valid range."""
    errors: list[str] = []
    required = {"MAX_RETRIES": (1, 10), "ACCEPTANCE_THRESHOLD": (0.0, 1.0),
                "CONFIDENCE_CONFIRMED": (0.0, 1.0), "DRIFT_THRESHOLD_MULTIPLIER": (1.0, 10.0)}
    for name, (lo, hi) in required.items():
        if name not in CENTRAL_CONSTANTS:
            errors.append(f"missing_constant: {name}")
            continue
        val = CENTRAL_CONSTANTS[name]
        if not (lo <= val <= hi):
            errors.append(f"constant_out_of_range: {name}={val} expected [{lo},{hi}]")
    return (len(errors) == 0, errors)


# ---------------------------------------------------------------------------
# Phase 3 — Strict reference data (step 2-3)
# ---------------------------------------------------------------------------

def strict_validate_reference_data(references: list[Any],
                                   responses: list[Any] | None = None) -> tuple[bool, str]:
    """Check reference values are distinct AND give distinct responses."""
    if not references:
        return False, "no_reference_data"
    if len(set(str(r) for r in references)) < len(references):
        return False, "duplicate_reference_values"
    if responses is not None and len(set(str(r) for r in responses)) < len(responses):
        return False, "reference_values_produce_identical_responses"
    return True, "ok"


__all__ = [
    "AlternativeCheckResult", "StrictAlternativeCheck", "StrictCalibrationStore",
    "StrictDriftMonitor", "StrictLogger", "consistent_quality_summary",
    "strict_load_rules", "strict_validate_reference_data",
    "validate_constants", "validate_translation_keys",
]
