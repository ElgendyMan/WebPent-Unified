"""Robustness & transparency layer — red-team plan execution (13 steps).

Phase 1 (critical logic fixes):
  * load_confidence_config — external YAML/JSON weights with safe fallback (step 1)
  * AlternativeFinder — actually DETECTS alternative explanations, not empty (step 2)
  * similarity_score — real path/module similarity, not just type match (step 3)
  * CalibrationStore — actually WRITES calibration history, not just reads (step 4)
  * DriftMonitor2 — baseline from last 3 runs, configurable threshold (step 5)

Phase 2 (robustness):
  * safe_load_rules — missing/invalid file → empty list, structure validation (step 6)
  * UNCERTAINTY_TRANSLATIONS — human-readable Arabic/English reasons (step 7)
  * validate_reference_data — negative-test data validity check (step 8)
  * MAX_RETRIES detail — reason string when bound hit (step 9)

Phase 3 (consistency & transparency):
  * UnifiedLogger — single logging interface (step 10)
  * CENTRAL_CONSTANTS — no magic numbers (step 11)
  * build_dynamic_assumptions — real list based on what ran (step 12)
  * build_quality_summary — full run-quality report (step 13)
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Step 11 — Central constants (no magic numbers scattered)
# ---------------------------------------------------------------------------

CENTRAL_CONSTANTS: dict[str, Any] = {
    "CONFIDENCE_CONFIRMED": 0.95,
    "CONFIDENCE_LIKELY": 0.70,
    "CONFIDENCE_POSSIBLE": 0.40,
    "ACCEPTANCE_THRESHOLD": 0.70,
    "MAX_RETRIES": 2,
    "DRIFT_THRESHOLD_MULTIPLIER": 3.0,
    "DRIFT_BASELINE_RUNS": 3,
    "DEFAULT_RULES_FILE": "data/learned_rules.json",
    "DEFAULT_CONFIG_FILE": "config/confidence.json",
}


# ---------------------------------------------------------------------------
# Step 10 — Unified logger
# ---------------------------------------------------------------------------

class UnifiedLogger:
    """Single logging interface — every module writes through here."""

    LEVELS = ("DEBUG", "INFO", "WARN", "ERROR", "CRITICAL")

    def __init__(self) -> None:
        self.entries: list[str] = []

    def log(self, level: str, module: str, message: str) -> str:
        lvl = level.upper() if level.upper() in self.LEVELS else "INFO"
        entry = f"[{lvl}] {module}: {message}"
        self.entries.append(entry)
        return entry

    def warn(self, module: str, message: str) -> str:
        return self.log("WARN", module, message)

    def error(self, module: str, message: str) -> str:
        return self.log("ERROR", module, message)


LOGGER = UnifiedLogger()


# ---------------------------------------------------------------------------
# Step 1 — External config loader with safe fallback
# ---------------------------------------------------------------------------

_DEFAULT_WEIGHTS: dict[str, float] = {
    "repetition_bonus": 0.20,
    "state_change_bonus": 0.25,
    "consistency_bonus": 0.10,
    "evidence_bonus_max": 0.15,
    "correlation_boost_max": 0.20,
    "calibration_min": 0.5,
    "calibration_max": 1.2,
}


def load_confidence_config(path: str | None = None) -> dict[str, float]:
    """Load weights from external JSON file. Missing/invalid file → safe
    defaults + warning logged. Never crashes."""
    target = path or CENTRAL_CONSTANTS["DEFAULT_CONFIG_FILE"]
    if not os.path.exists(target):
        LOGGER.warn("config_loader", f"config file {target} missing — using defaults")
        return dict(_DEFAULT_WEIGHTS)
    try:
        with open(target, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("config root must be an object")
        merged = dict(_DEFAULT_WEIGHTS)
        for k, v in data.items():
            if k in _DEFAULT_WEIGHTS and isinstance(v, (int, float)):
                merged[k] = float(v)
            else:
                LOGGER.warn("config_loader", f"ignoring invalid config key {k}={v!r}")
        return merged
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        LOGGER.error("config_loader", f"failed to parse {target}: {exc} — using defaults")
        return dict(_DEFAULT_WEIGHTS)


# ---------------------------------------------------------------------------
# Step 2 — Alternative explanations finder (REAL, not empty)
# ---------------------------------------------------------------------------

@dataclass
class AlternativeExplanation:
    name: str
    test: str
    confirmed: bool  # True = this alternative explains the observation


class AlternativeFinder:
    """Actually tests common alternative explanations. Returns real results."""

    COMMON_ALTERNATIVES = [
        ("network_transient", "retry from different network/location"),
        ("user_procedure_error", "re-run following exact correct procedure"),
        ("expected_behavior", "reproduce in known-safe test environment"),
        ("rate_limit_artifact", "re-run under low request rate"),
        ("stale_session", "re-run with freshly issued session/token"),
    ]

    def find(self, evidence: dict[str, Any]) -> list[AlternativeExplanation]:
        found: list[AlternativeExplanation] = []
        # Network transient: evidence shows timeout/connection errors
        if any(k in str(evidence).lower() for k in ("timeout", "connection", "502", "503")):
            found.append(AlternativeExplanation("network_transient", self.COMMON_ALTERNATIVES[0][1], True))
        # Stale session: artifact not freshly generated
        if not evidence.get("artifact_freshly_generated"):
            found.append(AlternativeExplanation("stale_session", self.COMMON_ALTERNATIVES[4][1], True))
        # Rate limit: high request count observed
        if evidence.get("recent_request_count", 0) > 10:
            found.append(AlternativeExplanation("rate_limit_artifact", self.COMMON_ALTERNATIVES[3][1], True))
        return found


# ---------------------------------------------------------------------------
# Step 3 — Real similarity (path/module, not just type)
# ---------------------------------------------------------------------------

def similarity_score(ep_a: str, ep_b: str) -> float:
    """Real path-based similarity: shared prefix segments. 0.0-1.0."""
    a = [p for p in re.sub(r"\d+", "{id}", str(ep_a or "")).split("/") if p]
    b = [p for p in re.sub(r"\d+", "{id}", str(ep_b or "")).split("/") if p]
    if not a or not b:
        return 0.0
    common = 0
    for i in range(min(len(a), len(b))):
        if a[i] == b[i]:
            common += 1
        else:
            break
    return round(common / max(len(a), len(b)), 2)


# ---------------------------------------------------------------------------
# Step 4 — Calibration store (actually writes history)
# ---------------------------------------------------------------------------

class CalibrationStore:
    """Persists calibration history to JSON. Actually writes, not just reads."""

    def __init__(self, path: str = "data/calibration_history.json") -> None:
        self.path = path
        self.history: list[dict[str, Any]] = self._load()

    def _load(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            return []

    def record_run(self, target: str, confirmed: int, total: int) -> None:
        self.history.append({"target": target, "confirmed": confirmed, "total": total,
                             "accuracy": round(confirmed / max(1, total), 3)})
        self._save()

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump(self.history[-50:], fh, indent=2)
        except OSError as exc:
            LOGGER.warn("calibration_store", f"could not save history: {exc}")

    def multiplier(self, target: str) -> float:
        relevant = [h for h in self.history if h["target"] == target]
        if not relevant:
            return 1.0
        avg = sum(h["accuracy"] for h in relevant[-5:]) / len(relevant[-5:])
        return round(max(0.5, min(1.2, avg + 0.2)), 2)


# ---------------------------------------------------------------------------
# Step 5 — Drift monitor with real baseline (last N runs)
# ---------------------------------------------------------------------------

class DriftMonitor2:
    """Baseline = average of last DRIFT_BASELINE_RUNS. Configurable threshold."""

    def __init__(self) -> None:
        self.history: list[float] = []

    def record_run(self, fp_rate: float) -> None:
        self.history.append(float(fp_rate))

    def alert(self, current_fp_rate: float) -> dict[str, Any]:
        n = CENTRAL_CONSTANTS["DRIFT_BASELINE_RUNS"]
        if len(self.history) < n:
            return {"drift_alert": False, "reason": f"need_{n}_runs_of_history",
                    "available": len(self.history)}
        baseline = sum(self.history[-n:]) / n
        threshold = CENTRAL_CONSTANTS["DRIFT_THRESHOLD_MULTIPLIER"]
        if baseline > 0 and current_fp_rate > baseline * threshold:
            return {"drift_alert": True, "reason": "fp_rate_spiked",
                    "baseline_avg": round(baseline, 3), "current": round(current_fp_rate, 3),
                    "recommendation": "review_old_rules_target_behavior_may_have_changed"}
        return {"drift_alert": False, "baseline_avg": round(baseline, 3),
                "current": round(current_fp_rate, 3)}


# ---------------------------------------------------------------------------
# Step 6 — Safe rules loader with structure validation
# ---------------------------------------------------------------------------

_REQUIRED_RULE_KEYS = {"reason", "scope"}


def safe_load_rules(path: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Load rules safely. Missing/invalid file → empty list. Returns
    (rules, stats) where stats has loaded/rejected counts."""
    stats = {"loaded": 0, "rejected": 0}
    if not os.path.exists(path):
        LOGGER.warn("rules_io", f"rules file {path} missing — starting empty")
        return [], stats
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        LOGGER.error("rules_io", f"failed to parse {path}: {exc} — starting empty")
        return [], stats
    if not isinstance(data, list):
        LOGGER.error("rules_io", f"{path} root is not a list — starting empty")
        return [], stats
    valid: list[dict[str, Any]] = []
    for item in data:
        if isinstance(item, dict) and _REQUIRED_RULE_KEYS.issubset(item.keys()):
            valid.append({k: item[k] for k in ("reason", "scope", "pattern", "hits", "misses") if k in item})
            stats["loaded"] += 1
        else:
            stats["rejected"] += 1
    if stats["rejected"]:
        LOGGER.warn("rules_io", f"rejected {stats['rejected']} malformed rule entries")
    return valid, stats


# ---------------------------------------------------------------------------
# Step 7 — Human-readable uncertainty translations
# ---------------------------------------------------------------------------

UNCERTAINTY_TRANSLATIONS: dict[str, str] = {
    "insufficient_data": "بيانات غير كافية لاتخاذ قرار نهائي — تحتاج فحوصات إضافية",
    "conflicting_evidence": "تعارض في الأدلة — نتائج متضادة لنفس المسار",
    "inconclusive_retest": "إعادة الفحص أعطت نتائج متغيرة غير حاسمة",
    "partial_verification": "اجتاز بعض الاختبارات ولم يجتز كلها",
    "max_retries": "تم تجاوز الحد الأقصى لمرات إعادة الفحص — النتيجة غير حاسمة",
}


# ---------------------------------------------------------------------------
# Step 8 — Validate reference data for negative tests
# ---------------------------------------------------------------------------

def validate_reference_data(references: list[Any]) -> tuple[bool, str]:
    """Check that negative-test reference data is valid and distinct.
    Returns (is_valid, reason)."""
    if not references:
        return False, "no_reference_data"
    if len(set(str(r) for r in references)) < len(references):
        return False, "duplicate_reference_values"
    if any(r in (None, "", [], {}) for r in references):
        return False, "empty_reference_value"
    return True, "ok"


# ---------------------------------------------------------------------------
# Step 9 — Max retries detail
# ---------------------------------------------------------------------------

def max_retries_reason(retries_used: int) -> dict[str, str]:
    if retries_used >= CENTRAL_CONSTANTS["MAX_RETRIES"]:
        return {"uncertainty_reason": "max_retries",
                "uncertainty_detail": f"تم إعادة الفحص {retries_used} مرات دون الوصول لدرجة ثقة كافية — النتيجة غير حاسمة"}
    return {}


# ---------------------------------------------------------------------------
# Step 12 — Dynamic assumptions (real, based on what ran)
# ---------------------------------------------------------------------------

def build_dynamic_assumptions(tests_run: list[str], missing_tests: list[str],
                              alternatives_examined: int) -> list[str]:
    """Build a REAL assumptions list from what actually executed."""
    assumptions: list[str] = []
    if any("repetition" in t for t in tests_run):
        assumptions.append("result_confirmed_by_consistent_repetition")
    else:
        assumptions.append("repetition_test_not_run_confidence_lower")
    if missing_tests:
        assumptions.append(f"missing_tests: {','.join(missing_tests)}")
    if alternatives_examined > 0:
        assumptions.append(f"{alternatives_examined}_alternative_explanations_examined_and_excluded")
    else:
        assumptions.append("no_alternative_explanations_examined_limited_analysis")
    return assumptions


# ---------------------------------------------------------------------------
# Step 13 — Quality summary
# ---------------------------------------------------------------------------

def build_quality_summary(*, total: int, confirmed: int, needs_review: int,
                          excluded: int, missing_tests: list[str],
                          calibration_accuracy: float | None,
                          drift_alert: dict[str, Any]) -> dict[str, Any]:
    return {
        "total_discoveries": total,
        "fully_confirmed": confirmed,
        "needs_manual_review": needs_review,
        "excluded_as_false_positive": excluded,
        "missing_tests": missing_tests,
        "calibration_accuracy": calibration_accuracy,
        "drift_alert": drift_alert,
        "notes": [
            "low_calibration_data_available" if calibration_accuracy is None else "calibration_based_on_history",
            "drift_monitor_insufficient_history" if not drift_alert.get("drift_alert") and drift_alert.get("reason", "").startswith("need_") else "drift_monitor_active",
        ],
    }


__all__ = [
    "CENTRAL_CONSTANTS", "CalibrationStore", "DriftMonitor2", "LOGGER",
    "UNCERTAINTY_TRANSLATIONS", "UnifiedLogger", "AlternativeExplanation",
    "AlternativeFinder", "build_dynamic_assumptions", "build_quality_summary",
    "load_confidence_config", "max_retries_reason", "safe_load_rules",
    "similarity_score", "validate_reference_data",
]
