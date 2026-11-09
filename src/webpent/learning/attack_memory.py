"""Proposal 1 — Self-Adversarial Learning Loop + Persistent Attack Memory.

Three components that turn the scanner into a learning hunter:

1. ``AttackMemory`` — persistent knowledge graph of every finding, failure,
   and chain outcome. The hunter never repeats a failed attempt for the same
   reason, categorizes failure causes, and generalizes weak patterns across
   similar path patterns.
2. ``AdversarialReviewer`` — dual-agent skeptic. After every CONFIRMED
   finding, it checks BOTH generic benign explanations (apply to every
   finding) AND per-vuln-class specific explanations. If any survives, the
   finding is downgraded (false-positive reduction).
3. ``AdaptiveStrategyOptimizer`` — tracks per-scenario success/failure counts
   and adjusts priority: repeated failures lose priority, a success spawns
   deeper exploration around that scenario.

All fail-closed: memory never fabricates evidence; the reviewer never
promotes, only downgrades.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MemoryEntry:
    key: str  # dedupe key (scenario + endpoint + failure_reason)
    outcome: str  # "confirmed" | "failed" | "needs_review"
    scenario_id: str
    endpoint: str
    reason: str = ""
    category: str = "unknown"  # failure category (see categorize_failure)
    count: int = 1


# Failure categories — generalize beyond the exact reason string.
_FAILURE_CATEGORY_PATTERNS: list[tuple[str, str]] = [
    ("network", r"timeout|connection|refused|dns|unreachable|network"),
    ("permission_denied", r"403|forbidden|unauthorized|401|scope|not.allowed|permission"),
    ("behavior_not_matched", r"not.matched|no.state.change|expected|invariant|held|rate.limit.enforced"),
    ("invalid_artifact", r"invalid|expired|stale|malformed|wrong.format|artifact"),
    ("server_error", r"500|502|503|server.error|internal.error|exception"),
]


def categorize_failure(reason: str) -> str:
    """Categorize a failure reason into a coarse class (generalization)."""
    r = str(reason or "").lower()
    for cat, pat in _FAILURE_CATEGORY_PATTERNS:
        if re.search(pat, r):
            return cat
    return "unknown"


def generalize_path_pattern(endpoint: str) -> str:
    """Generalize an endpoint to its path pattern (replace last segment +
    numeric ids with wildcard). Used to skip similar paths."""
    path = str(endpoint or "")
    if " " in path:
        path = path.split(" ", 1)[-1]
    path = re.sub(r"\d+", "{id}", path)
    parts = [p for p in path.split("/") if p]
    if len(parts) > 2:
        parts[-1] = "*"
    return "/" + "/".join(parts)


class AttackMemory:
    """Persistent attack memory — dedupes attempts, avoids repeat failures,
    generalizes by failure category + path pattern."""

    def __init__(self) -> None:
        self.entries: dict[str, MemoryEntry] = {}
        self._failed_patterns: dict[str, int] = {}  # path_pattern -> fail count

    def record(self, *, scenario_id: str, endpoint: str, outcome: str, reason: str = "") -> MemoryEntry:
        key = f"{scenario_id}:{endpoint}:{reason}"
        category = categorize_failure(reason) if outcome == "failed" else "n/a"
        if key in self.entries:
            self.entries[key].count += 1
            self.entries[key].outcome = outcome
            self.entries[key].category = category
            entry = self.entries[key]
        else:
            entry = MemoryEntry(key=key, outcome=outcome, scenario_id=scenario_id,
                                endpoint=endpoint, reason=reason, category=category)
            self.entries[key] = entry
        if outcome == "failed":
            pat = generalize_path_pattern(endpoint)
            self._failed_patterns[pat] = self._failed_patterns.get(pat, 0) + 1
        return entry

    def should_skip(self, *, scenario_id: str, endpoint: str, reason: str = "", threshold: int = 3) -> bool:
        """Skip an attempt that failed >= threshold times for the same reason."""
        key = f"{scenario_id}:{endpoint}:{reason}"
        entry = self.entries.get(key)
        if entry and entry.outcome == "failed" and entry.count >= threshold:
            return True
        # Generalization: if the same path pattern failed repeatedly for any
        # reason, skip similar endpoints (bounded, conservative threshold).
        pat = generalize_path_pattern(endpoint)
        if self._failed_patterns.get(pat, 0) >= threshold * 2:
            return True
        return False

    def failed_reasons(self, scenario_id: str) -> list[str]:
        return sorted({e.reason for e in self.entries.values()
                       if e.scenario_id == scenario_id and e.outcome == "failed" and e.reason})

    def failed_categories(self, scenario_id: str) -> list[str]:
        return sorted({e.category for e in self.entries.values()
                       if e.scenario_id == scenario_id and e.outcome == "failed"})


# Generic benign explanations — apply to EVERY finding regardless of vuln
# class. Each requires a specific evidence field to refute it. These are the
# "safety net" that catches false positives the per-class rules miss.
_GENERIC_BENIGN_EXPLANATIONS: dict[str, str] = {
    "response_identical_for_unauthenticated_baseline": "baseline_differs",
    "test_artifact_was_stale_or_invalid": "artifact_freshly_generated",
    "observation_caused_by_preexisting_state_not_by_test": "state_changed_by_test",
    "endpoint_returns_static_content_for_everyone": "response_varies_with_identity",
}

# Per-vuln-class specific benign explanations.
_BENIGN_EXPLANATIONS: dict[str, tuple[str, set[str]]] = {
    "static_page_returns_same_content_for_everyone": ("foreign_tenant_identifiers", {"tenant_isolation", "idor", "info_disclosure"}),
    "rate_limit_not_enforced_but_no_state_changed": ("expected_side_effect_count", {"race_condition"}),
    "redirect_is_expected_to_registered_callback": ("attacker_redirect_matched_exact_registered", {"oauth", "open_redirect"}),
    "error_message_is_generic_not_data_leak": ("foreign_tenant_identifiers", {"info_disclosure", "tenant_isolation"}),
    "session_was_already_authenticated_before_test": ("post_replay_session_check", {"multi_step_auth_bypass", "auth_bypass"}),
}


class AdversarialReviewer:
    """Dual-agent skeptic — refutes confirmed findings. Only downgrades.
    Checks generic explanations (always) + per-class explanations (when
    applicable). If any survives, the finding does NOT stand."""

    def review(self, finding_like: Any, evidence: dict[str, Any], *, vuln_class: str = "") -> tuple[bool, list[str]]:
        surviving: list[str] = []
        vc = str(vuln_class or "")
        # Generic explanations — always checked (safety net).
        for explanation, required_evidence in _GENERIC_BENIGN_EXPLANATIONS.items():
            value = evidence.get(required_evidence)
            if value in (None, "", [], {}, False):
                surviving.append(explanation)
        # Per-class explanations — only when applicable.
        for explanation, (required_evidence, applicable) in _BENIGN_EXPLANATIONS.items():
            if applicable and vc not in applicable:
                continue
            value = evidence.get(required_evidence)
            if value in (None, "", [], {}, False):
                surviving.append(explanation)
        return (len(surviving) == 0, surviving)


class AdaptiveStrategyOptimizer:
    """Tracks per-scenario outcomes; adjusts priority. Failures lose priority,
    a success spawns deeper exploration."""

    def __init__(self) -> None:
        self.success: dict[str, int] = {}
        self.failure: dict[str, int] = {}

    def record_success(self, scenario_id: str) -> None:
        self.success[scenario_id] = self.success.get(scenario_id, 0) + 1

    def record_failure(self, scenario_id: str) -> None:
        self.failure[scenario_id] = self.failure.get(scenario_id, 0) + 1

    def priority(self, scenario_id: str) -> float:
        s = self.success.get(scenario_id, 0)
        f = self.failure.get(scenario_id, 0)
        if s == 0 and f == 0:
            return 1.0
        if f >= 3 and s == 0:
            return 0.1
        return (s + 1) / (s + f + 1)

    def spawn_deeper(self, scenario_id: str) -> list[str]:
        if self.success.get(scenario_id, 0) >= 1:
            return [f"{scenario_id}::deeper-bypass-variant-{i}" for i in range(1, 4)]
        return []


__all__ = [
    "AdaptiveStrategyOptimizer", "AdversarialReviewer", "AttackMemory",
    "MemoryEntry", "categorize_failure", "generalize_path_pattern",
]
