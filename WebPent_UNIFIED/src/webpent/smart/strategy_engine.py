"""
VIP Smart Autonomous Bug Hunter — Smart Strategy Engine.

Generates adaptive detection plans based on:
- Target features (what kind of system is this?)
- Learned patterns from memory (what worked before?)
- Time budget (how much time do we have?)

Governance: Strategy plan is advisory only. Actual execution still passes
through all existing causal evaluators and governance gates.
"""
from dataclasses import dataclass, field
from typing import Any

from webpent.smart.memory_engine import SmartMemory

# Pattern library — generic detection patterns with estimated cost
PATTERN_LIBRARY: list[dict[str, Any]] = [
    {"pattern_type": "idor", "base_cost": 8, "applies_to": ["has_user_objects", "has_order_system"]},
    {"pattern_type": "broken_access_control", "base_cost": 10, "applies_to": ["has_admin_endpoints", "has_role_system"]},
    {"pattern_type": "tenant_isolation", "base_cost": 15, "applies_to": ["has_multi_tenant"]},
    {"pattern_type": "privilege_escalation", "base_cost": 20, "applies_to": ["has_role_system", "has_admin_endpoints"]},
    {"pattern_type": "business_logic", "base_cost": 25, "applies_to": ["has_workflow", "has_payment_system"]},
    {"pattern_type": "workflow_authz", "base_cost": 12, "applies_to": ["has_workflow"]},
    {"pattern_type": "sensitive_data_exposure", "base_cost": 10, "applies_to": ["has_user_objects", "has_pii"]},
    {"pattern_type": "multi_step_chain", "base_cost": 30, "applies_to": ["has_user_objects", "has_admin_endpoints"]},
    {"pattern_type": "ssrf", "base_cost": 18, "applies_to": ["has_url_fetching", "has_external_integrations"]},
    {"pattern_type": "sqli", "base_cost": 15, "applies_to": ["has_search", "has_user_input"]},
]


@dataclass
class DetectionPlan:
    ordered_patterns: list[dict[str, Any]] = field(default_factory=list)
    estimated_time: float = 0.0
    time_budget: float = 600.0
    include_governance_checks: bool = True
    strategy_reasoning: str = ""


class SmartStrategyEngine:
    """
    Generates adaptive detection plans.

    The plan is advisory. Actual execution always respects:
    1. Existing causal evaluators
    2. Governance gates
    3. Fail-closed policy
    """

    def __init__(self, memory: SmartMemory | None = None):
        self.memory = memory or SmartMemory()
        self._pattern_library = list(PATTERN_LIBRARY)

    def _pattern_relevance(self, pattern: dict[str, Any], target_features: dict[str, Any]) -> float:
        """Score how relevant a pattern is to this target (0.0 to 1.0)."""
        applies = pattern.get("applies_to", [])
        if not applies:
            return 0.3  # Mild baseline relevance
        matches = sum(1 for feature in applies if target_features.get(feature))
        return matches / len(applies) if applies else 0.3

    def _memory_boost(self, pattern_type: str) -> float:
        """Boost from memory — patterns that have worked before get priority."""
        boost = 0.0
        for entry in self.memory._entries.values():
            if entry.pattern_type == pattern_type and entry.outcome == "vulnerable":
                boost += entry.confidence * 0.1
        return min(boost, 0.5)

    def plan_detection(
        self,
        target_features: dict[str, Any],
        time_budget_seconds: float = 600.0,
    ) -> DetectionPlan:
        """Generate an ordered detection plan."""
        scored_patterns = []
        for pattern in self._pattern_library:
            relevance = self._pattern_relevance(pattern, target_features)
            memory_boost = self._memory_boost(pattern["pattern_type"])
            score = relevance + memory_boost
            cost = pattern["base_cost"]

            scored_patterns.append({
                "pattern_type": pattern["pattern_type"],
                "score": round(score, 3),
                "cost": cost,
                "relevance": round(relevance, 3),
                "memory_boost": round(memory_boost, 3),
                "applies_to": pattern["applies_to"],
            })

        # Sort by score descending, then by cost ascending
        scored_patterns.sort(key=lambda p: (-p["score"], p["cost"]))

        # Fit within time budget
        ordered = []
        total_time = 0.0
        for p in scored_patterns:
            if total_time + p["cost"] <= time_budget_seconds:
                ordered.append(p)
                total_time += p["cost"]
            elif len(ordered) == 0:
                ordered.append(p)
                total_time += p["cost"]
                break

        reasoning = (
            f"Selected {len(ordered)} of {len(self._pattern_library)} patterns. "
            f"Budget: {time_budget_seconds}s, Estimated: {total_time}s. "
            f"Top pattern: {ordered[0]['pattern_type'] if ordered else 'none'} "
            f"(score={ordered[0]['score'] if ordered else 0})."
        )

        return DetectionPlan(
            ordered_patterns=ordered,
            estimated_time=round(total_time, 1),
            time_budget=time_budget_seconds,
            include_governance_checks=True,
            strategy_reasoning=reasoning,
        )
