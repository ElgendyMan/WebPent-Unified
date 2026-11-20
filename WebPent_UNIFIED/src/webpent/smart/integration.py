"""
VIP Smart Autonomous Bug Hunter — Integration Layer.

Wires together all 5 smart modules into a single cohesive interface:
  1. Memory Engine   — stores and queries learned patterns
  2. Strategy Engine — generates adaptive detection plans
  3. Prioritizer     — ranks findings by risk
  4. Reporter        — generates predictive, actionable reports

GOVERNANCE: This layer is advisory and augmentative only.
It NEVER bypasses or overrides:
- Existing causal evaluators (CQA v2, DCVU, RTA)
- Governance gates
- Fail-closed policy

The smart layer provides: hints, plans, prioritization, reporting.
All actual detection decisions still come from the existing causal pipeline.
"""
from typing import Any

from webpent.smart.memory_engine import MemoryEntry, SmartMemory
from webpent.smart.prioritizer import PrioritizedFinding, SmartPrioritizer
from webpent.smart.reporter import SmartReporter
from webpent.smart.strategy_engine import SmartStrategyEngine


class VIPSmartHunter:
    """
    VIP Smart Autonomous Bug Hunter — unified interface.

    Architecture:
      plan() → Strategy Engine (adaptive planning)
         ↓
      [Existing causal detection: CQA v2, DCVU, RTA]
         ↓
      learn() → Memory Engine (stores patterns, hint-only)
         ↓
      prioritize() → Prioritizer (risk ranking)
         ↓
      report() → Reporter (predictive, actionable)

    GOVERNANCE: All causal decisions come from EXISTING evaluators.
    Smart layer augments but never overrides.
    """

    def __init__(self):
        self.memory = SmartMemory()
        self.strategy = SmartStrategyEngine(self.memory)
        self.prioritizer = SmartPrioritizer()
        self.reporter = SmartReporter()

        # Immutable governance declaration
        self.governance: dict[str, Any] = {
            "can_override_causal": False,
            "fail_closed": True,
            "memory_is_hint_only": True,
            "all_findings_reported": True,
            "external_targets_blocked": True,
            "state_mutation_blocked": True,
        }

    def plan(
        self,
        target_features: dict[str, Any] | None = None,
        time_budget_seconds: float = 600.0,
    ) -> dict[str, Any]:
        """Generate an adaptive detection plan. Advisory only."""
        target_features = target_features or {}
        detection_plan = self.strategy.plan_detection(target_features, time_budget_seconds)
        return {
            "ordered_patterns": detection_plan.ordered_patterns,
            "estimated_time": detection_plan.estimated_time,
            "time_budget": detection_plan.time_budget,
            "include_governance_checks": detection_plan.include_governance_checks,
            "reasoning": detection_plan.strategy_reasoning,
            "governance_note": "Plan is advisory only. Execution must pass through existing causal evaluators and governance gates.",
        }

    def learn(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Learn from verified findings. HINT-ONLY governance."""
        stored = 0
        for f in findings:
            try:
                entry = MemoryEntry(
                    pattern_id=f"learned_{f.get('finding_id', stored)}",
                    pattern_type=str(f.get("class", "unknown")),
                    features=dict(f.get("features", {})),
                    outcome="vulnerable",
                    confidence=float(f.get("confidence", 0.5)),
                    source="vip_smart_learning",
                )
                self.memory.store(entry)
                stored += 1
            except Exception:
                continue

        return {
            "entries_stored": stored,
            "total_entries": len(self.memory._entries),
            "governance_note": "hint-only — never overrides causal",
        }

    def prioritize(
        self,
        findings: list[dict[str, Any]],
        asset_context: dict[str, Any] | None = None,
    ) -> list[PrioritizedFinding]:
        """Prioritize findings by risk. Reorders only — never drops."""
        return self.prioritizer.prioritize(findings, asset_context)

    def report(
        self,
        findings: list[dict[str, Any]],
        asset_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate a smart, predictive, actionable report."""
        return self.reporter.generate_summary(findings, asset_context)

    def get_memory_hint(self, features: dict[str, Any]) -> dict[str, Any]:
        """Get a learning hint for given features. HINT-ONLY governance."""
        return self.memory.get_hint(features)

    def audit_snapshot(self) -> dict[str, Any]:
        """Get an auditable snapshot of smart layer state."""
        return {
            "governance": dict(self.governance),
            "memory_entries": len(self.memory._entries),
            "memory_signatures": {
                pid: entry.signature
                for pid, entry in self.memory._entries.items()
            },
        }
