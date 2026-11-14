"""Offline controlled benchmark for VABHIC v7.

This runner only evaluates supplied recorded artifacts. It deliberately sends
zero requests and reports blocked cases when the complete evidence contract is
not present.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .contracts import BenchmarkCaseV6, BenchmarkDisposition

SCENARIO_CLASSES = (
    "complex_idor_chain",
    "privilege_escalation",
    "multi_step_business_logic_abuse",
    "tenant_isolation_failure",
    "workflow_authorization_bypass",
    "sensitive_data_exposure_chain",
)


class VIPControlledBenchmarkV6:
    def __init__(self) -> None:
        self.scenario_classes = SCENARIO_CLASSES

    def evaluate(self, *, recorded_cases: object | None = None) -> dict[str, Any]:
        supplied = self._supplied(recorded_cases)
        cases: list[BenchmarkCaseV6] = []
        for index, scenario in enumerate(SCENARIO_CLASSES, start=1):
            item = supplied.get(scenario, {})
            reasons = []
            for key, label in (
                ("realistic_behavior", "realistic application behavior"),
                ("hidden_assumptions", "hidden assumptions"),
                ("adaptive_strategy_required", "adaptive strategy evidence"),
                ("causal_oracle_present", "causal oracle"),
                ("proof_bundle_present", "ProofBundle"),
                ("replay_verified", "replay verification"),
            ):
                value = item.get(key) if isinstance(item, dict) else None
                if not value:
                    reasons.append(f"missing:{label}")
            disposition = (
                BenchmarkDisposition.SCORABLE if not reasons else BenchmarkDisposition.BLOCKED
            )
            cases.append(
                BenchmarkCaseV6(
                    case_id=f"vabhic-v6:{index:02d}",
                    scenario_class=scenario,
                    realistic_behavior=bool(item.get("realistic_behavior", False)),
                    hidden_assumptions=tuple(item.get("hidden_assumptions", ())),
                    adaptive_strategy_required=bool(item.get("adaptive_strategy_required", False)),
                    causal_oracle_present=bool(item.get("causal_oracle_present", False)),
                    proof_bundle_present=bool(item.get("proof_bundle_present", False)),
                    replay_verified=bool(item.get("replay_verified", False)),
                    disposition=disposition,
                    blocked_reasons=tuple(reasons),
                    requests_sent=0,
                )
            )
        scorable = [case for case in cases if case.disposition == BenchmarkDisposition.SCORABLE]
        return {
            "benchmark_version": "vabhic-v7-controlled-benchmark-v6",
            "scenario_class_count": len(SCENARIO_CLASSES),
            "registered_classes": list(SCENARIO_CLASSES),
            "cases": [asdict(case) for case in cases],
            "scorable_case_count": len(scorable),
            "blocked_case_count": len(cases) - len(scorable),
            "requests_sent": 0,
            "runner_mode": "offline_recorded_artifacts_only",
            "real_world_detection_rate": None,
            "metrics_valid": bool(scorable),
        }

    @staticmethod
    def _supplied(recorded_cases: object | None) -> dict[str, dict[str, Any]]:
        if not isinstance(recorded_cases, dict):
            return {}
        return {str(key): value for key, value in recorded_cases.items() if isinstance(value, dict)}


__all__ = ["SCENARIO_CLASSES", "VIPControlledBenchmarkV6"]
