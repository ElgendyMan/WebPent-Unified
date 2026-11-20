"""VIP Benchmark Final Suite v9: registry only, never a live runner."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import VIPBenchmarkCaseV9

SCENARIO_CLASSES = (
    "idor",
    "broken_access_control",
    "privilege_escalation",
    "business_logic_abuse",
    "tenant_isolation_failure",
    "workflow_authorization_failure",
    "sensitive_data_exposure",
    "multi_step_vulnerability_chain",
)


@dataclass(frozen=True, slots=True)
class VIPBenchmarkSuiteV9:
    cases: tuple[VIPBenchmarkCaseV9, ...]
    requests_sent: int = 0

    @classmethod
    def from_recorded_state(
        cls, recorded_cases: tuple[dict[str, object], ...] = ()
    ) -> VIPBenchmarkSuiteV9:
        cases: list[VIPBenchmarkCaseV9] = []
        supplied = {str(item.get("scenario_class", "")): item for item in recorded_cases}
        for scenario in SCENARIO_CLASSES:
            item = supplied.get(scenario, {})
            complete = all(
                bool(item.get(key))
                for key in (
                    "realistic_target_behavior",
                    "autonomous_opportunity",
                    "causal_oracle",
                    "proof_bundle",
                    "replay_verified",
                    "metric_ready",
                )
            ) and bool(item.get("hidden_assumptions"))
            cases.append(
                VIPBenchmarkCaseV9(
                    case_id=f"v9-{scenario}",
                    scenario_class=scenario,
                    realistic_target_behavior=bool(item.get("realistic_target_behavior", False)),
                    hidden_assumptions=tuple(str(v) for v in item.get("hidden_assumptions", ())),
                    autonomous_opportunity=bool(item.get("autonomous_opportunity", False)),
                    causal_oracle=bool(item.get("causal_oracle", False)),
                    proof_bundle=bool(item.get("proof_bundle", False)),
                    replay_verified=bool(item.get("replay_verified", False)),
                    metric_ready=bool(item.get("metric_ready", False)),
                    disposition="scorable" if complete else "blocked",
                    blocked_reasons=()
                    if complete
                    else ("complete realistic causal evidence package is unavailable",),
                )
            )
        return cls(cases=tuple(cases))

    @property
    def scorable_cases(self) -> tuple[VIPBenchmarkCaseV9, ...]:
        return tuple(case for case in self.cases if case.disposition == "scorable")

    def summary(self) -> dict[str, object]:
        return {
            "suite_version": "vabh-fqr-v9",
            "registered_classes": len(SCENARIO_CLASSES),
            "case_count": len(self.cases),
            "scorable_case_count": len(self.scorable_cases),
            "blocked_case_count": sum(case.disposition == "blocked" for case in self.cases),
            "requests_sent": self.requests_sent,
            "qualification_claim": False,
        }


__all__ = ["SCENARIO_CLASSES", "VIPBenchmarkSuiteV9"]
