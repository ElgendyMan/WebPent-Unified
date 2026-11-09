"""Controlled VIP benchmark v7 registry; this runner never contacts a target."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import BenchmarkCaseV7

REQUIRED_SCENARIOS = (
    ("authorization-failure", "complex authorization failure"),
    ("privilege-escalation", "multi-step privilege escalation"),
    ("business-logic", "business logic vulnerability"),
    ("tenant-isolation", "tenant isolation weakness"),
    ("workflow-security", "workflow security failure"),
    ("chained-vulnerability", "chained vulnerability scenario"),
)


@dataclass(frozen=True, slots=True)
class VIPControlledBenchmarkV7:
    """Evaluate readiness from supplied recorded artifacts only."""

    def run(self, recorded_cases: tuple[dict[str, object], ...] = ()) -> dict[str, object]:
        supplied = {str(item.get("case_id", "")): item for item in recorded_cases}
        cases: list[BenchmarkCaseV7] = []
        for case_id, scenario in REQUIRED_SCENARIOS:
            item = supplied.get(case_id, {})
            flags = {
                "realistic_target_model": bool(item.get("realistic_target_model", False)),
                "hidden_security_assumptions": tuple(item.get("hidden_security_assumptions", ())),
                "autonomous_investigation": bool(item.get("autonomous_investigation", False)),
                "multiple_research_paths": bool(item.get("multiple_research_paths", False)),
                "causal_oracle": bool(item.get("causal_oracle", False)),
                "proof_bundle": bool(item.get("proof_bundle", False)),
                "replay_verified": bool(item.get("replay_verified", False)),
            }
            reasons = tuple(
                name
                for name, value in flags.items()
                if not value or (name == "hidden_security_assumptions" and not value)
            )
            cases.append(
                BenchmarkCaseV7(
                    case_id=case_id,
                    scenario_class=scenario,
                    **flags,
                    disposition="scorable" if not reasons else "blocked",
                    blocked_reasons=reasons,
                    requests_sent=0,
                )
            )
        scorable = sum(case.disposition == "scorable" for case in cases)
        return {
            "benchmark": "VIP Controlled Benchmark v7",
            "cases": [
                case.__dict__
                if hasattr(case, "__dict__")
                else {
                    "case_id": case.case_id,
                    "scenario_class": case.scenario_class,
                    "realistic_target_model": case.realistic_target_model,
                    "hidden_security_assumptions": list(case.hidden_security_assumptions),
                    "autonomous_investigation": case.autonomous_investigation,
                    "multiple_research_paths": case.multiple_research_paths,
                    "causal_oracle": case.causal_oracle,
                    "proof_bundle": case.proof_bundle,
                    "replay_verified": case.replay_verified,
                    "disposition": case.disposition,
                    "blocked_reasons": list(case.blocked_reasons),
                    "requests_sent": 0,
                }
                for case in cases
            ],
            "registered_scenario_count": len(cases),
            "scorable_case_count": scorable,
            "blocked_case_count": len(cases) - scorable,
            "requests_sent": 0,
            "production_detection_claim": None,
            "governance": {
                "official_isolated_p10_runs_authorized": False,
                "vip_qualification": "NOT_QUALIFIED",
                "p10": "NOT_QUALIFIED",
            },
        }


__all__ = ["REQUIRED_SCENARIOS", "VIPControlledBenchmarkV7"]
