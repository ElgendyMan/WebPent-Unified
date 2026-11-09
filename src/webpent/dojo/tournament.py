"""U-DOJO-6: tournament mode — built-in agents compete on the same seeds.

Laws honored here:
- L-3 GROUND TRUTH: built-in agents plan from surface information only
  (routes, params, family-typical candidates); they never read the
  scenario's ground truth, and the poison test proves it.
- L-4 DETERMINISTIC: every agent is a fixed strategy; same inputs, same
  standings, byte for byte.
- L-6 ADVERSARIAL HONESTY: the blind claimer cannot beat honest explorers,
  because false-positive claims are priced into the score.
"""

from __future__ import annotations

from dataclasses import dataclass

from webpent.dojo.engine import DojoRequest, DojoResponse
from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.practice_runner import AttackAgent, Conclusion, PracticeRunner
from webpent.dojo.scenario_library import Scenario

#: family-typical candidate payloads; deliberately surface knowledge only
CANDIDATE_PAYLOADS: dict[str, tuple[str, ...]] = {
    "idor": ("1002", "1001", "1003", "0"),
    "sqli": ("' OR 1=1", "admin'--", "1=1"),
    "xss": ("<script>", "<img>", "javascript:"),
    "ssrf": ("169.254.169.254", "localhost", "127.0.0.1"),
    "jwt": ("alg:none", "expired", "none"),
    "info_disclosure": ("env", "heapdump", "beans"),
    "race_condition": ("DUPLICATE", "resend", "SINGLE"),
    "business_logic": ("-1", "0", "200%"),
    "auth_bypass": ("administrator", "admin", "true"),
}

#: built-ins never spend more than this many planned requests
MAX_PLANNED_REQUESTS = 12

_NO_AUTH = {"", "none", None}


def _first_hit_class(response: DojoResponse) -> str:
    for flag in response.flags:
        if flag != "vuln_hit":
            return flag
    return ""


class _BaseAgent:
    name = "base"

    def plan(self, lab_view: dict, scenario: Scenario) -> list[DojoRequest]:
        raise NotImplementedError

    def conclude(
        self, responses: list[tuple[DojoRequest, DojoResponse]]
    ) -> Conclusion:
        raise NotImplementedError

    @staticmethod
    def _open_routes(lab_view: dict) -> list[dict]:
        return [r for r in lab_view.get("routes", []) if r.get("requires_auth") in _NO_AUTH]


class NaiveAgent(_BaseAgent):
    """One blind guess, then an unconditional claim. FP-prone by design."""

    name = "naive"

    def plan(self, lab_view: dict, scenario: Scenario) -> list[DojoRequest]:
        routes = self._open_routes(lab_view)
        if not routes or not routes[0].get("params"):
            return []
        route = routes[0]
        method = route.get("method", "GET") or "GET"
        return [DojoRequest(method, route["path"], {route["params"][0]: "admin"})]

    def conclude(self, responses) -> Conclusion:
        # blind: claims regardless of what came back (L-6 prices this)
        return Conclusion(claims_finding=True)


class MethodicalAgent(_BaseAgent):
    """Exhausts family candidates over every open param, claims first hit."""

    name = "methodical"

    def plan(self, lab_view: dict, scenario: Scenario) -> list[DojoRequest]:
        candidates = CANDIDATE_PAYLOADS.get(scenario.family, ("probe",))
        requests: list[DojoRequest] = []
        for route in self._open_routes(lab_view):
            for param in route.get("params", []):
                for payload in candidates:
                    if len(requests) >= MAX_PLANNED_REQUESTS:
                        return requests
                    requests.append(
                        DojoRequest(
                            route.get("method", "GET") or "GET",
                            route["path"], {param: payload},
                        )
                    )
        return requests

    def conclude(self, responses) -> Conclusion:
        for request, response in responses:
            if response.has("vuln_hit"):
                return Conclusion(
                    claims_finding=True,
                    vuln_class=_first_hit_class(response),
                    location=request.path,
                )
        return Conclusion(claims_finding=False)


class SignatureMatcherAgent(_BaseAgent):
    """Claims on any hit-shaped response, decoys included. FP-prone."""

    name = "signature_matcher"

    def plan(self, lab_view: dict, scenario: Scenario) -> list[DojoRequest]:
        return MethodicalAgent().plan(lab_view, scenario)

    def conclude(self, responses) -> Conclusion:
        for request, response in responses:
            if response.has("vuln_hit") or response.has("decoy_hit"):
                flag_class = _first_hit_class(response)
                return Conclusion(
                    claims_finding=True,
                    vuln_class=flag_class or "unknown",
                    location=request.path,
                )
        return Conclusion(claims_finding=False)


class AdaptiveAgent(_BaseAgent):
    """Leads with the most likely candidate per param and claims honestly."""

    name = "adaptive"

    def plan(self, lab_view: dict, scenario: Scenario) -> list[DojoRequest]:
        candidates = CANDIDATE_PAYLOADS.get(scenario.family, ("probe",))
        lead = candidates[0]
        requests: list[DojoRequest] = []
        for route in self._open_routes(lab_view):
            for param in route.get("params", []):
                if len(requests) >= MAX_PLANNED_REQUESTS:
                    return requests
                requests.append(DojoRequest(
                    route.get("method", "GET") or "GET",
                    route["path"], {param: lead},
                ))
        return requests

    def conclude(self, responses) -> Conclusion:
        # honest variant of methodical: claims only on a true vuln_hit,
        # never on decoy ground (L-6)
        for request, response in responses:
            if response.has("vuln_hit"):
                return Conclusion(
                    claims_finding=True,
                    vuln_class=_first_hit_class(response),
                    location=request.path,
                )
        return Conclusion(claims_finding=False)


BUILTIN_AGENTS: dict[str, AttackAgent] = {
    agent.name: agent
    for agent in (NaiveAgent(), MethodicalAgent(), SignatureMatcherAgent(), AdaptiveAgent())
}


@dataclass(frozen=True)
class AgentStanding:
    """One agent's tournament record, ranked position implied by order."""

    agent: str
    total_score: float
    successes: int
    false_positives: int
    per_scenario: tuple[tuple[str, float], ...]

    def as_dict(self) -> dict:
        return {
            "agent": self.agent,
            "total_score": self.total_score,
            "successes": self.successes,
            "false_positives": self.false_positives,
            "per_scenario": dict(self.per_scenario),
        }


@dataclass(frozen=True)
class TournamentResult:
    """Ranked standings; deterministic tie-breaking by agent name."""

    standings: tuple[AgentStanding, ...]

    def as_dict(self) -> dict:
        return {"standings": [s.as_dict() for s in self.standings]}


class TournamentRunner:
    """Runs agents over the same scenario list and ranks them."""

    def __init__(
        self,
        generator: LabGenerator | None = None,
        runner: PracticeRunner | None = None,
    ) -> None:
        self.generator = generator or LabGenerator()
        self.runner = runner or PracticeRunner(self.generator)

    def _run(self, agent: AttackAgent, scenarios: list[Scenario]):
        return [self.runner.run(agent, scenario) for scenario in scenarios]

    @staticmethod
    def _name(agent: AttackAgent) -> str:
        return getattr(agent, "name", type(agent).__name__)

    def round_robin(
        self,
        scenarios: list[Scenario],
        agents: dict[str, AttackAgent] | None = None,
    ) -> TournamentResult:
        roster = agents if agents is not None else BUILTIN_AGENTS
        standings: list[AgentStanding] = []
        for name, agent in roster.items():
            results = self._run(agent, scenarios)
            standings.append(AgentStanding(
                agent=name,
                total_score=round(sum(r.score for r in results), 2),
                successes=sum(1 for r in results if r.success),
                false_positives=sum(r.false_positives for r in results),
                per_scenario=tuple((r.scenario_id, r.score) for r in results),
            ))
        standings.sort(key=lambda s: (-s.total_score, s.agent))
        return TournamentResult(tuple(standings))

    def ab_comparison(
        self,
        agent_a: AttackAgent,
        agent_b: AttackAgent,
        scenarios: list[Scenario],
    ) -> dict:
        """Same seeds, same order, two agents; the difference is the agent."""
        results_a = self._run(agent_a, scenarios)
        results_b = self._run(agent_b, scenarios)
        name_a, name_b = self._name(agent_a), self._name(agent_b)
        return {
            "agents": [name_a, name_b],
            "totals": {
                name_a: round(sum(r.score for r in results_a), 2),
                name_b: round(sum(r.score for r in results_b), 2),
            },
            "per_scenario": {
                name_a: {r.scenario_id: r for r in results_a},
                name_b: {r.scenario_id: r for r in results_b},
            },
            "same_seeds": True,
        }
