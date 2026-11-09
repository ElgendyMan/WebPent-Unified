"""U-DOJO-3: the practice runner.

Laws honored here:
- L-1 OFFLINE ONLY: practice never touches a socket; the target is the
  deterministic SimulatedTarget of U-DOJO-1.
- L-3 GROUND TRUTH: success is judged against the scenario's ground truth,
  never against the agent's own claim.
- L-4 DETERMINISTIC: same seed, same agent, same PracticeResult.
- L-6 ADVERSARIAL HONESTY: a claim without matching evidence is recorded as
  a false positive and lowers the score.
- L-10 NO IMPACT ON REAL CAMPAIGNS: nothing here reads campaign state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from webpent.dojo.engine import DojoRequest, DojoResponse, SimulatedTarget
from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.scenario_library import Scenario

#: weights of the score formula (fixed by the Dojo spec)
W_SUCCESS = 0.5
W_TIME = 0.2
W_REQUESTS = 0.1
W_FP = 0.2

#: a practice session runs at most this many planning waves
MAX_WAVES = 4


@dataclass(frozen=True)
class Conclusion:
    """What an agent claims after its run (L-6 judges this against truth)."""

    claims_finding: bool
    vuln_class: str = ""
    location: str = ""
    signature: str = ""
    notes: str = ""


class AttackAgent(Protocol):
    """Anything that can plan requests and conclude honestly or not."""

    def plan(self, lab_view: dict, scenario: Scenario) -> list[DojoRequest]: ...

    def conclude(self, responses: list[tuple[DojoRequest, DojoResponse]]) -> Conclusion: ...


@dataclass(frozen=True)
class PracticeResult:
    """The measured outcome of one practice session."""

    scenario_id: str
    success: bool
    score: float
    requests_used: int
    false_positives: int
    time_steps: int
    budget: int = 0
    evidence: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "success": self.success,
            "score": self.score,
            "requests_used": self.requests_used,
            "false_positives": self.false_positives,
            "time_steps": self.time_steps,
            "budget": self.budget,
            "evidence": list(self.evidence),
        }


class PracticeRunner:
    """Runs one agent against one scenario on one isolated lab (L-2)."""

    def __init__(
        self,
        generator: LabGenerator | None = None,
        target: SimulatedTarget | None = None,
    ) -> None:
        self.generator = generator or LabGenerator()
        self.target = target or SimulatedTarget()

    @staticmethod
    def score(
        *,
        success: bool,
        requests_used: int,
        time_steps: int,
        false_positives: int,
        budget: int,
    ) -> float:
        """The spec formula, hand-verifiable:

        score = 100 x (0.5 x success + 0.2 x time_eff
                       + 0.1 x req_eff + 0.2 x (1 - fp))

        where time_eff = max(0, 1 - time_steps / budget),
              req_eff  = max(0, 1 - requests_used / budget),
              fp       = 1.0 when at least one false-positive claim, else 0.0.
        """
        bounded = max(int(budget), 1)
        time_eff = max(0.0, 1.0 - time_steps / bounded)
        req_eff = max(0.0, 1.0 - requests_used / bounded)
        fp = 1.0 if false_positives > 0 else 0.0
        value = W_SUCCESS * (1.0 if success else 0.0)
        value += W_TIME * time_eff
        value += W_REQUESTS * req_eff
        value += W_FP * (1.0 - fp)
        return round(100.0 * value, 2)

    def run(
        self,
        agent: AttackAgent,
        scenario: Scenario,
        lab=None,
    ) -> PracticeResult:
        """Run the agent's plan against the scenario ground truth (L-3)."""
        if lab is None:
            lab = self.generator.start(scenario.template_id, seed=scenario.seed)
            # a fresh lab is sized by the scenario; a lab handed in (e.g. one
            # already shrunk or hardened by a defense pattern) keeps its own
            # budget, so pattern effects are observable (L-5)
            lab.request_budget = int(scenario.request_budget)
        # R2-dojo-02: a pattern-hardened lab enforces its own (smaller)
        # budget at consumption time; snapshot it after sizing/pattern and
        # score and record against that enforced budget, or the hardening
        # inflates the score mechanically (L-5 measured improvement)
        enforced_budget = int(lab.request_budget)

        transcript: list[tuple[DojoRequest, DojoResponse]] = []
        evidence: list[str] = []
        requests_used = 0
        time_steps = 0
        for _ in range(MAX_WAVES):
            planned = agent.plan(lab.public_view(), scenario)
            if not planned:
                break
            time_steps += 1
            for request in planned:
                requests_used += 1
                response = self.target.respond(lab, request)
                transcript.append((request, response))
                evidence.append(
                    f"{request.method} {request.path}"
                    f" -> {response.status} [{','.join(response.flags)}]"
                )
                if lab.request_budget <= 0:
                    break
            if lab.request_budget <= 0:
                break

        conclusion = agent.conclude(transcript)
        success, false_positives = self._judge(conclusion, scenario, transcript)
        evidence.append(
            f"claim: {conclusion.claims_finding}"
            f" class={conclusion.vuln_class} location={conclusion.location}"
            f" -> judged success={success} fp={false_positives}"
        )
        return PracticeResult(
            scenario_id=scenario.scenario_id,
            success=success,
            score=self.score(
                success=success,
                requests_used=requests_used,
                time_steps=time_steps,
                false_positives=false_positives,
                budget=enforced_budget,
            ),
            requests_used=requests_used,
            false_positives=false_positives,
            time_steps=time_steps,
            budget=enforced_budget,
            evidence=tuple(evidence),
        )

    @staticmethod
    def _judge(
        conclusion: Conclusion,
        scenario: Scenario,
        transcript: list[tuple[DojoRequest, DojoResponse]],
    ) -> tuple[bool, int]:
        """Adversarial honesty (L-6): the claim must match the evidence."""
        if not conclusion.claims_finding:
            return False, 0
        claim_ok = (
            conclusion.vuln_class == scenario.vuln_class
            and conclusion.location == scenario.location
        )
        hit_ok = any(
            request.path == scenario.location
            and response.has("vuln_hit")
            and scenario.vuln_class in response.flags
            for request, response in transcript
        )
        success = claim_ok and hit_ok
        return success, 0 if success else 1
