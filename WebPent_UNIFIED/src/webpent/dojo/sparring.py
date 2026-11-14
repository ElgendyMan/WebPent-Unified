"""U-DOJO-4: the sparring protocol — a red agent against a blue patch run.

Laws honored here:
- L-4 DETERMINISTIC: same red, same patterns, same seed, same result.
- L-6 ADVERSARIAL HONESTY: a red win is recorded as a blue weakness with no
  varnish; a blue hold is recorded plainly too.
- L-7 LESSON FEEDBACK: every round produces an advisory lesson ready for
  import into training material; nothing is dropped silently.
"""

from __future__ import annotations

from dataclasses import dataclass

from webpent.dojo.defender import DefensePattern
from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.practice_runner import AttackAgent, PracticeRunner
from webpent.dojo.scenario_library import Scenario


@dataclass(frozen=True)
class RoundLog:
    """One red-vs-blue round, fully recorded."""

    round_no: int
    pattern: str
    red_success: bool
    red_score: float
    blue_score: float

    def as_dict(self) -> dict:
        return {
            "round_no": self.round_no,
            "pattern": self.pattern,
            "red_success": self.red_success,
            "red_score": self.red_score,
            "blue_score": self.blue_score,
        }


@dataclass(frozen=True)
class SparringMatchResult:
    """The measured outcome of a full sparring match."""

    scenario_id: str
    red_score: float
    blue_score: float
    winner: str
    rounds_log: tuple[RoundLog, ...]
    lessons: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "red_score": self.red_score,
            "blue_score": self.blue_score,
            "winner": self.winner,
            "rounds_log": [r.as_dict() for r in self.rounds_log],
            "lessons": list(self.lessons),
        }


class SparringMatch:
    """Runs a red agent against a sequence of blue defense patterns."""

    def __init__(
        self,
        generator: LabGenerator | None = None,
        runner: PracticeRunner | None = None,
    ) -> None:
        self.generator = generator or LabGenerator()
        self.runner = runner or PracticeRunner(self.generator)

    def run(
        self,
        red: AttackAgent,
        scenario: Scenario,
        blue_patterns: list[DefensePattern],
        rounds: int = 3,
    ) -> SparringMatchResult:
        rounds_log: list[RoundLog] = []
        lessons: list[str] = []
        for round_no in range(1, max(int(rounds), 1) + 1):
            pattern = (
                blue_patterns[(round_no - 1) % len(blue_patterns)]
                if blue_patterns
                else None
            )
            lab = self.generator.start(scenario.template_id, seed=scenario.seed)
            # base budget first, THEN the pattern: a pattern that shrinks or
            # hardens the budget must take effect (RT-02), not be stomped by
            # a re-assignment after apply (L-5 measured improvement)
            lab.request_budget = int(scenario.request_budget)
            if pattern is not None:
                lab = pattern.apply(lab)
            result = self.runner.run(red, scenario, lab)
            blue_won_round = not result.success
            rounds_log.append(RoundLog(
                round_no=round_no,
                pattern=pattern.name if pattern else "none",
                red_success=result.success,
                red_score=result.score,
                blue_score=100.0 if blue_won_round else 0.0,
            ))
            if pattern is None:
                continue
            if result.success:
                lessons.append(
                    f"advisory: weakness recorded — defense '{pattern.name}'"
                    f" was bypassed on {scenario.scenario_id}"
                    f" (red score {result.score})"
                )
            else:
                lessons.append(
                    f"advisory: defense '{pattern.name}' held on"
                    f" {scenario.scenario_id} (red score {result.score})"
                )
        red_score = round(
            sum(entry.red_score for entry in rounds_log) / len(rounds_log), 2
        ) if rounds_log else 0.0
        blue_score = round(
            sum(entry.blue_score for entry in rounds_log) / len(rounds_log), 2
        ) if rounds_log else 0.0
        red_won = any(entry.red_success for entry in rounds_log)
        return SparringMatchResult(
            scenario_id=scenario.scenario_id,
            red_score=red_score,
            blue_score=blue_score,
            winner="red" if red_won else "blue",
            rounds_log=tuple(rounds_log),
            lessons=tuple(lessons),
        )
