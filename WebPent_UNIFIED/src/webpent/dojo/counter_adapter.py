"""U-DOJO-5: the counter adapter — blue escalates, red tries to break through.

Laws honored here:
- L-4 DETERMINISTIC: escalation follows fixed rules, never chance.
- L-5 MEASURED IMPROVEMENT: a defense pattern is only declared effective
  after it has been evaluated on at least 5 scenarios (anti-overfit guard).
- L-6 ADVERSARIAL HONESTY: bypasses are counted, never explained away.
- L-7 LESSON FEEDBACK: every round produces an advisory lesson.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from webpent.dojo.defender import DefensePattern
from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.practice_runner import AttackAgent, PracticeRunner
from webpent.dojo.scenario_library import Scenario

#: anti-overfit guard: a pattern needs this many scenarios before any
#: effectiveness claim is admissible
MIN_SCENARIOS_FOR_VERDICT = 5


@dataclass(frozen=True)
class AdaptationRound:
    """One round of the escalation ladder."""

    round_no: int
    pattern: str
    red_success: bool
    red_score: float
    bypassed: bool

    def as_dict(self) -> dict:
        return {
            "round_no": self.round_no,
            "pattern": self.pattern,
            "red_success": self.red_success,
            "red_score": self.red_score,
            "bypassed": self.bypassed,
        }


@dataclass(frozen=True)
class AdaptationResult:
    """The full record of one escalation challenge."""

    scenario_id: str
    rounds: tuple[AdaptationRound, ...]
    red_victor: bool
    bypass_counts: dict[str, int]
    lessons: tuple[str, ...]

    @property
    def applied_patterns(self) -> frozenset[str]:
        """Patterns actually applied in at least one round (R2-dojo-04).

        A round that runs before any red win applies no pattern at all, so
        an empty bypass_counts may mean "measured, none got through" or
        "never measured"; this flag tells the two apart.
        """
        return frozenset(
            entry.pattern for entry in self.rounds if entry.pattern != "none"
        )

    def as_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "rounds": [r.as_dict() for r in self.rounds],
            "red_victor": self.red_victor,
            "bypass_counts": dict(self.bypass_counts),
            "lessons": list(self.lessons),
        }


@dataclass(frozen=True)
class PatternVerdict:
    """Effectiveness verdict for one defense pattern (L-5)."""

    pattern: str
    scenarios_evaluated: int
    bypasses: int
    sufficient: bool
    effective: bool
    note: str

    def as_dict(self) -> dict:
        return {
            "pattern": self.pattern,
            "scenarios_evaluated": self.scenarios_evaluated,
            "bypasses": self.bypasses,
            "sufficient": self.sufficient,
            "effective": self.effective,
            "note": self.note,
        }


class AdaptationChallenge:
    """Runs red against an escalating blue playbook on one scenario."""

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
        playbook: list[DefensePattern],
        max_rounds: int | None = None,
    ) -> AdaptationResult:
        limit = max_rounds if max_rounds is not None else len(playbook) + 2
        index = -1  # nothing applied before the first red win
        rounds: list[AdaptationRound] = []
        lessons: list[str] = []
        bypass_counts: dict[str, int] = {}
        red_victor = False
        for round_no in range(1, max(limit, 1) + 1):
            if round_no > 1 and rounds[-1].red_success:
                if index + 1 >= len(playbook):
                    red_victor = True
                    lessons.append(
                        f"advisory: red exhausted the playbook on"
                        f" {scenario.scenario_id}; declared victor"
                    )
                    break
                index += 1
            pattern = playbook[index] if index >= 0 else None
            lab = self.generator.start(scenario.template_id, seed=scenario.seed)
            # base budget first, THEN the pattern (RT-02): pattern budget
            # effects must survive into the run (L-5)
            lab.request_budget = int(scenario.request_budget)
            if pattern is not None:
                lab = pattern.apply(lab)
            result = self.runner.run(red, scenario, lab)
            rounds.append(AdaptationRound(
                round_no=round_no,
                pattern=pattern.name if pattern else "none",
                red_success=result.success,
                red_score=result.score,
                bypassed=result.success if pattern is not None else False,
            ))
            if pattern is not None:
                bypass_counts[pattern.name] = bypass_counts.get(pattern.name, 0)
                if result.success:
                    bypass_counts[pattern.name] += 1
                    lessons.append(
                        f"advisory: red bypassed '{pattern.name}' on"
                        f" {scenario.scenario_id} (round {round_no})"
                    )
                else:
                    lessons.append(
                        f"advisory: '{pattern.name}' held red on"
                        f" {scenario.scenario_id} (round {round_no})"
                    )
            if pattern is not None and not result.success:
                # blue adapted successfully; the challenge ends here
                break
        return AdaptationResult(
            scenario_id=scenario.scenario_id,
            rounds=tuple(rounds),
            red_victor=red_victor,
            bypass_counts=bypass_counts,
            lessons=tuple(lessons),
        )

    def evaluate_pattern(
        self,
        pattern: DefensePattern,
        red_factory: Callable[[Scenario], AttackAgent],
        scenarios: list[Scenario],
    ) -> PatternVerdict:
        """Assess one pattern across scenarios (L-5 anti-overfit guard).

        No effectiveness claim is admissible below
        MIN_SCENARIOS_FOR_VERDICT scenarios, whatever the outcomes look like.
        """
        bypasses = 0
        applied_at_least_once = False
        for scenario in scenarios:
            outcome = self.run(red_factory(scenario), scenario, [pattern], max_rounds=2)
            bypasses += outcome.bypass_counts.get(pattern.name, 0)
            # R2-dojo-04: if red never wins a baseline round the pattern is
            # never applied in any round; bypasses == 0 then claims
            # effectiveness for a measurement that never ran (L-5/L-6)
            if pattern.name in outcome.applied_patterns:
                applied_at_least_once = True
        sufficient = len(scenarios) >= MIN_SCENARIOS_FOR_VERDICT
        if not sufficient:
            note = (
                f"insufficient evidence: {len(scenarios)} scenario(s) evaluated,"
                f" at least {MIN_SCENARIOS_FOR_VERDICT} required before any"
                f" effectiveness claim"
            )
        elif not applied_at_least_once:
            note = (
                f"evaluated on {len(scenarios)} scenarios with {bypasses}"
                f" bypass(es); pattern never applied: red never won a"
                f" baseline round"
            )
        else:
            note = (
                f"evaluated on {len(scenarios)} scenarios with {bypasses}"
                f" bypass(es)"
            )
        return PatternVerdict(
            pattern=pattern.name,
            scenarios_evaluated=len(scenarios),
            bypasses=bypasses,
            sufficient=sufficient,
            effective=sufficient and bypasses == 0 and applied_at_least_once,
            note=note,
        )
