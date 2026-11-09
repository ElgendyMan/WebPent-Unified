"""U-DOJO-9: the practice generator — a plan the trainee can actually run.

Laws honored here:
- L-4 DETERMINISTIC: same weaknesses, same library, same seed, same plan.
- L-5 MEASURED IMPROVEMENT: every plan closes with reassessment criteria
  that demand measured evidence before improvement may be declared.
- L-7 LESSON FEEDBACK: focus items are ordered by weakness severity, so the
  lessons from U-DOJO-8 decide what gets practiced first.
- L-3 GROUND TRUTH: every item names a scenario that exists in the library;
  a plan with dangling identifiers is not a plan.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from webpent.dojo.scenario_library import Scenario, ScenarioLibrary
from webpent.dojo.weakness_identifier import Weakness

#: phases fixed by the spec
PHASES = ("warmup", "focus", "sparring", "reassessment")

#: plan-size guards (L-4: bounded and deterministic)
MAX_WARMUP_ITEMS = 4
MAX_FOCUS_ITEMS_PER_FAMILY = 3
MAX_SPARRING_ITEMS = 4

#: warmup scenarios come from the easy end of the library
WARMUP_MAX_DIFFICULTY = 2

#: reassessment criteria every plan carries (L-5)
REASSESSMENT_CRITERIA = (
    "re-run the skill assessment with at least 10 samples per family before "
    "declaring any skill value (L-5)",
    "declare improvement only when the measured skill value rises against "
    "the previous window (L-5)",
    "re-run sparring on the focus scenarios; any red victory reopens the "
    "adaptation gap and the plan regenerates (L-7)",
)


@dataclass(frozen=True)
class PlanItem:
    """One executable drill: a real scenario, one phase, one purpose."""

    phase: str
    scenario_id: str
    family: str
    description: str
    drills: int = 1

    def as_dict(self) -> dict:
        return {
            "phase": self.phase,
            "scenario_id": self.scenario_id,
            "family": self.family,
            "description": self.description,
            "drills": self.drills,
        }


@dataclass(frozen=True)
class TrainingPlan:
    """A full practice plan, executable end to end against the library."""

    seed: int
    warmup: tuple[PlanItem, ...]
    focus: tuple[PlanItem, ...]
    sparring: tuple[PlanItem, ...]
    reassessment: tuple[str, ...] = REASSESSMENT_CRITERIA

    @property
    def phases(self) -> tuple[str, ...]:
        return PHASES

    def items(self) -> tuple[PlanItem, ...]:
        return self.warmup + self.focus + self.sparring

    def as_dict(self) -> dict:
        return {
            "seed": self.seed,
            "warmup": [i.as_dict() for i in self.warmup],
            "focus": [i.as_dict() for i in self.focus],
            "sparring": [i.as_dict() for i in self.sparring],
            "reassessment": list(self.reassessment),
        }


class PracticeGenerator:
    """Turns identified weaknesses into an executable training plan."""

    @staticmethod
    def _family_scenarios(
        library: ScenarioLibrary, family: str
    ) -> list[Scenario]:
        return sorted(library.filter(skill_family=family), key=lambda s: s.scenario_id)

    def generate(
        self,
        weaknesses: list[Weakness],
        library: ScenarioLibrary,
        seed: int = 0,
    ) -> TrainingPlan:
        rng = random.Random(int(seed))
        ranked = sorted(weaknesses, key=lambda w: (-w.severity, w.skill_family, w.kind))

        # focus: the weakest family's drills come first (L-7)
        focus: list[PlanItem] = []
        seen_families: set[str] = set()
        for weakness in ranked:
            if weakness.skill_family in seen_families:
                continue
            seen_families.add(weakness.skill_family)
            scenarios = self._family_scenarios(library, weakness.skill_family)
            for scenario in scenarios[:MAX_FOCUS_ITEMS_PER_FAMILY]:
                focus.append(
                    PlanItem(
                        phase="focus",
                        scenario_id=scenario.scenario_id,
                        family=weakness.skill_family,
                        description=(
                            f"drill {weakness.kind} in {weakness.skill_family} "
                            f"on {scenario.scenario_id} "
                            f"(difficulty {scenario.difficulty})"
                        ),
                        drills=1,
                    )
                )

        # warmup: easy scenarios, deterministically sampled
        easy = [
            s for s in sorted(library.all(), key=lambda s: s.scenario_id)
            if s.difficulty <= WARMUP_MAX_DIFFICULTY
        ]
        picked = (
            rng.sample(easy, MAX_WARMUP_ITEMS) if len(easy) > MAX_WARMUP_ITEMS else easy
        )
        warmup = tuple(
            PlanItem(
                phase="warmup",
                scenario_id=s.scenario_id,
                family=s.family,
                description=f"warm-up rep on {s.scenario_id}",
            )
            for s in sorted(picked, key=lambda s: s.scenario_id)
        )

        # sparring: the hardest scenario of each focused family
        sparring: list[PlanItem] = []
        for weakness in ranked:
            if len(sparring) >= MAX_SPARRING_ITEMS:
                break
            if weakness.skill_family in {item.family for item in sparring}:
                continue
            scenarios = self._family_scenarios(library, weakness.skill_family)
            if not scenarios:
                continue
            hardest = max(
                scenarios, key=lambda s: (s.difficulty, s.scenario_id)
            )
            sparring.append(
                PlanItem(
                    phase="sparring",
                    scenario_id=hardest.scenario_id,
                    family=weakness.skill_family,
                    description=(
                        f"red-vs-blue match on {hardest.scenario_id}: the "
                        "defense patterns must hold or the gap reopens"
                    ),
                )
            )

        return TrainingPlan(
            seed=int(seed),
            warmup=warmup,
            focus=tuple(focus),
            sparring=tuple(sparring),
        )
