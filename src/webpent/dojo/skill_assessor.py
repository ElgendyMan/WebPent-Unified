"""U-DOJO-7: the skill assessor — measured improvement, honestly gated.

Laws honored here:
- L-5 MEASURED IMPROVEMENT: a skill number is only declared once at least
  10 samples back it; below that the profile is marked insufficient.
- L-6 ADVERSARIAL HONESTY: false positives drag the skill down by formula,
  not by narration.
- L-7 LESSON FEEDBACK: profiles carry the family they feed in the matrix.
"""

from __future__ import annotations

from dataclasses import dataclass

from webpent.dojo.practice_runner import PracticeResult
from webpent.dojo.scenario_library import Scenario

#: minimum samples before a skill value may be declared (L-5)
MIN_SAMPLES = 10

W_SUCCESS_RATE = 0.4
W_AVG_SCORE = 0.3
W_FP_RATE = 0.2
W_TIME = 0.1


@dataclass(frozen=True)
class SkillProfile:
    """One skill family's measured standing."""

    skill_family: str
    samples: int
    success_rate: float
    avg_score: float
    fp_rate: float
    time_ratio: float
    skill: float
    sufficient: bool

    def as_dict(self) -> dict:
        return {
            "skill_family": self.skill_family,
            "samples": self.samples,
            "success_rate": self.success_rate,
            "avg_score": self.avg_score,
            "fp_rate": self.fp_rate,
            "time_ratio": self.time_ratio,
            "skill": self.skill,
            "sufficient": self.sufficient,
        }


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


class SkillAssessor:
    """Turns practice results into skill-family profiles and trends."""

    @staticmethod
    def _matches(family: str, scenario: Scenario) -> bool:
        return family in scenario.skill_families

    def assess(
        self,
        skill_family: str,
        results: list[PracticeResult],
        scenarios: list[Scenario],
    ) -> SkillProfile:
        relevant = [
            r for r in results
            if any(
                s.scenario_id == r.scenario_id and self._matches(skill_family, s)
                for s in scenarios
            )
        ]
        samples = len(relevant)
        if samples == 0:
            return SkillProfile(
                skill_family=skill_family,
                samples=0,
                success_rate=0.0,
                avg_score=0.0,
                fp_rate=0.0,
                time_ratio=0.0,
                skill=0.0,
                sufficient=False,
            )
        success_rate = _mean([1.0 if r.success else 0.0 for r in relevant])
        avg_score = _mean([r.score for r in relevant]) / 100.0
        fp_rate = _mean([float(r.false_positives) for r in relevant])
        time_ratio = _mean(
            [
                min(1.0, r.time_steps / r.budget) if r.budget > 0 else 0.0
                for r in relevant
            ]
        )
        value = (
            W_SUCCESS_RATE * success_rate
            + W_AVG_SCORE * avg_score
            + W_FP_RATE * (1.0 - min(1.0, fp_rate))
            + W_TIME * (1.0 - min(1.0, time_ratio))
        )
        return SkillProfile(
            skill_family=skill_family,
            samples=samples,
            success_rate=round(success_rate, 4),
            avg_score=round(avg_score, 4),
            fp_rate=round(fp_rate, 4),
            time_ratio=round(time_ratio, 4),
            skill=round(100.0 * value, 2),
            sufficient=samples >= MIN_SAMPLES,
        )

    def trend(
        self,
        skill_family: str,
        results: list[PracticeResult],
        scenarios: list[Scenario],
        window: int = MIN_SAMPLES,
    ) -> tuple[SkillProfile, ...]:
        """Chronological skill snapshots, one per window of results."""
        relevant = [
            r for r in results
            if any(
                s.scenario_id == r.scenario_id and self._matches(skill_family, s)
                for s in scenarios
            )
        ]
        size = max(int(window), 1)
        profiles = [
            self.assess(skill_family, relevant[start:start + size], scenarios)
            for start in range(0, len(relevant), size)
        ]
        return tuple(p for p in profiles if p.samples > 0)

    @staticmethod
    def direction(profiles: tuple[SkillProfile, ...]) -> str:
        """improving / declining / flat, comparing first and last windows."""
        if len(profiles) < 2 or profiles[-1].skill == profiles[0].skill:
            return "flat"
        return "improving" if profiles[-1].skill > profiles[0].skill else "declining"
