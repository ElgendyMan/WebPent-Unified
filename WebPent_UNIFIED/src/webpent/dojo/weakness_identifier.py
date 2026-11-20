"""U-DOJO-8: the weakness identifier — L-7 LESSON FEEDBACK made concrete.

Laws honored here:
- L-6 ADVERSARIAL HONESTY: weaknesses are derived from measured results,
  never asserted; a passing-but-slow agent is not called unskilled.
- L-7 LESSON FEEDBACK: every finding is advisory material with a stated
  detail, never a silent judgment, and never a punishment.
- L-5 MEASURED IMPROVEMENT: statistical kinds need at least five samples
  before a weakness may be declared, mirroring the anti-overfit guard.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from webpent.dojo.practice_runner import PracticeResult
from webpent.dojo.scenario_library import Scenario
from webpent.dojo.sparring import SparringMatchResult

#: the five weakness kinds the Dojo recognizes (fixed by the spec)
WEAKNESS_KINDS = frozenset(
    {
        "skill_gap",
        "consistency_gap",
        "context_gap",
        "speed_gap",
        "adaptation_gap",
    }
)

#: minimum samples before a statistical weakness may be declared (L-5)
MIN_SAMPLES_FOR_WEAKNESS = 5

#: a skill gap needs a failure rate past this line, with false positives
SKILL_GAP_SUCCESS_LINE = 0.5

#: a speed gap needs most of the budget burned while still passing
SPEED_GAP_TIME_LINE = 0.8

#: a consistency gap needs score standard deviation past this line
CONSISTENCY_GAP_STDDEV_LINE = 25.0

#: context gap: easy scenarios pass, hard ones of the same family fail
EASY_DIFFICULTY = 2
HARD_DIFFICULTY = 4
EASY_PASS_LINE = 0.8
HARD_FAIL_LINE = 0.2


@dataclass(frozen=True)
class Weakness:
    """One advisory finding about where the trainee is weak (L-7)."""

    kind: str
    skill_family: str
    severity: float
    detail: str
    advisory: bool = True

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "skill_family": self.skill_family,
            "severity": self.severity,
            "detail": self.detail,
            "advisory": self.advisory,
        }


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = _mean(values)
    return math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))


class WeaknessIdentifier:
    """Derives advisory weaknesses from practice and sparring results."""

    def __init__(self, min_samples: int = MIN_SAMPLES_FOR_WEAKNESS) -> None:
        self.min_samples = int(min_samples)

    # -- family bookkeeping ------------------------------------------------

    @staticmethod
    def _families(
        results: list[PracticeResult], scenarios: list[Scenario]
    ) -> dict[str, list[PracticeResult]]:
        """Group results by the skill families their scenarios declare."""
        by_id = {s.scenario_id: s for s in scenarios}
        grouped: dict[str, list[PracticeResult]] = {}
        for result in results:
            scenario = by_id.get(result.scenario_id)
            if scenario is None:
                continue
            for family in scenario.skill_families:
                grouped.setdefault(family, []).append(result)
        return grouped

    @staticmethod
    def _per_scenario_success(
        results: list[PracticeResult],
    ) -> dict[str, float]:
        by_id: dict[str, list[PracticeResult]] = {}
        for result in results:
            by_id.setdefault(result.scenario_id, []).append(result)
        return {
            scenario_id: _mean([1.0 if r.success else 0.0 for r in group])
            for scenario_id, group in by_id.items()
        }

    # -- per-family detectors ----------------------------------------------

    def _skill_gap(
        self, family: str, results: list[PracticeResult]
    ) -> Weakness | None:
        success_rate = _mean([1.0 if r.success else 0.0 for r in results])
        total_fp = sum(r.false_positives for r in results)
        if success_rate >= SKILL_GAP_SUCCESS_LINE:
            return None
        # pure honest failure (0% success, zero false-positive claims) is
        # the clearest gap there is; requiring an FP to flag it hid the
        # most important finding (RT-05, L-7: nothing is dropped silently)
        severity = round(1.0 - success_rate, 2)
        if total_fp == 0:
            detail = (
                f"advisory: {family} success rate {success_rate:.0%} over "
                f"{len(results)} runs with no false-positive claims; the "
                "fundamentals need practice before anything else"
            )
        else:
            detail = (
                f"advisory: {family} success rate {success_rate:.0%} over "
                f"{len(results)} runs with {total_fp} false-positive claim(s); "
                "the fundamentals need practice before anything else"
            )
        return Weakness(
            kind="skill_gap",
            skill_family=family,
            severity=severity,
            detail=detail,
        )

    def _speed_gap(
        self, family: str, results: list[PracticeResult]
    ) -> Weakness | None:
        success_rate = _mean([1.0 if r.success else 0.0 for r in results])
        if success_rate < SKILL_GAP_SUCCESS_LINE:
            return None
        ratios = [
            min(1.0, r.time_steps / r.budget) if r.budget > 0 else 0.0
            for r in results
        ]
        time_ratio = _mean(ratios)
        if time_ratio < SPEED_GAP_TIME_LINE:
            return None
        return Weakness(
            kind="speed_gap",
            skill_family=family,
            severity=round(time_ratio, 2),
            detail=(
                f"advisory: {family} solves the target ({success_rate:.0%} "
                f"success) but burns {time_ratio:.0%} of the request budget "
                "on average; the skill is there, the economy is not"
            ),
        )

    def _consistency_gap(
        self, family: str, results: list[PracticeResult]
    ) -> Weakness | None:
        scores = [r.score for r in results]
        if len(scores) < self.min_samples:
            return None
        spread = _stddev(scores)
        if spread < CONSISTENCY_GAP_STDDEV_LINE:
            return None
        return Weakness(
            kind="consistency_gap",
            skill_family=family,
            severity=round(min(1.0, spread / 50.0), 2),
            detail=(
                f"advisory: {family} scores swing by a standard deviation of "
                f"{spread:.1f} points across {len(scores)} runs; the method "
                "works sometimes, which means it is not yet a method"
            ),
        )

    def _context_gap(
        self, family: str, results: list[PracticeResult], scenarios: list[Scenario]
    ) -> Weakness | None:
        by_id = {s.scenario_id: s for s in scenarios}
        rates = self._per_scenario_success(results)
        easy_pass = [
            sid for sid, rate in rates.items()
            if by_id.get(sid) is not None
            and by_id[sid].difficulty <= EASY_DIFFICULTY
            and rate >= EASY_PASS_LINE
        ]
        hard_fail = [
            sid for sid, rate in rates.items()
            if by_id.get(sid) is not None
            and by_id[sid].difficulty >= HARD_DIFFICULTY
            and rate <= HARD_FAIL_LINE
        ]
        if not easy_pass or not hard_fail:
            return None
        easy_rate = _mean([rates[sid] for sid in easy_pass])
        hard_rate = _mean([rates[sid] for sid in hard_fail])
        return Weakness(
            kind="context_gap",
            skill_family=family,
            severity=round(easy_rate - hard_rate, 2),
            detail=(
                f"advisory: {family} passes easy scenarios "
                f"({', '.join(sorted(easy_pass))}) but fails hard ones "
                f"({', '.join(sorted(hard_fail))}); the basics transfer, "
                "the harder context does not"
            ),
        )

    # -- sparring detector ---------------------------------------------------

    @staticmethod
    def _adaptation_gaps(
        sparring_results: list[SparringMatchResult], scenarios: list[Scenario]
    ) -> list[Weakness]:
        by_id = {s.scenario_id: s for s in scenarios}
        weaknesses: list[Weakness] = []
        for match in sparring_results:
            if match.winner != "red":
                continue
            scenario = by_id.get(match.scenario_id)
            # R2-dojo-03: drills resolve via library.filter(skill_family=...),
            # which matches scenario.skill_families; deriving the family from
            # scenario.family emitted weaknesses that could never be drilled
            # (0 focus items, silently). Emit one weakness per ground-truth
            # skill family, same as the other detectors (L-7: nothing is
            # dropped silently).
            families = (
                tuple(scenario.skill_families) if scenario is not None else ()
            )
            if not families:
                families = ("",)
            for family in families:
                weaknesses.append(
                    Weakness(
                        kind="adaptation_gap",
                        skill_family=family,
                        severity=round(min(1.0, match.red_score / 100.0), 2),
                        detail=(
                            f"advisory: red defeated the blue playbook on "
                            f"{match.scenario_id} (red {match.red_score} vs blue "
                            f"{match.blue_score}); the defense chain ran out of "
                            "answers, adaptation is the gap"
                        ),
                    )
                )
        return weaknesses

    # -- entry point ----------------------------------------------------------

    def identify(
        self,
        results: list[PracticeResult],
        scenarios: list[Scenario],
        sparring_results: list[SparringMatchResult] | None = None,
    ) -> list[Weakness]:
        """Advisory weaknesses from measured evidence, never silent (L-7)."""
        findings: list[Weakness] = []
        for family, family_results in sorted(
            self._families(results, scenarios).items()
        ):
            if len(family_results) < self.min_samples:
                continue
            for detector in (
                self._skill_gap,
                self._speed_gap,
                self._consistency_gap,
            ):
                weakness = detector(family, family_results)
                if weakness is not None:
                    findings.append(weakness)
            context = self._context_gap(family, family_results, scenarios)
            if context is not None:
                findings.append(context)
        findings.extend(self._adaptation_gaps(sparring_results or [], scenarios))
        return findings
