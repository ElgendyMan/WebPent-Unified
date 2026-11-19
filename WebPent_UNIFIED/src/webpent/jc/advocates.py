"""Judgment Council — U-JC-2: the Advocates.

Each existing brain layer becomes one advocate. Advocates are pure
functions of the injected context (L-2): they read their own context key,
build evidence from it and either argue or abstain. Every advocate is
deterministic (JC-L-2) and every argument carries evidence, reasoning,
alternatives and a confidence in [0, 1] (L-4).

Context keys (all optional; absence means the advocate abstains):

    ev_schedule       -> Tactician   [{target_id, ev_per_hour}, ...]
    signals           -> Observer    [{endpoint, description, confidence}, ...]
    ev_per_hour_now   -> Adapter     {lane: float} (+ ev_per_hour_week_ago)
    ev_per_hour_week_ago -> Adapter  {lane: float}
    lessons           -> Historian   [{lesson_id, content, confidence}, ...]
    payload_hints     -> Strategist  [str, ...]
    blocked_paths     -> Resilient   [{lane, fallback}, ...]
    findings_value    -> Economist   [{finding_id, value_usd}, ...]
    now               -> datetime stamp used for deterministic timestamps
    target_id         -> the target under discussion (evidence source)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from webpent.jc.contracts import Argument, Evidence, clamp01, utc

#: Economist: a finding must be worth at least this much (USD) to submit
ECONOMIST_SUBMIT_THRESHOLD_USD = 50.0
#: Adapter: a lane whose EV fell to this ratio of last week's is collapsed
ADAPTER_COLLAPSE_RATIO = 0.5


def _rank_number(value) -> float:
    """Raw-metric sort key for USD/EV domains (R2-jc-02).

    clamp01 would flatten every realistic candidate (value >= 1.0) to
    exactly 1.0 and degenerate the ranking to alphabetical order — the
    Economist/Tactician/Adapter would pick the wrong target.
    """
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return 0.0


def _now_of(context: dict, now: datetime | None = None) -> datetime:
    if now is not None:
        return utc(now)
    return utc(context.get("now"))


def _source_of(context: dict, fallback: str) -> str:
    return str(context.get("target_id") or fallback)[:120]


class Advocate(ABC):
    """Base class: one brain layer, one voice in the chamber."""

    id: str = "advocate"

    @abstractmethod
    def argue(self, context: dict, *, now: datetime | None = None) -> Argument | None:
        """Return the argument, or None to abstain (recorded either way)."""

    def _argue(
        self,
        context: dict,
        *,
        claim: str,
        reasoning: str,
        evidence: list[Evidence],
        confidence: float,
        alternatives: list[str],
        now: datetime | None = None,
    ) -> Argument:
        return Argument(
            advocate_id=self.id,
            claim=claim,
            evidence=evidence,
            reasoning=reasoning,
            confidence=clamp01(confidence, 0.0),
            alternatives=alternatives or ["hold current course"],
            timestamp=_now_of(context, now),
        )


class TacticianAdvocate(Advocate):
    """The EV Scheduler's voice: work the highest EV/hour target."""

    id = "tactician"

    def argue(self, context: dict, *, now: datetime | None = None) -> Argument | None:
        rows = [r for r in (context.get("ev_schedule") or []) if isinstance(r, dict)]
        if not rows:
            return None
        ranked = sorted(
            rows,
            key=lambda r: (-_rank_number(r.get("ev_per_hour")),
                           str(r.get("target_id") or "")),
        )
        top = ranked[0]
        target = str(top.get("target_id") or "unknown")
        try:
            ev = max(0.0, float(top.get("ev_per_hour") or 0.0))
        except (TypeError, ValueError):
            ev = 0.0
        evidence = [
            Evidence(
                kind="metric",
                content=f"target {target} has EV/hour {ev:.2f}",
                source=_source_of(context, "ev_schedule"),
                observed_at=_now_of(context, now),
                confidence=clamp01(top.get("confidence", 0.7), 0.7),
                specificity=0.9,
            )
        ]
        return self._argue(
            context,
            now=now,
            claim=f"work target {target} (highest EV/hour {ev:.2f})",
            reasoning=(
                f"the EV schedule ranks {len(ranked)} target(s); {target} is "
                f"the top by deterministic sort, so it is the best use of time"
            ),
            evidence=evidence,
            confidence=min(1.0, 0.4 + 0.6 * ev),
            alternatives=[str(r.get("target_id")) for r in ranked[1:3] if r.get("target_id")],
        )


class ObserverAdvocate(Advocate):
    """The Curiosity module's voice: investigate the observed signal."""

    id = "observer"

    def argue(self, context: dict, *, now: datetime | None = None) -> Argument | None:
        rows = [r for r in (context.get("signals") or []) if isinstance(r, dict)]
        if not rows:
            return None
        ranked = sorted(
            rows,
            key=lambda r: (-clamp01(r.get("confidence"), 0.0),
                           str(r.get("endpoint") or "")),
        )
        top = ranked[0]
        endpoint = str(top.get("endpoint") or "unknown-endpoint")
        desc = str(top.get("description") or "unusual behavior")[:200]
        conf = clamp01(top.get("confidence"), 0.5)
        evidence = [
            Evidence(
                kind="signal",
                content=f"signal on {endpoint}: {desc}",
                source=_source_of(context, "curiosity"),
                observed_at=_now_of(context, now),
                confidence=conf,
                specificity=1.0,
            )
        ]
        return self._argue(
            context,
            now=now,
            claim=f"investigate the signal on {endpoint}",
            reasoning=(
                f"a live signal ({desc}) was observed directly; direct "
                f"observations outrank projections until disproven"
            ),
            evidence=evidence,
            confidence=0.3 + 0.7 * conf,
            alternatives=[str(r.get("endpoint")) for r in ranked[1:3] if r.get("endpoint")],
        )


class AdapterAdvocate(Advocate):
    """The Adaptation module's voice: switch a lane whose EV collapsed
    to ADAPTER_COLLAPSE_RATIO (50%) of last week's value."""

    id = "adapter"

    def argue(self, context: dict, *, now: datetime | None = None) -> Argument | None:
        now_map = context.get("ev_per_hour_now")
        week_map = context.get("ev_per_hour_week_ago")
        if not isinstance(now_map, dict) or not isinstance(week_map, dict):
            return None
        lanes = sorted(set(now_map) & set(week_map))
        fell: list[tuple[str, float, float]] = []
        for lane in lanes:
            try:
                ev_now = float(now_map[lane])
                ev_before = float(week_map[lane])
            except (TypeError, ValueError):
                continue
            if ev_before > 0 and ev_now <= ADAPTER_COLLAPSE_RATIO * ev_before:
                fell.append((lane, ev_now, ev_before))
        if not fell:
            return None
        lane, ev_now, ev_before = sorted(fell)[0]
        best_other = max(
            (x for x in lanes if x != lane),
            key=lambda x: (_rank_number(now_map[x]), x),
            default=None,
        )
        switch = f"switch to lane {best_other}" if best_other else "pause and re-plan"
        evidence = [
            Evidence(
                kind="metric",
                content=(
                    f"lane {lane} EV/hour fell to {ev_now:.2f} from "
                    f"{ev_before:.2f} within a week"
                ),
                source=_source_of(context, "adaptation"),
                observed_at=_now_of(context, now),
                confidence=0.8,
                specificity=0.9,
            )
        ]
        return self._argue(
            context,
            now=now,
            claim=f"stop working lane {lane}; {switch}",
            reasoning=(
                "a 50%+ weekly EV collapse is the documented adaptation "
                "trigger; continuing a collapsed lane wastes budget"
            ),
            evidence=evidence,
            confidence=0.7,
            alternatives=[switch, f"keep lane {lane} one more day"],
        )


class HistorianAdvocate(Advocate):
    """The Lessons ledger's voice: apply what previous rounds taught."""

    id = "historian"

    def argue(self, context: dict, *, now: datetime | None = None) -> Argument | None:
        rows = [r for r in (context.get("lessons") or []) if isinstance(r, dict)]
        if not rows:
            return None
        ranked = sorted(
            rows,
            key=lambda r: (-clamp01(r.get("confidence"), 0.0),
                           str(r.get("lesson_id") or "")),
        )
        top = ranked[0]
        lesson_id = str(top.get("lesson_id") or "L?")
        content = str(top.get("content") or "")[:200]
        conf = clamp01(top.get("confidence"), 0.5)
        evidence = [
            Evidence(
                kind="lesson",
                content=f"lesson {lesson_id}: {content}",
                source=_source_of(context, "lessons"),
                observed_at=_now_of(context, now),
                confidence=conf,
                specificity=0.7,
            )
        ]
        return self._argue(
            context,
            now=now,
            claim=f"apply lesson {lesson_id} here",
            reasoning=(
                f"a recorded lesson says: {content}. Ignoring recorded "
                "experience repeats known mistakes"
            ),
            evidence=evidence,
            confidence=0.3 + 0.5 * conf,
            alternatives=[str(r.get("lesson_id")) for r in ranked[1:3] if r.get("lesson_id")],
        )


class StrategistAdvocate(Advocate):
    """The Payload Selector's voice: use the hinted payload."""

    id = "strategist"

    def argue(self, context: dict, *, now: datetime | None = None) -> Argument | None:
        hints = [str(h)[:200] for h in (context.get("payload_hints") or []) if str(h).strip()]
        if not hints:
            return None
        payload = hints[0]
        evidence = [
            Evidence(
                kind="prior",
                content=f"payload hint: {payload}",
                source=_source_of(context, "payload_selector"),
                observed_at=_now_of(context, now),
                confidence=0.6,
                specificity=0.8,
            )
        ]
        return self._argue(
            context,
            now=now,
            claim=f"use payload {payload}",
            reasoning=(
                "the payload selector ranks this payload first for the "
                "current class; a ranked prior beats an unranked guess"
            ),
            evidence=evidence,
            confidence=0.5,
            alternatives=hints[1:3],
        )


class ResilientAdvocate(Advocate):
    """The Blocked-Path module's voice: a fallback exists if this blocks."""

    id = "resilient"

    def argue(self, context: dict, *, now: datetime | None = None) -> Argument | None:
        rows = [r for r in (context.get("blocked_paths") or []) if isinstance(r, dict)]
        if not rows:
            return None
        first = rows[0]
        lane = str(first.get("lane") or "current-lane")
        fallback = str(first.get("fallback") or "re-plan")[:200]
        evidence = [
            Evidence(
                kind="prior",
                content=f"lane {lane} has a prepared fallback: {fallback}",
                source=_source_of(context, "blocked_paths"),
                observed_at=_now_of(context, now),
                confidence=0.6,
                specificity=0.7,
            )
        ]
        return self._argue(
            context,
            now=now,
            claim=f"if lane {lane} blocks, fall back to {fallback}",
            reasoning=(
                "planning the fallback before the block happens converts a "
                "dead end into a detour; blocked-path memory exists for this"
            ),
            evidence=evidence,
            confidence=0.4,
            alternatives=[str(r.get("fallback")) for r in rows[1:3] if r.get("fallback")],
        )


class EconomistAdvocate(Advocate):
    """The ROI/Economist's voice: value the finding before spending time."""

    id = "economist"

    def argue(self, context: dict, *, now: datetime | None = None) -> Argument | None:
        rows = [r for r in (context.get("findings_value") or []) if isinstance(r, dict)]
        if not rows:
            return None
        ranked = sorted(
            rows,
            key=lambda r: (-_rank_number(r.get("value_usd")),
                           str(r.get("finding_id") or "")),
        )
        top = ranked[0]
        finding = str(top.get("finding_id") or "F?")
        try:
            value = max(0.0, float(top.get("value_usd") or 0.0))
        except (TypeError, ValueError):
            value = 0.0
        verdict_word = (
            "submit"
            if value >= ECONOMIST_SUBMIT_THRESHOLD_USD
            else "park (low value)"
        )
        evidence = [
            Evidence(
                kind="metric",
                content=f"finding {finding} is valued at {value:.2f} USD",
                source=_source_of(context, "roi_optimizer"),
                observed_at=_now_of(context, now),
                confidence=0.7,
                specificity=0.9,
            )
        ]
        return self._argue(
            context,
            now=now,
            claim=f"finding {finding}: {verdict_word} (value {value:.2f} USD)",
            reasoning=(
                "the ROI valuation is the spend/stop boundary; time spent "
                "below it is time taken from better targets"
            ),
            evidence=evidence,
            confidence=0.6,
            alternatives=[str(r.get("finding_id")) for r in ranked[1:3] if r.get("finding_id")],
        )


#: the seven default advocates, in chamber seating order
DEFAULT_ADVOCATES: tuple[type[Advocate], ...] = (
    TacticianAdvocate,
    ObserverAdvocate,
    AdapterAdvocate,
    HistorianAdvocate,
    StrategistAdvocate,
    ResilientAdvocate,
    EconomistAdvocate,
)


def build_default_advocates() -> list[Advocate]:
    """Instantiate the seven default advocates."""
    return [cls() for cls in DEFAULT_ADVOCATES]


def all_advocate_ids() -> list[str]:
    """The seating order ids of the default chamber."""
    return [cls.id for cls in DEFAULT_ADVOCATES]


__all__ = [
    "DEFAULT_ADVOCATES",
    "Advocate",
    "AdapterAdvocate",
    "EconomistAdvocate",
    "HistorianAdvocate",
    "ObserverAdvocate",
    "ResilientAdvocate",
    "StrategistAdvocate",
    "TacticianAdvocate",
    "all_advocate_ids",
    "build_default_advocates",
]
