"""Judgment Council — U-JC-1: the Council Chamber.

The infrastructure that makes the debate possible: sessions are convened
over a question + injected context, advocates submit arguments, the skeptic
challenges, and ``close()`` asks the judge for a verdict. Everything is
local and deterministic (JC-L-2, L-2, L-3): the session id is a hash of the
question and context, so the same debate always opens the same session.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from webpent.jc.contracts import (
    Argument,
    CouncilSession,
    Verdict,
    context_hash,
    deterministic_id,
    utc,
)

_LOG = logging.getLogger(__name__)

#: defaults for config/jc/council.yaml; a missing/corrupt file fails soft
COUNCIL_DEFAULTS: dict[str, Any] = {
    "max_debate_rounds": 3,
    "time_limit_seconds": 30,
    "min_advocates": 3,
    "require_skeptic": True,
    "require_judge": True,
    "confidence_thresholds": {"high": 0.85, "medium": 0.60},
    "escalation": {
        "on_low_confidence": True,
        "on_tie": True,
        "on_missing_judge": True,
    },
}


def load_council_config(path: Any) -> dict[str, Any]:
    """Load config/jc/council.yaml over the defaults; corrupt -> defaults."""
    import contextlib

    config = {
        "max_debate_rounds": COUNCIL_DEFAULTS["max_debate_rounds"],
        "time_limit_seconds": COUNCIL_DEFAULTS["time_limit_seconds"],
        "min_advocates": COUNCIL_DEFAULTS["min_advocates"],
        "require_skeptic": COUNCIL_DEFAULTS["require_skeptic"],
        "require_judge": COUNCIL_DEFAULTS["require_judge"],
        "confidence_thresholds": dict(COUNCIL_DEFAULTS["confidence_thresholds"]),
        "escalation": dict(COUNCIL_DEFAULTS["escalation"]),
    }
    if path is None:
        return config
    try:
        import yaml

        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return config
    except Exception as exc:  # noqa: BLE001 - fail-soft by charter
        _LOG.warning("council config unreadable; using defaults: %s", exc)
        return config
    block = raw.get("council") if isinstance(raw, dict) else None
    if not isinstance(block, dict):
        return config
    for key in ("max_debate_rounds", "time_limit_seconds", "min_advocates"):
        with contextlib.suppress(TypeError, ValueError):
            config[key] = max(0, int(block.get(key, config[key])))
    for key in ("require_skeptic", "require_judge"):
        config[key] = bool(block.get(key, config[key]))
    thresholds = block.get("confidence_thresholds")
    if isinstance(thresholds, dict):
        with contextlib.suppress(TypeError, ValueError):
            config["confidence_thresholds"]["high"] = float(
                thresholds.get("high", config["confidence_thresholds"]["high"])
            )
            config["confidence_thresholds"]["medium"] = float(
                thresholds.get("medium", config["confidence_thresholds"]["medium"])
            )
    escalation = block.get("escalation")
    if isinstance(escalation, dict):
        for key in ("on_low_confidence", "on_tie", "on_missing_judge"):
            config["escalation"][key] = bool(escalation.get(key, True))
    return config


@dataclass
class ChamberRole:
    """Who is seated in the chamber for a session (ids only, L-4)."""

    advocates: list[str] = field(default_factory=list)
    skeptic_id: str | None = None
    judge_id: str | None = None


class CouncilChamber:
    """Convenes sessions, collects arguments, closes with a verdict."""

    #: sentinel: "caller did not say" -> seat the default council
    _UNSET = object()

    def __init__(
        self,
        skeptic: Any = _UNSET,
        judge: Any = _UNSET,
        *,
        config_path: Any = None,
        now: datetime | None = None,
    ) -> None:
        self.skeptic = skeptic
        self.judge = judge
        self.config = load_council_config(config_path)
        base = now or datetime.now(timezone.utc)
        self._now = base if base.tzinfo else base.replace(tzinfo=timezone.utc)
        self._sessions: dict[str, CouncilSession] = {}
        # seat the default council when the caller did not say (require_*)
        if skeptic is CouncilChamber._UNSET and self.config["require_skeptic"]:
            from webpent.jc.skeptic import Skeptic

            self.skeptic = Skeptic(now=self._now)
        if judge is CouncilChamber._UNSET and self.config["require_judge"]:
            from webpent.jc.judge import Judge

            self.judge = Judge()
        # R2-jc-01: an explicitly DISABLED role must seat None, not the
        # _UNSET sentinel — close() checks ``is not None`` and would
        # otherwise call methods on the raw sentinel object
        # (AttributeError: 'object' object has no attribute ...).
        if skeptic is CouncilChamber._UNSET and not self.config["require_skeptic"]:
            self.skeptic = None
        if judge is CouncilChamber._UNSET and not self.config["require_judge"]:
            self.judge = None

    # ------------------------------------------------------------ convene
    def convene(self, question: str, context: dict) -> CouncilSession:
        """Open a session; unknown/empty question or context is rejected."""
        if not str(question or "").strip():
            raise ValueError("a session needs a question")
        if not isinstance(context, dict) or not context:
            raise ValueError("a session needs a non-empty context dict")
        session_id = deterministic_id(question, context_hash(context))
        session = CouncilSession(
            session_id=session_id,
            question=str(question)[:300],
            context=dict(context),
            started_at=self._now,
            deadline=self._now + timedelta(
                seconds=float(self.config["time_limit_seconds"])
            ),
        )
        self._sessions[session_id] = session
        return session

    # ------------------------------------------------------------ debate
    def submit_argument(self, session_id: str, arg: Argument) -> None:
        """File one advocate's argument into an open session."""
        if session_id not in self._sessions:
            raise ValueError(f"unknown session {session_id!r}")
        session = self._sessions[session_id]
        if session.closed:
            raise ValueError(f"session {session_id} is closed")
        if not isinstance(arg, Argument):
            raise ValueError(
                f"submit an Argument, not {type(arg).__name__}"
            )
        # R2-jc-06: one argument per advocate per session. The judge's
        # summary is keyed by advocate_id, so a re-submission would
        # silently erase the advocate's earlier (possibly stronger)
        # argument from the verdict while its challenges still count.
        if any(a.advocate_id == arg.advocate_id for a in session.arguments):
            raise ValueError(
                f"advocate {arg.advocate_id!r} already argued in this session"
            )
        rounds = -(-len(session.arguments) // max(1, self.config["min_advocates"]))
        if rounds >= max(1, self.config["max_debate_rounds"]):
            raise ValueError(
                f"debate limit reached ({self.config['max_debate_rounds']} rounds)"
            )
        session.arguments.append(arg)

    def get_session(self, session_id: str) -> CouncilSession:
        if session_id not in self._sessions:
            raise ValueError(f"unknown session {session_id!r}")
        return self._sessions[session_id]

    # -------------------------------------------------------------- close
    def close(self, session_id: str, *, now: datetime | None = None) -> Verdict:
        """Challenge, judge and seal the session; returns the verdict."""
        if session_id not in self._sessions:
            raise ValueError(f"unknown session {session_id!r}")
        session = self._sessions[session_id]
        if session.closed and session.verdict is not None:
            return session.verdict
        close_at = utc(now) if now is not None else self._now
        reasons: list[str] = []

        if len(session.arguments) < int(self.config["min_advocates"]):
            reasons.append(
                f"only {len(session.arguments)} advocate(s) argued; "
                f"minimum is {self.config['min_advocates']}"
            )

        # the skeptic challenges every argument (JC-L-4: every voice heard)
        if self.skeptic is not None:
            session.challenges.extend(
                self.skeptic.challenge_all(session.arguments, session.context)
            )
        elif self.config["require_skeptic"]:
            reasons.append("skeptic absent while require_skeptic is true")

        if self.judge is None:
            if self.config["require_judge"] and self.config["escalation"][
                "on_missing_judge"
            ]:
                reasons.append("no judge seated while require_judge is true")
            verdict = Verdict(
                action="none",
                reasoning="; ".join(reasons) or "no judge available",
                confidence=0.0,
                confidence_tier="low",
                dissent=[],
                escalate=True,
                escalation_reason="; ".join(reasons) or "no judge available",
                advocates_summary={},
                session_id=session_id,
                timestamp=close_at,
            )
        else:
            verdict = self.judge.rule(session, now=close_at)
            if reasons:
                verdict.escalate = True
                merged = "; ".join(reasons)
                verdict.escalation_reason = (
                    merged if not verdict.escalation_reason
                    else f"{verdict.escalation_reason}; {merged}"
                )
        # a debate that ran past its logical time limit always escalates
        if session.deadline is not None and close_at > session.deadline:
            verdict.escalate = True
            overdue = (f"time limit exceeded "
                       f"({self.config['time_limit_seconds']}s)")
            verdict.escalation_reason = (
                overdue if not verdict.escalation_reason
                else f"{verdict.escalation_reason}; {overdue}"
            )
        session.verdict = verdict
        session.closed = True
        return verdict


__all__ = [
    "COUNCIL_DEFAULTS",
    "ChamberRole",
    "CouncilChamber",
    "load_council_config",
]
