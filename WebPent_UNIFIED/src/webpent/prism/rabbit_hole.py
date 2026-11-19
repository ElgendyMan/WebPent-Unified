"""THE PRISM — U-PRISM-10, the Rabbit Hole Protector (v89).

"The clever fall into rabbit holes because they are curious. The wise
know when to leave." Five deterministic detection rules — depth, time,
diminishing returns, sunk cost, and known hole patterns — each returning
a clear recommendation (PRISM-L-7: rabbit holes are losses). Advisory
only (PRISM-L-2), fully offline and deterministic (PRISM-L-9).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from webpent.prism.errors import PrismLawError

RECOMMENDATIONS = ("continue", "pause", "abandon")


@dataclass(frozen=True)
class ExplorationState:
    depth: int
    time_spent_hours: float
    requests_spent: int
    # one entry per recent step, True when it produced NEW evidence
    recent_new_evidence: tuple[bool, ...] = ()
    reason_for_continuing: str = ""


@dataclass(frozen=True)
class Signal:
    signal_id: str
    anomaly_type: str


@dataclass(frozen=True)
class RabbitHolePattern:
    name: str
    note: str


@dataclass(frozen=True)
class RabbitHoleCheck:
    signal_id: str
    is_hole: bool
    depth: int
    time_spent_hours: float
    requests_spent: int
    diminishing_returns: bool
    sunk_cost_warning: bool
    recommendation: str
    reasoning: str
    mode: str = "advisory-only (PRISM-L-2)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "is_hole": self.is_hole,
            "depth": self.depth,
            "time_spent_hours": round(self.time_spent_hours, 6),
            "requests_spent": self.requests_spent,
            "diminishing_returns": self.diminishing_returns,
            "sunk_cost_warning": self.sunk_cost_warning,
            "recommendation": self.recommendation,
            "reasoning": self.reasoning,
            "mode": self.mode,
        }


class RabbitHoleProtector:
    """Five-rule rabbit hole detection (U-PRISM-10)."""

    def __init__(self, config_path: Path | str) -> None:
        path = Path(config_path)
        if not path.is_file():
            raise PrismLawError(
                f"curiosity params not found: {path}", law="PRISM-L-4"
            )
        config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        block = config.get("rabbit_hole")
        if not isinstance(block, dict):
            raise PrismLawError(
                "curiosity params: missing 'rabbit_hole' block",
                law="PRISM-L-4",
            )
        for key in ("max_depth", "max_time_hours", "diminishing_window"):
            value = block.get(key)
            if not isinstance(value, (int, float)) or value <= 0:
                raise PrismLawError(
                    f"rabbit_hole: '{key}' must be a positive number",
                    law="PRISM-L-1",
                )
        holes = config.get("known_holes")
        if not isinstance(holes, list) or not holes:
            raise PrismLawError(
                "curiosity params: known_holes must be a non-empty list",
                law="PRISM-L-4",
            )
        self._patterns = tuple(
            RabbitHolePattern(name=str(h["name"]), note=str(h.get("note", "")))
            for h in holes
        )
        self._config = block

    @property
    def max_depth(self) -> int:
        return int(self._config["max_depth"])

    @property
    def max_time_hours(self) -> float:
        return float(self._config["max_time_hours"])

    def get_patterns(self) -> list[RabbitHolePattern]:
        return list(self._patterns)

    def _matches_known_hole(self, signal: Signal) -> bool:
        return any(p.name == signal.anomaly_type for p in self._patterns)

    def check(self, signal: Signal,
              state: ExplorationState) -> RabbitHoleCheck:
        window = int(self._config["diminishing_window"])
        sunk_markers = [
            str(m) for m in self._config.get("sunk_cost_markers", [])
        ]

        # rule 1: depth
        if state.depth > self.max_depth:
            return self._result(signal, state, is_hole=True,
                                recommendation="pause",
                                diminishing=False, sunk=False,
                                reasoning=(
                    f"depth {state.depth} exceeds max_depth "
                    f"{self.max_depth}; pausing before the hole deepens"
                ))
        # rule 2: time
        if state.time_spent_hours > self.max_time_hours:
            return self._result(signal, state, is_hole=True,
                                recommendation="pause",
                                diminishing=False, sunk=False,
                                reasoning=(
                    f"time_spent {state.time_spent_hours:.2f}h exceeds "
                    f"max_time_hours {self.max_time_hours:.2f}h; pausing"
                ))
        # rule 3: diminishing returns
        recent = state.recent_new_evidence[-window:] if window > 0 else ()
        if len(recent) >= window and not any(recent):
            return self._result(signal, state, is_hole=True,
                                recommendation="abandon",
                                diminishing=True, sunk=False,
                                reasoning=(
                    f"the last {window} steps produced no new evidence; "
                    f"diminishing returns — abandoning"
                ))
        # rule 4: sunk cost
        reason = state.reason_for_continuing.lower()
        if reason and any(marker in reason for marker in sunk_markers):
            return self._result(signal, state, is_hole=True,
                                recommendation="abandon",
                                diminishing=False, sunk=True,
                                reasoning=(
                    "the stated reason to continue is sunk cost "
                    f"({state.reason_for_continuing!r}); abandoning"
                ))
        # rule 5: known hole pattern
        if self._matches_known_hole(signal):
            return self._result(signal, state, is_hole=True,
                                recommendation="abandon",
                                diminishing=False, sunk=False,
                                reasoning=(
                    f"signal type {signal.anomaly_type!r} matches a known "
                    f"hole pattern; abandoning"
                ))
        return self._result(signal, state, is_hole=False,
                            recommendation="continue",
                            diminishing=False, sunk=False,
                            reasoning=(
                f"depth {state.depth}/{self.max_depth}, "
                f"time {state.time_spent_hours:.2f}h/"
                f"{self.max_time_hours:.2f}h, recent progress present; "
                f"no hole indicators"
            ))

    @staticmethod
    def _result(signal: Signal, state: ExplorationState, is_hole: bool,
                recommendation: str, diminishing: bool, sunk: bool,
                reasoning: str) -> RabbitHoleCheck:
        return RabbitHoleCheck(
            signal_id=signal.signal_id,
            is_hole=is_hole,
            depth=state.depth,
            time_spent_hours=state.time_spent_hours,
            requests_spent=state.requests_spent,
            diminishing_returns=diminishing,
            sunk_cost_warning=sunk,
            recommendation=recommendation,
            reasoning=reasoning,
        )


__all__ = ["RECOMMENDATIONS", "ExplorationState", "RabbitHoleCheck",
           "RabbitHolePattern", "RabbitHoleProtector", "Signal"]
