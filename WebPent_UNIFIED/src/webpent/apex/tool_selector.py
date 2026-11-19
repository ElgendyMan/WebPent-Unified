"""The Apex Predator — U-APEX-7, the Tool Selector (v87).

Picks the best vetted tool for a capability under the current context.
Scoring = capability gate (a tool without the capability is not a
candidate at all) + weighted components from config/apex/selection.yaml:
speed (APEX-L-8), stealth (raised when the context demands quiet),
historical accuracy from the learning ledger (APEX-L-7), resource fit.
Every selection carries a reason string and its alternatives; identical
inputs produce identical rankings (determinism, ties broken by tool id).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import yaml

from webpent.apex.tool_registry import ToolRegistry, ToolSpec

PREAMBLE_LINE = (
    "advisory: tool selection is a weighted proposal with stated reasons; "
    "the operator approves what actually runs."
)


@dataclass
class ToolSelection:
    """One tool's fitness for a capability, with its evidence."""

    tool_id: str
    reason: str
    score: float
    alternatives: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool_id": self.tool_id,
            "reason": self.reason,
            "score": round(self.score, 4),
            "alternatives": list(self.alternatives),
        }


@dataclass
class SelectionContext:
    """What this run needs: how quiet, that's mostly it."""

    stealth_requirement: str = "low"


class AccuracyLedger(Protocol):
    """Historical success rates, fed by the learning loop (U-APEX-12)."""

    def success_rate(self, tool_id: str) -> float | None: ...


class DictLedger:
    """Ledger backed by a plain mapping — tests and early wiring."""

    def __init__(self, rates: dict[str, float]) -> None:
        self._rates = dict(rates)

    def success_rate(self, tool_id: str) -> float | None:
        return self._rates.get(tool_id)


class ToolSelector:
    """Capability-gated, weighted tool ranking."""

    def __init__(self, config: dict, registry: ToolRegistry) -> None:
        self._cfg = config
        self._registry = registry

    @classmethod
    def load(cls, selection_path: Path, registry: ToolRegistry) -> ToolSelector:
        if not selection_path.is_file():
            raise FileNotFoundError(f"selection file not found: {selection_path}")
        try:
            raw = yaml.safe_load(selection_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(f"broken selection yaml: {exc}") from exc
        if not isinstance(raw, dict) or "profiles" not in raw:
            raise ValueError("selection yaml must define 'profiles'")
        return cls(raw, registry)

    # -- public API -----------------------------------------------------------

    def select(
        self,
        capability: str,
        context: SelectionContext,
        ledger: AccuracyLedger | None = None,
    ) -> ToolSelection:
        candidates = [
            spec for spec in self._registry.list_tools()
            if capability in spec.capabilities
        ]
        if not candidates:
            raise ValueError(
                f"no registered vetted tool provides capability {capability!r}"
            )
        ranked = self.rank(candidates, context, ledger=ledger)
        best = ranked[0]
        return ToolSelection(
            tool_id=best.tool_id,
            reason=best.reason,
            score=best.score,
            alternatives=[s.tool_id for s in ranked[1:]],
        )

    def rank(
        self,
        tools: list[ToolSpec],
        context: SelectionContext,
        ledger: AccuracyLedger | None = None,
    ) -> list[ToolSelection]:
        profile_name = {"low": "low", "medium": "medium", "high": "high"}[
            context.stealth_requirement
        ]
        weights = self._cfg["profiles"][profile_name]
        default_accuracy = float(self._cfg.get("default_accuracy", 0.5))
        scored: list[ToolSelection] = []
        for spec in tools:
            components = self._components(spec, context, ledger, default_accuracy)
            score = sum(
                weights[k] * v for k, v in components.items()
            )
            scored.append(
                ToolSelection(
                    tool_id=spec.id,
                    reason=self._reason(spec, components, context),
                    score=score,
                )
            )
        # deterministic: score desc, then tool id asc for ties
        scored.sort(key=lambda s: (-s.score, s.tool_id))
        return scored

    # -- internals ------------------------------------------------------------

    def _components(
        self,
        spec: ToolSpec,
        context: SelectionContext,
        ledger: AccuracyLedger | None,
        default_accuracy: float,
    ) -> dict[str, float]:
        speed = float(self._cfg["speed_scores"][spec.speed])
        stealth = float(self._cfg["stealth_scores"][spec.stealth])
        resource_name = self._cfg["category_resource"].get(
            spec.category, "medium"
        )
        resource = float(self._cfg["resource_scores"][resource_name])
        rate = ledger.success_rate(spec.id) if ledger else None
        accuracy = (
            max(0.0, min(1.0, float(rate))) if rate is not None
            else default_accuracy
        )
        return {
            "speed": speed,
            "stealth": stealth,
            "accuracy": accuracy,
            "resource": resource,
        }

    def _reason(
        self,
        spec: ToolSpec,
        components: dict[str, float],
        context: SelectionContext,
    ) -> str:
        parts = [f"capability match, speed tier {spec.speed}"]
        if context.stealth_requirement == "high":
            parts.append(f"stealth tier {spec.stealth} weighted up by demand")
        else:
            parts.append(f"stealth tier {spec.stealth}")
        parts.append(f"accuracy {components['accuracy']:.2f}")
        return "; ".join(parts)
