"""Proposal-only planner boundary for optional LLM assistance."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from webpent.shared.copilot_boundary import sanitize_copilot_suggestion


class LLMPlanner:
    """Turn a bounded context into advisory research proposals only."""

    def __init__(self) -> None:
        self.boundary = sanitize_copilot_suggestion

    def propose(
        self,
        context: Mapping[str, Any],
        *,
        candidate_actions: Sequence[Mapping[str, Any]] = (),
    ) -> list[dict[str, Any]]:
        _ = {
            key: value
            for key, value in context.items()
            if key in {"knowledge_gaps", "coverage_gaps", "target_dimensions", "query"}
        }
        proposals: list[dict[str, Any]] = []
        for raw in candidate_actions:
            if not isinstance(raw, Mapping):
                continue
            proposal = self.boundary(
                {
                    "action_class": raw.get("action_class", "information_gathering"),
                    "target_ref": raw.get("target_ref", raw.get("target", "")),
                    "reason": raw.get("reason", "planner proposal"),
                    "expected_information_gain": raw.get("expected_information_gain", 0.0),
                    "evidence_refs": raw.get("evidence_refs", []),
                }
            )
            if proposal is not None:
                proposals.append(proposal)
        return proposals


__all__ = ["LLMPlanner"]
