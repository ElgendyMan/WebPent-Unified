"""Bounded state-transition model for business-logic research."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StateSnapshot(BaseModel):
    """Named state with bounded, non-sensitive labels only."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    state_id: str = Field(..., min_length=1, max_length=160)
    label: str = Field(..., min_length=1, max_length=200)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))


class StateTransition(BaseModel):
    """Observed or planned transition metadata, not an executable action."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    source_state_id: str = Field(..., min_length=1, max_length=160)
    target_state_id: str = Field(..., min_length=1, max_length=160)
    operation: str = Field(..., min_length=1, max_length=160)
    observed: bool = False
    invariant_refs: list[str] = Field(default_factory=list, max_length=16)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("invariant_refs", "evidence_refs")
    @classmethod
    def _unique_refs(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))


class StateModel(BaseModel):
    """Target-scoped state machine projection for bounded planning."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int = 1
    engagement_id: str = Field(..., min_length=1, max_length=200)
    target_id: str = Field(..., min_length=1, max_length=200)
    states: dict[str, StateSnapshot] = Field(default_factory=dict)
    transitions: list[StateTransition] = Field(default_factory=list, max_length=512)

    def add_state(self, state: StateSnapshot) -> None:
        self.states[state.state_id] = state

    def add_transition(self, transition: StateTransition) -> None:
        if (
            transition.source_state_id not in self.states
            or transition.target_state_id not in self.states
        ):
            raise ValueError("state_transition_requires_known_states")
        if transition not in self.transitions:
            self.transitions.append(transition)

    def candidate_invariants(self) -> list[str]:
        """List only explicitly referenced invariants, without judging them."""
        return sorted({ref for item in self.transitions for ref in item.invariant_refs})[:32]

    def evidence_refs(self) -> list[str]:
        return sorted(
            {ref for state in self.states.values() for ref in state.evidence_refs}
            | {ref for transition in self.transitions for ref in transition.evidence_refs}
        )[:64]


__all__ = ["StateModel", "StateSnapshot", "StateTransition"]
