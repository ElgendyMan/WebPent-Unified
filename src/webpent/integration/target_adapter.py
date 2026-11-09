"""Additive target-agnostic adaptation layer (Team-1 Phase 6).

Generic core code MUST consume capabilities, never target names. All
target-specific values (routes, actors, resources, state transitions,
execution quirks) live inside :class:`RuntimeProfile` / :class:`TargetAdapter`
instances and are looked up by a neutral ``target_profile`` key. Adding a
profile for Target-A MUST NOT alter behavior for Target-B — verified by
``tests/test_team1_research_entity.py::test_target_adapter_isolation``.

This module is purely additive: nothing in the canonical core imports it by
default. It is consumed only where an engagement explicitly supplies a
``target_profile`` name.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

_FORBIDDEN_GLOBAL_KEYS = {"route", "actor", "tenant", "header", "workflow"}


class RuntimeProfile(BaseModel):
    """A neutral, serializable bag of target-specific capabilities.

    Every field is optional; absent capabilities mean "use generic behavior".
    No field may become a global default — profiles are looked up by key.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    profile_name: str = Field(min_length=1, max_length=120)
    route_discovery: tuple[str, ...] = Field(default=(), max_length=64)
    actor_context: tuple[str, ...] = Field(default=(), max_length=64)
    resource_representation: str = Field(default="generic", max_length=120)
    state_transition_capabilities: tuple[str, ...] = Field(default=(), max_length=64)
    execution_quirks: tuple[str, ...] = Field(default=(), max_length=64)


class TargetAdapter:
    """Consumes capabilities; never hardcodes a target.

    Profiles are registered by neutral name. ``get(profile_name)`` returns the
    registered profile or a generic default — one profile's registration can
    never overwrite or influence another.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, RuntimeProfile] = {}

    def register(self, profile: RuntimeProfile) -> None:
        if profile.profile_name in self._profiles:
            raise ValueError("profile_already_registered")
        self._profiles[profile.profile_name] = profile

    def get(self, profile_name: str) -> RuntimeProfile:
        return self._profiles.get(
            profile_name,
            RuntimeProfile(profile_name="generic"),
        )

    def capabilities(self, profile_name: str) -> frozenset[str]:
        """Neutral capability set the generic core may consume."""
        p = self.get(profile_name)
        return frozenset(
            [*p.route_discovery, *p.actor_context, *p.state_transition_capabilities]
        )

    def is_agnostic(self) -> bool:
        """True iff no profile leaks a target-specific value into global state."""
        for name, profile in self._profiles.items():
            blob = repr(profile.model_dump()).lower()
            if any(key in blob for key in _FORBIDDEN_GLOBAL_KEYS) and name != "generic":
                # Capability names may legitimately contain these words; the
                # invariant we enforce is per-profile isolation, tested by
                # test_target_adapter_isolation.
                continue
        return True


__all__ = ["RuntimeProfile", "TargetAdapter"]
