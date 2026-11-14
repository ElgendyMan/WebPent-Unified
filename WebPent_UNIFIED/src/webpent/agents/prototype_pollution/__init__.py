"""Prototype-pollution detector package (P2-301)."""

from webpent.agents.prototype_pollution.agent import (
    analyze_reflection_pair,
    build_pollution_payload_set,
    build_pollution_probes,
)

__all__ = ["analyze_reflection_pair", "build_pollution_payload_set", "build_pollution_probes"]
