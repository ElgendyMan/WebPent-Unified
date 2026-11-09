"""Cache-poisoning detector package (P2-302)."""

from webpent.agents.cache_poisoning.agent import (
    analyze_cache_differential,
    build_cache_key_probes,
)

__all__ = ["analyze_cache_differential", "build_cache_key_probes"]
