"""Versioned, target-neutral workflow contracts.

Adapters may expose a compatibility mapping from legacy target-local identifiers
into these values. The shared runner depends only on these generic concepts and
never on a target's historical workflow names.
"""

from __future__ import annotations

from typing import Final

WORKFLOW_CONTRACT_VERSION: Final[str] = "workflow-contract.v2"

READ_ONLY_NAVIGATION: Final[str] = "read_only_navigation"
TYPED_SEARCH: Final[str] = "typed_search"
AUTHORIZED_API_READ: Final[str] = "authorized_api_read"
BROWSER_DOM_OBSERVATION: Final[str] = "browser_dom_observation"
SAME_ORIGIN_RESOURCE_OBSERVATION: Final[str] = "same_origin_resource_observation"

# Compatibility names remain accepted at adapter boundaries, but new adapters
# should declare the v2 concepts above. No alias is inferred from a URL.
AUTHORIZED_API_REQUEST: Final[str] = "authorized_api_request"
BROWSER_OBSERVATION: Final[str] = "browser_observation"

WORKFLOW_MIGRATION_ALIASES: Final[dict[str, str]] = {
    AUTHORIZED_API_REQUEST: AUTHORIZED_API_READ,
    BROWSER_OBSERVATION: BROWSER_DOM_OBSERVATION,
}

CANONICAL_WORKFLOW_IDS: Final[frozenset[str]] = frozenset(
    {
        READ_ONLY_NAVIGATION,
        TYPED_SEARCH,
        AUTHORIZED_API_READ,
        BROWSER_DOM_OBSERVATION,
        SAME_ORIGIN_RESOURCE_OBSERVATION,
    }
)

SUPPORTED_WORKFLOW_IDS: Final[frozenset[str]] = frozenset(
    set(CANONICAL_WORKFLOW_IDS) | set(WORKFLOW_MIGRATION_ALIASES)
)


def canonical_workflow_id(workflow_id: str) -> str | None:
    """Return the v2 workflow ID, or ``None`` for an unknown identifier."""
    candidate = str(workflow_id or "").strip()
    if not candidate:
        return None
    if candidate not in SUPPORTED_WORKFLOW_IDS:
        return None
    return WORKFLOW_MIGRATION_ALIASES.get(candidate, candidate)


__all__ = [
    "AUTHORIZED_API_READ",
    "AUTHORIZED_API_REQUEST",
    "BROWSER_DOM_OBSERVATION",
    "BROWSER_OBSERVATION",
    "CANONICAL_WORKFLOW_IDS",
    "READ_ONLY_NAVIGATION",
    "SAME_ORIGIN_RESOURCE_OBSERVATION",
    "SUPPORTED_WORKFLOW_IDS",
    "TYPED_SEARCH",
    "WORKFLOW_CONTRACT_VERSION",
    "WORKFLOW_MIGRATION_ALIASES",
    "canonical_workflow_id",
]
