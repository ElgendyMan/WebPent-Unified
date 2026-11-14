"""Adversarial, deterministic mutations for IRTA generated target contracts.

Mutations model misleading but bounded target behavior. They only return new
immutable specifications; they never execute HTTP requests or rewrite truth.
"""

from __future__ import annotations

from dataclasses import replace
from enum import StrEnum

from .models import GeneratedRoute, GeneratedTarget


class MutationKind(StrEnum):
    DENIAL_AS_EMPTY_SUCCESS = "denial_as_empty_success"
    SAME_STATUS_DIFFERENT_SEMANTICS = "same_status_different_semantics"
    PERMISSION_ALIAS = "permission_alias"
    PARTIAL_OBJECT_ACCESS = "partial_object_access"


class AdversarialMutator:
    """Apply one named mutation to a target specification deterministically."""

    def mutate(self, target: GeneratedTarget, kind: MutationKind) -> GeneratedTarget:
        target.validate()
        if not isinstance(kind, MutationKind):
            raise ValueError("unknown mutation kind")
        routes = tuple(self._mutate_route(route, kind) for route in target.routes)
        mutated = replace(
            target,
            routes=routes,
            metadata={
                **target.metadata,
                "mutation": kind.value,
                "base_digest": target.digest(),
            },
        )
        mutated.validate()
        return mutated

    @staticmethod
    def _mutate_route(route: GeneratedRoute, kind: MutationKind) -> GeneratedRoute:
        if kind is MutationKind.DENIAL_AS_EMPTY_SUCCESS:
            return replace(route, response_profile="empty_success_on_denial")
        if kind is MutationKind.SAME_STATUS_DIFFERENT_SEMANTICS:
            return replace(route, response_profile="same_status_semantic_denial")
        if kind is MutationKind.PERMISSION_ALIAS:
            return replace(route, required_permission=f"alias:{route.required_permission}")
        if kind is MutationKind.PARTIAL_OBJECT_ACCESS:
            return replace(route, response_profile="partial_object_disclosure")
        raise ValueError("unsupported mutation")


def mutate_target(target: GeneratedTarget, kind: MutationKind) -> GeneratedTarget:
    """Functional wrapper for benchmark composition."""

    return AdversarialMutator().mutate(target, kind)
