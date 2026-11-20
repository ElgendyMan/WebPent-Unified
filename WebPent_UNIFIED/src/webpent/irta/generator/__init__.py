"""Independent target generation and mutation contracts for IRTA v2."""

from .generator import IndependentTargetGenerator, generate_target
from .models import (
    GeneratedIdentity,
    GeneratedObject,
    GeneratedRole,
    GeneratedRoute,
    GeneratedTarget,
    VulnerabilityClass,
)
from .mutations import AdversarialMutator, MutationKind, mutate_target

__all__ = [
    "GeneratedIdentity",
    "GeneratedObject",
    "GeneratedRole",
    "GeneratedRoute",
    "GeneratedTarget",
    "AdversarialMutator",
    "IndependentTargetGenerator",
    "MutationKind",
    "VulnerabilityClass",
    "generate_target",
    "mutate_target",
]
