"""Planning/report-safe identity matrix facade.

Execution and confirmation remain owned by the existing ActionAuthority,
CampaignExecutor, and sealed ProofBundle/replay validators.
"""

from .matrix import build_identity_matrix
from .models import (
    AccessExpectation,
    ComparisonKind,
    IdentityActor,
    IdentityComparison,
    IdentityMatrix,
    IdentityObservation,
    IdentityRole,
    OwnershipRelation,
)

__all__ = [
    "AccessExpectation",
    "ComparisonKind",
    "IdentityActor",
    "IdentityComparison",
    "IdentityMatrix",
    "IdentityObservation",
    "IdentityRole",
    "OwnershipRelation",
    "build_identity_matrix",
]
