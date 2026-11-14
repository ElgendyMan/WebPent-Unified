"""Role authorization matrix (PROPOSALS_ULTIMATE_V2 §4, 2026-10-30).

Flag-gated (enable_role_matrix, default False). An execution layer on
top of ``webpent.shared.bac_identity_tester``: verified role sessions,
a deterministic (subject, foreign-resource) pair builder, and the
three-probe differential (owner / subject / anonymous control) feeding
the existing classifier instead of reinventing it.
"""

from .matrix import (
    MatrixPair,
    MatrixResource,
    RoleMatrixError,
    RoleMatrixResult,
    build_role_matrix,
    run_role_matrix,
)
from .sessions import RoleSession, RoleSessionError, register_role_session

__all__ = [
    "MatrixPair",
    "MatrixResource",
    "RoleMatrixError",
    "RoleMatrixResult",
    "RoleSession",
    "RoleSessionError",
    "build_role_matrix",
    "register_role_session",
    "run_role_matrix",
]
