"""The Dojo: WebPent's self-training ground (advisory, offline, deterministic).

Seventh layer on the stack: synthetic labs, sparring, skill metering
and targeted practice. Charter: DOJO-L-1..L-10
(plan: docs/plans/2026-10-16-v85-dojo.md).
"""

from webpent.dojo.engine import (
    DojoRequest,
    DojoResponse,
    LabInstance,
    RouteSpec,
    SimulatedTarget,
    VulnPoint,
    stable_hash,
)
from webpent.dojo.lab_generator import EXTERNAL_LABS, LabGenerator

__all__ = [
    "EXTERNAL_LABS",
    "DojoRequest",
    "DojoResponse",
    "LabGenerator",
    "LabInstance",
    "RouteSpec",
    "SimulatedTarget",
    "VulnPoint",
    "stable_hash",
]
