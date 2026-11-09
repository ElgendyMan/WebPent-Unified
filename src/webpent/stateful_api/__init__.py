"""webpent.stateful_api — M5 (Part 4 §7): stateful REST API testing engine.

Contract ingestion (OpenAPI + observed traffic) → inferred
state-dependency model → bounded, replayable sequence plans with
cleanup budgets → two-authorized-identity BOLA/IDOR differential plans
with randomized-id negative controls and causal evidence specs. The
engine PLANS; the deterministic validator owns confirmation. Advisory
only, by construction.
"""
from webpent.stateful_api.bola import BolaPlan, bola_hypotheses, build_bola_plans
from webpent.stateful_api.contracts import (
    ApiOperation,
    StateDependency,
    infer_dependencies,
    operations_from_state,
)
from webpent.stateful_api.sequences import (
    SequencePlan,
    generate_sequences,
    sequence_hypotheses,
)

__all__ = [
    "ApiOperation",
    "BolaPlan",
    "SequencePlan",
    "StateDependency",
    "bola_hypotheses",
    "build_bola_plans",
    "generate_sequences",
    "infer_dependencies",
    "operations_from_state",
    "sequence_hypotheses",
]
