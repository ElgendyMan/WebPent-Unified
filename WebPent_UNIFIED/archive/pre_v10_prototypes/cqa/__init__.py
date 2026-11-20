"""CQA v1 causal evidence activation components.

TEAM-1 Phase 9 (orphan adjudication) — ISOLATED, NOT DELETED
=============================================================
Adjudication evidence (recorded 2026-09):
  1. Runtime callers: NONE. No module under ``src/webpent`` outside this
     package, and no script/Makefile target, imports ``webpent.cqa``.
  2. Test/fixture dependency: NONE. The test suite contains no import of
     ``webpent.cqa`` (only ``webpent.cqa_v2`` is referenced).
  3. Governance dependency: NONE for runtime behaviour; historical
     ``reports/cqa_v1/`` artifacts reference the *reports*, not the code.

Conclusion: legacy architecture superseded by ``webpent.cqa_v2`` (whose
CausalGuard/ProofBundle/ReplayVerifier are the protected authority
components). The package is intentionally KEPT for historical traceability
but is ISOLATED: it must not be re-wired without a governance decision.
"""


from .execution import (
    CandidateExecutionLayer,
    CaseExecutionSpec,
    ExecutionRecord,
    RequestMetadata,
    SemanticObservation,
)

__all__ = [
    "CandidateExecutionLayer",
    "CaseExecutionSpec",
    "ExecutionRecord",
    "RequestMetadata",
    "SemanticObservation",
]
