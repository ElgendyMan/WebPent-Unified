# src/webpent/integration/__init__.py
"""Shannon→GOED protected integration layer (additive only).

This package is the SOLE surface of the Shannon capability integration
(docs/integration/SHANNON_GOED_CAPABILITY_MATRIX.md). It is strictly
additive: no existing GOED module was modified, and no Shannon source
code or prompt text was copied (Shannon is AGPL-3.0 — see
docs/integration/SHANNON_LICENSE_AUDIT.md; the modules below reference
Shannon *patterns* as architecture only and are original GOED code).

Modules
-------
research_agenda / priority_policy
    Adaptive researcher brain: dynamic, deterministic, bounded,
    auditable prioritization with budget reallocation, branch bounds,
    and checkpoint/resume (protocol §11, §12, §23). BUILD decision.
source_mapping
    Source-code location ↔ runtime endpoint ↔ hypothesis correlation
    (advisory annotations for the attack graph). ADAPT decision.
surface_dossier
    Consolidated, evidence-referenced attack-surface artifact built
    from GOED's own runtime state. KEEP runtime + ADAPT consolidation.
exploitation_queue
    Evidence-gated exploitation planning queue with a strict
    attempted/blocked outcome union — never authoritative, always
    routed through CausalGuard downstream. ADAPT decision.
reconciliation
    Deterministic staged observation reconciliation with forbidden
    internal-key scrubbing and stable task refs. ADAPT decision.
auth_session_contract
    Typed auth-validation verdict (secret-free) for research state.
    ADAPT decision over GOED's existing auth machinery.

Non-negotiables preserved (protocol §8, §9):

* CausalGuard is the ONLY verdict authority; nothing in this package
  confirms, promotes, or scores findings.
* The LLM can only propose (clamped priority suggestions, hypothesis
  ids) — never decide priority or verdicts.
* No ground truth access; no destructive actions; no fabricated
  evidence; no silent fallbacks; no new third-party dependencies.
* Planning-only: no I/O, no execution, no transport.
"""

from webpent.integration.auth_session_contract import (
    AuthFailurePoint,
    AuthSessionRecord,
    AuthValidationVerdict,
    merge_into_state_dict,
    record_from_verdict,
)
from webpent.integration.exploitation_queue import (
    ExploitationQueue,
    ExploitAttemptRecord,
    GateDecision,
    GateResult,
    QueueEntry,
)
from webpent.integration.priority_policy import (
    PriorityDecision,
    PriorityFactor,
    PriorityInput,
    PriorityProposal,
    compute_priority,
)
from webpent.integration.reconciliation import (
    Observation,
    ReconciliationResult,
    ResearchTask,
    reconcile,
)
from webpent.integration.research_agenda import (
    AgendaLimits,
    AgendaSignal,
    BranchStatus,
    ResearchAgenda,
    branch_id_for,
)
from webpent.integration.source_mapping import (
    CodeLocation,
    SourceMappingRecord,
    SourceRole,
    join_source_locations,
)
from webpent.integration.surface_dossier import (
    SurfaceDossier,
    build_surface_dossier,
)

__all__ = [
    # research agenda / priority policy
    "AgendaLimits",
    "AgendaSignal",
    # auth session contract
    "AuthFailurePoint",
    "AuthSessionRecord",
    "AuthValidationVerdict",
    "BranchStatus",
    # source mapping
    "CodeLocation",
    # exploitation queue
    "ExploitAttemptRecord",
    "ExploitationQueue",
    "GateDecision",
    "GateResult",
    # reconciliation
    "Observation",
    "PriorityDecision",
    "PriorityFactor",
    "PriorityInput",
    "PriorityProposal",
    "QueueEntry",
    "ReconciliationResult",
    "ResearchAgenda",
    "ResearchTask",
    "SourceMappingRecord",
    "SourceRole",
    # surface dossier
    "SurfaceDossier",
    "branch_id_for",
    "build_surface_dossier",
    "compute_priority",
    "join_source_locations",
    "merge_into_state_dict",
    "reconcile",
    "record_from_verdict",
]
