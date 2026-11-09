"""Autonomous Bug Hunter — unified self-directed hunt loop.

This package is the single orchestrator that turns WebPent's existing
advisory research components, bounded execution spine, and proof contracts
into one end-to-end autonomous hunt:

    recon -> hypotheses -> rank -> execute (gated) -> observe -> prove -> learn

Design boundaries (non-negotiable, inherited from the rest of the codebase):

* The orchestrator is **orchestration only**. It never creates a transport
  client and never executes an action without an injected ``ActionExecutor``
  and handler. A missing executor is a configuration error, not an implicit
  fallback to raw HTTP.
* The orchestrator never promotes a finding. Promotion stays in the existing
  deterministic validators + sealed/replayable ``ProofBundle`` path.
* Every phase is bounded and fail-closed. Budget exhaustion, a repeated
  action, no new evidence, or a blocked capability all produce an explicit
  typed stop reason rather than a silent "clean" result.
* Nothing here weakens scope, authority, rate-limit, SSRF, or evidence gates.
"""

from webpent.autonomous.amplifiers.cloud_storage import (
    bucket_permutations,
    classify_bucket,
    scan_buckets,
)
from webpent.autonomous.amplifiers.ct_mining import mine_ct_logs
from webpent.autonomous.amplifiers.fp_autopsy import FPAutopsyStore, summarize_autopsy
from webpent.autonomous.amplifiers.intuition import (
    CrossTargetStore,
    build_baseline,
    detect_anomalies,
    fingerprint_of,
    rank_by_quality,
    score_hypothesis,
)
from webpent.autonomous.amplifiers.js_analyzer import analyze_javascript
from webpent.autonomous.amplifiers.operational import (
    rate_limit_map,
    session_topology,
    temporal_profile,
)
from webpent.autonomous.amplifiers.skeptic import run_skeptic_checks
from webpent.autonomous.amplifiers.swarm import run_swarm, run_swarm_round
from webpent.autonomous.amplifiers.takeover import scan_takeover
from webpent.autonomous.amplifiers.triager_sim import simulate_triager, triage_report
from webpent.autonomous.amplifiers.wayback import historical_endpoints
from webpent.autonomous.authorization import (
    AuthorizationError,
    EngagementAuthorization,
    load_authorization,
    require_authorization,
    verify_authorization,
)
from webpent.autonomous.authorization_recheck import make_authorization_recheck
from webpent.autonomous.cem.cycle import new_cem_state, run_cem_cycle
from webpent.autonomous.cem.diff_engine import diff_snapshots
from webpent.autonomous.cem.digest import build_digest
from webpent.autonomous.cem.dormant_pool import DormantPool
from webpent.autonomous.cem.reactor import ChangeReactor
from webpent.autonomous.cem.regression_watch import RegressionWatch
from webpent.autonomous.cem.scheduler import KillSwitch, PoliteScheduler
from webpent.autonomous.cem.scope_drift import evaluate as evaluate_scope_drift
from webpent.autonomous.cem.snapshot import SnapshotStore
from webpent.autonomous.cem.temporal_lessons import TemporalLessons
from webpent.autonomous.cem.wake_up import WakeUpProtocol
from webpent.autonomous.coverage_packs import (
    CoveragePack,
    pack_hypothesis_seeds,
    pack_ledger_entries,
)
from webpent.autonomous.hunt_budget import (
    recommend_rehypothesize_rounds,
    recommend_round_budget,
)
from webpent.autonomous.hunt_contracts import (
    HuntOutcome,
    HuntPhase,
    HuntStopReason,
    PhaseRecord,
)
from webpent.autonomous.hunt_deadends import DeadEndStore
from webpent.autonomous.hunt_discovery import (
    allocate_uncertainty_budget,
    build_discovery_agenda,
    discover_from_records,
    generate_hybrid_scenarios,
)
from webpent.autonomous.hunt_intel import IntelStore
from webpent.autonomous.hunt_knowledge import (
    coerce_target_knowledge,
    surface_map_to_knowledge,
)
from webpent.autonomous.hunt_memory import ScopedHuntMemory, scope_key
from webpent.autonomous.hunt_orchestrator import (
    AutonomousHuntOrchestrator,
    run_autonomous_hunt,
)
from webpent.autonomous.hunt_runtime import (
    bootstrap_knowledge,
    build_hunt_runtime,
    run_wired_hunt,
    wire_orchestrator,
)
from webpent.autonomous.hunt_state import AutonomousHuntState

__all__ = [
    "AuthorizationError",
    "EngagementAuthorization",
    "CoveragePack",
    "IntelStore",
    "DeadEndStore",
    "allocate_uncertainty_budget",
    "bootstrap_knowledge",
    "build_discovery_agenda",
    "coerce_target_knowledge",
    "discover_from_records",
    "generate_hybrid_scenarios",
    "surface_map_to_knowledge",
    "load_authorization",
    "require_authorization",
    "verify_authorization",
    "make_authorization_recheck",
    "AutonomousHuntOrchestrator",
    "AutonomousHuntState",
    "HuntOutcome",
    "HuntPhase",
    "HuntStopReason",
    "PhaseRecord",
    "ScopedHuntMemory",
    "build_hunt_runtime",
    "run_autonomous_hunt",
    "run_wired_hunt",
    "scope_key",
    "wire_orchestrator",
    "pack_hypothesis_seeds",
    "pack_ledger_entries",
    "recommend_rehypothesize_rounds",
    "recommend_round_budget",
    "bucket_permutations",
    "classify_bucket",
    "scan_buckets",
    "mine_ct_logs",
    "FPAutopsyStore",
    "summarize_autopsy",
    "CrossTargetStore",
    "build_baseline",
    "detect_anomalies",
    "fingerprint_of",
    "rank_by_quality",
    "score_hypothesis",
    "analyze_javascript",
    "rate_limit_map",
    "session_topology",
    "temporal_profile",
    "run_skeptic_checks",
    "run_swarm",
    "run_swarm_round",
    "scan_takeover",
    "simulate_triager",
    "triage_report",
    "historical_endpoints",
    "ChangeReactor",
    "DormantPool",
    "KillSwitch",
    "PoliteScheduler",
    "RegressionWatch",
    "SnapshotStore",
    "TemporalLessons",
    "WakeUpProtocol",
    "build_digest",
    "diff_snapshots",
    "evaluate_scope_drift",
    "new_cem_state",
    "run_cem_cycle",
    # DonorC-lineage VIP layer (2026-10-26 merge, from unified_v4):
    "CampaignAction",
    "CampaignInput",
    "CampaignLedger",
    "VipOrchestrator",
    "VipOrchestratorConfig",
    "run_vip_campaign",
]

# ---------------------------------------------------------------------------
# DonorC-lineage addition preserved by the 2026-10-26 merge (unified_v4):
# two default-off modules also live in this package —
#   * webpent.autonomous.campaign_ledger — unified JSONL audit ledger for a
#     campaign (one line per step; fail-soft; never stores raw payloads).
#   * webpent.autonomous.vip_orchestrator — the VIP campaign leader that
#     composes the Project Zero advisory modules into one bounded
#     perceive->plan pass (advisory only; act is always caller-supplied).
# Wiring contracts: see
# docs/archive/2026-11-01-plan-exec-root-reports/ADDITIONS_AND_FIXES_20261022.md sections 9-10.
# ---------------------------------------------------------------------------

# --- DonorC-lineage VIP layer (unified_v4), preserved by the 2026-10-26 merge.
# Both modules are default-off/advisory-only by their own contracts; see
# ADDITIONS_AND_FIXES_20261022.md sections 9-10.
from webpent.autonomous.campaign_ledger import CampaignLedger
from webpent.autonomous.vip_orchestrator import (
    CampaignAction,
    CampaignInput,
    VipOrchestrator,
    VipOrchestratorConfig,
    run_vip_campaign,
)
