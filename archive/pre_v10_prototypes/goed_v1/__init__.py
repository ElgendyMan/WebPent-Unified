"""
WebPent GOED v1 — Generative Open-Ended Exploration & Discovery

ADDITIVE MODULE — does not modify existing CQA/RTA/IRTA/ASROS/AREX behavior.

Purpose:
Move WebPent from "smart autonomous detector with predefined heuristics"
to "generative autonomous vulnerability researcher capable of discovering
new attack hypotheses from previously unknown target behavior."

Phases implemented:
- Phase 1: Discovery Knowledge Inventory (reports/goed_v1/)
- Phase 2: GenerativeResearchOpportunity contract
- Phase 3: Open-World Target Mode
- Phase 4: Knowledge Isolation Layer
- Phase 5: Generative Hypothesis Engine
- Phase 6: Security Invariant Miner
- Phase 7: Active Exploration Loop
"""

from .contracts import (
    GOED_V1_GOVERNANCE,
    ConfidenceLevel,
    GenerativeResearchOpportunity,
    Hypothesis,
    OpportunityType,
    create_opportunity_from_observation,
)
from .exploration_loop import (
    EXPLORATION_GOVERNANCE,
    ExplorationStep,
    GenerativeExplorationLoop,
    InvariantStrength,
    SecurityInvariant,
    SecurityInvariantMiner,
)
from .hypothesis_engine import (
    HYPOTHESIS_ENGINE_GOVERNANCE,
    GenerativeHypothesisEngine,
    KnowledgeIsolationBoundary,
    ObservationDelta,
)
from .open_world_mode import (
    ISOLATION_VERIFIED,
    DiscoveredResource,
    OpenWorldDiscoveryEngine,
    OpenWorldTarget,
)

__all__ = [
    "GenerativeResearchOpportunity", "Hypothesis", "OpportunityType",
    "ConfidenceLevel", "create_opportunity_from_observation", "GOED_V1_GOVERNANCE",
    "OpenWorldTarget", "DiscoveredResource", "OpenWorldDiscoveryEngine", "ISOLATION_VERIFIED",
    "KnowledgeIsolationBoundary", "GenerativeHypothesisEngine", "ObservationDelta",
    "HYPOTHESIS_ENGINE_GOVERNANCE",
    "SecurityInvariant", "SecurityInvariantMiner", "InvariantStrength",
    "GenerativeExplorationLoop", "ExplorationStep", "EXPLORATION_GOVERNANCE",
]

# Phase A1: Stateful Execution Engine
# GOED v1.7 Phase 4: Hypothesis-driven business logic evaluator
from .business_logic_evaluator import (
    BUSINESS_LOGIC_V17_GOVERNANCE,
    BusinessLogicEvaluator,
    BusinessLogicFinding,
    ControlledExperiment,
    ExperimentResult,
    InvariantFamily,
    InvariantVerdict,
)
from .business_logic_evaluator import (
    InvariantHypothesis as EvaluatorInvariantHypothesis,
)

# Phase A2: Business Logic Invariant Strategies
from .business_logic_strategies import (
    ALL_INVARIANT_STRATEGIES,
    BUSINESS_LOGIC_GOVERNANCE,
    INVARIANT_STRATEGY_REGISTRY,
    ApprovalSeparationInvariant,
    BalanceConservationInvariant,
    BaseInvariantStrategy,
    InvariantHypothesis,
    OwnershipConsistencyInvariant,
    QuantityConservationInvariant,
    ReplayResistanceInvariant,
    StateTransitionValidityInvariant,
    WorkflowOrderingInvariant,
    generate_all_invariant_hypotheses,
)
from .business_logic_strategies import (
    InvariantStrength as BusinessInvariantStrength,
)

# Phase COMPLETION: Integrated Evaluator
from .integrated_evaluator import (
    INTEGRATED_EVALUATOR_GOVERNANCE,
    EvaluationStrategy,
    IntegratedEvaluator,
    IntegratedResult,
)

# GOED v1.7 Phase 2: Real target-observed stateful execution
from .real_stateful_executor import (
    REAL_STATEFUL_GOVERNANCE,
    InvariantTest,
    ObservationSource,
    RealStatefulExecutor,
    StateDelta,
    StateObservation,
    StepTrace,
)
from .real_stateful_executor import (
    ActionSpec as RealActionSpec,
)
from .real_stateful_executor import (
    StatefulResult as RealStatefulResult,
)
from .real_stateful_executor import (
    StateSnapshot as RealStateSnapshot,
)
from .stateful_executor import (
    STATEFUL_ENGINE_GOVERNANCE,
    ActionSpec,
    ExecutionStep,
    StatefulExecutor,
    StatefulResult,
    StateSnapshot,
    StepStatus,
)

PRESERVATION_VERIFIED = True
