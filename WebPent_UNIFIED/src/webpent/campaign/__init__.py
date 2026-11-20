"""webpent.campaign — the CAMPAIGN layer (U-CAMPAIGN-1..15, Waves 1-5).

A NEW, isolated package inside the repo: it imports NOTHING from the
webpent core, the verdict tool, the emulator or the rehearsal lab — the
same zero-coupling rule those three packages live under. It performs no
network I/O of its own: transport is always injected by the caller
(the executor is where a runner plugs the authorized HTTP client in).

Governing laws implemented here (CAMPAIGN-L):

- L-1  No action without a thesis: ThesisBuilder is the only entry
       point; validation fails closed below the confidence floor.
- L-2  The operator is sovereign: OperatorHandoff + require_approved;
       the machine NEVER self-approves a campaign.
- L-3  Budget is law: BudgetGuard answers before every spend; nothing
       bypasses it.
- L-6  Pivot at boundaries: triggers are declared up front in the
       phase, evaluated mechanically by the PivotEngine.
- L-9  Determinism: the strategist is pure computation — no LLM, no
       clock-dependent decisions in its outputs.

Wave map: Wave 1 (Strategist: U-CAMPAIGN-1..3), Wave 2 (Executor
core: U-CAMPAIGN-4..6), Wave 3 (Storyteller: U-CAMPAIGN-7..8),
Wave 4 (Historian: U-CAMPAIGN-9..11), Wave 5 (War Room:
U-CAMPAIGN-12..15). The spine-side integration lives in
webpent.production.campaign_bridge (a separate documented touch
point), not here.
"""
from webpent.campaign.errors import (
    CampaignError,
    CampaignNotApprovedError,
    InsufficientDataError,
    InvalidModificationError,
    ThesisValidationError,
)
from webpent.campaign.schemas import (
    CampaignBrief,
    CampaignBudget,
    ConfidenceLevel,
    Decision,
    Family,
    Hypothesis,
    Phase,
    PhaseBudget,
    PhaseStatus,
    PivotAction,
    PivotTrigger,
    TargetThesis,
    ThesisEvidence,
)

__all__ = [
    "CampaignError",
    "CampaignNotApprovedError",
    "InsufficientDataError",
    "InvalidModificationError",
    "ThesisValidationError",
    "CampaignBudget",
    "CampaignBrief",
    "ConfidenceLevel",
    "Decision",
    "Family",
    "Hypothesis",
    "Phase",
    "PhaseBudget",
    "PhaseStatus",
    "PivotAction",
    "PivotTrigger",
    "TargetThesis",
    "ThesisEvidence",
]
