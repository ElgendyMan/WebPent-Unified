"""U-CAMPAIGN-3 — OperatorHandoff.

L-2: the operator is sovereign. Before ANY traffic leaves the
workshop, a human reads the brief and approves, rejects or modifies
it. The machine NEVER self-approves, and a decision, once recorded,
cannot be rewritten — it can only be superseded by a new brief.

The handoff is also where approval is ENFORCED for the rest of the
layer: ``require_approved`` is the gate the executor-side units call
before doing anything. The operator's decision lives on the brief;
the gate reads it; nothing else does.
"""
from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from webpent.campaign.errors import (
    CampaignNotApprovedError,
    InvalidModificationError,
)
from webpent.campaign.schemas import (
    CampaignBrief,
    CampaignBudget,
    Decision,
    Phase,
    TargetThesis,
)


def require_approved(brief: CampaignBrief) -> None:
    """L-2 gate: raise unless the operator APPROVED this brief.

    Every executor-side entry point calls this before its first spend.
    Returns None on success (so it composes as a guard clause).
    """
    if brief.decision is not Decision.APPROVED:
        raise CampaignNotApprovedError(
            f"campaign {brief.campaign_id} is "
            f"'{brief.decision.value}' — no traffic may leave the "
            "workshop until the operator approves (L-2: the operator "
            "is sovereign)")
    return None


class OperatorHandoff:
    """Presents the plan to the operator and records the ruling.

    With a store attached, every brief and every ruling is persisted;
    without one, the handoff still enforces the same laws in memory
    (useful for rehearsals).
    """

    def __init__(self, store: Any | None = None):
        self._store = store

    def present(self, thesis: TargetThesis, phases: list[Phase],
                total_budget: CampaignBudget) -> CampaignBrief:
        """Assemble the brief the operator rules on (starts PENDING)."""
        brief = CampaignBrief(
            campaign_id=f"campaign-{uuid.uuid4().hex[:12]}",
            created_at=datetime.now(timezone.utc),
            thesis=thesis,
            phases=list(phases),
            total_budget=total_budget,
            decision=Decision.PENDING,
        )
        if self._store is not None:
            self._store.save_brief(brief)
        return brief

    def approve(self, brief: CampaignBrief) -> CampaignBrief:
        """Record the operator's approval — from PENDING only."""
        self._require_pending(brief, "approve")
        updated = replace(brief, decision=Decision.APPROVED)
        self._save(updated)
        return updated

    def reject(self, brief: CampaignBrief) -> CampaignBrief:
        """Record the operator's rejection — from PENDING only."""
        self._require_pending(brief, "reject")
        updated = replace(brief, decision=Decision.REJECTED)
        self._save(updated)
        return updated

    def modify(self, brief: CampaignBrief, *,
               modifications: dict[str, Any]) -> CampaignBrief:
        """Record the operator's modifications — from PENDING only.

        Supported keys: ``skip_phases`` (list of phase ids that must
        exist in the brief). Unknown phase ids raise
        InvalidModificationError — a typo is not a decision.
        """
        self._require_pending(brief, "modify")
        changes: dict[str, Any] = {}
        skip = modifications.get("skip_phases") or []
        if skip:
            known = {p.phase_id for p in brief.phases}
            unknown = [pid for pid in skip if pid not in known]
            if unknown:
                raise InvalidModificationError(
                    f"modification references unknown phase(s): "
                    f"{', '.join(sorted(unknown))} — refusing to guess")
            remaining = [p for p in brief.phases
                         if p.phase_id not in set(skip)]
            if not remaining:
                raise InvalidModificationError(
                    "cannot skip every phase — reject the brief instead")
            changes["phases"] = remaining
        changes["decision"] = Decision.MODIFIED
        updated = replace(brief, **changes)
        self._save(updated)
        return updated

    def get_brief(self, campaign_id: str) -> CampaignBrief | None:
        if self._store is None:
            return None
        return self._store.get_brief(campaign_id)

    def get_pending(self) -> list[CampaignBrief]:
        if self._store is None:
            return []
        return [b for b in self._store.list_briefs()
                if b.decision is Decision.PENDING]

    # ------------------------------------------------------------------

    @staticmethod
    def _require_pending(brief: CampaignBrief, action: str) -> None:
        if brief.decision is not Decision.PENDING:
            raise ValueError(
                f"cannot {action} campaign {brief.campaign_id}: a decision "
                f"('{brief.decision.value}') is already recorded — rulings "
                "are immutable; issue a new brief instead")

    def _save(self, brief: CampaignBrief) -> None:
        if self._store is not None:
            self._store.save_brief(brief)
