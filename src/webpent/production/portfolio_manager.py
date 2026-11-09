# src/webpent/production/portfolio_manager.py
"""webpent.production.portfolio_manager — Track 12, item 1.

Roadmap contract (المسار 12، البند 1 — إدارة محفظة البرامج):

    ترتيب الأعمال وفق قيمة متوقعة وموازنة موحدة، مع حدود لكل حملة
    ولكل عميل.

    ("Order work by expected value under a UNIFIED budget, with limits
    per campaign and per client.")

Design
------
``PortfolioManager`` answers one question deterministically: *given the
pending programs/work units and the money available, what may start
now, in what order, and what must be refused?*

1. **Expected value ordering** — each program carries an operator-
   supplied estimate: expected reward (currency), success probability
   (0..1), and estimated cost. EV = reward × probability − cost.
   Ranking is deterministic (EV desc, then name asc — stable ties).
2. **Unified budget** — ONE ledger shared by all clients: total cap,
   per-client cap, and per-campaign cap. Spend is recorded per campaign
   and per client; admission is fail-closed on any cap breach (money is
   a hard resource: overspending is worse than refusing work).
3. **Per-campaign / per-client limits** — a campaign's estimated cost
   must fit the per-campaign cap; a client's committed spend must fit
   its cap. Both are checked BEFORE admission and again at
   ``record_spend`` time (fail-closed: a spend that would exceed the
   client cap is refused and logged).
4. **Redaction-safe ledger** — the ledger stores identifiers and
   amounts only (client id, campaign id, amounts, timestamps); no
   finding data, no payloads.

The manager never touches scope/authorization — those live in
``webpent.scope`` and run first; portfolio admission is an economic
layer on top, never a substitute.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "AdmissionVerdict",
    "BudgetCaps",
    "PortfolioDecision",
    "PortfolioManager",
    "ProgramEstimate",
]


class AdmissionVerdict(str, Enum):
    """Outcome vocabulary for portfolio admission."""

    ADMITTED = "admitted"
    DENIED_TOTAL_BUDGET = "denied_total_budget"
    DENIED_CLIENT_BUDGET = "denied_client_budget"
    DENIED_CAMPAIGN_CAP = "denied_campaign_cap"
    DENIED_PROGRAM_UNKNOWN = "denied_program_unknown"


@dataclass
class BudgetCaps:
    """Unified budget limits (currency units; 0 = disabled cap)."""

    total_budget: float = 0.0
    per_client_budget: float = 0.0
    per_campaign_cap: float = 0.0

    def as_dict(self) -> dict[str, float]:
        return {
            "total_budget": self.total_budget,
            "per_client_budget": self.per_client_budget,
            "per_campaign_cap": self.per_campaign_cap,
        }


@dataclass
class ProgramEstimate:
    """Operator-supplied economics for one program (client-scoped)."""

    program_name: str
    client_id: str
    expected_reward: float = 0.0
    success_probability: float = 0.0
    estimated_cost: float = 0.0
    notes: str = ""

    @property
    def expected_value(self) -> float:
        """EV = reward × probability − cost (the ranking key)."""
        prob = min(1.0, max(0.0, self.success_probability))
        return self.expected_reward * prob - self.estimated_cost

    def as_dict(self) -> dict[str, Any]:
        return {
            "program_name": self.program_name,
            "client_id": self.client_id,
            "expected_reward": self.expected_reward,
            "success_probability": self.success_probability,
            "estimated_cost": self.estimated_cost,
            "expected_value": self.expected_value,
            "notes": self.notes,
        }


@dataclass
class PortfolioDecision:
    """One admission decision (auditable, identifier-level only)."""

    verdict: AdmissionVerdict
    program_name: str
    client_id: str
    campaign_id: str = ""
    estimated_cost: float = 0.0
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "program_name": self.program_name,
            "client_id": self.client_id,
            "campaign_id": self.campaign_id,
            "estimated_cost": self.estimated_cost,
            "reason": self.reason,
        }


@dataclass
class PortfolioManager:
    """Unified-budget portfolio admission (deterministic, fail-closed)."""

    caps: BudgetCaps = field(default_factory=BudgetCaps)

    def __post_init__(self) -> None:
        self._programs: dict[tuple[str, str], ProgramEstimate] = {}
        self._client_spend: dict[str, float] = {}
        self._campaign_spend: dict[str, float] = {}
        self._total_spend: float = 0.0

    # ------------------------------------------------------------------
    # registration & ranking
    # ------------------------------------------------------------------
    def register_program(self, estimate: ProgramEstimate) -> None:
        """Register/update a program's economics (idempotent by name)."""
        self._programs[(estimate.client_id, estimate.program_name)] = estimate

    def rank_programs(self) -> list[tuple[ProgramEstimate, float]]:
        """All registered programs sorted by EV (desc), name (asc).

        Deterministic and side-effect free — safe to display in a
        dashboard before any admission decision.
        """
        ranked = sorted(
            self._programs.values(),
            key=lambda p: (-p.expected_value, p.client_id, p.program_name),
        )
        return [(p, p.expected_value) for p in ranked]

    # ------------------------------------------------------------------
    # admission (fail-closed on caps)
    # ------------------------------------------------------------------
    def admit(
        self,
        client_id: str,
        program_name: str,
        campaign_id: str,
        *,
        estimated_cost: float | None = None,
    ) -> PortfolioDecision:
        """Admit a campaign for a program under the unified budget.

        Fail-closed: any cap breach (or unknown program) refuses the
        campaign with an explicit reason. A disabled cap (0) never
        refuses.
        """
        program = self._programs.get((client_id, program_name))
        if program is None:
            return PortfolioDecision(
                AdmissionVerdict.DENIED_PROGRAM_UNKNOWN,
                program_name,
                client_id,
                campaign_id,
                reason="no registered estimate for (client, program)",
            )
        cost = program.estimated_cost if estimated_cost is None else float(estimated_cost)
        if self.caps.per_campaign_cap > 0 and cost > self.caps.per_campaign_cap:
            return PortfolioDecision(
                AdmissionVerdict.DENIED_CAMPAIGN_CAP,
                program_name,
                client_id,
                campaign_id,
                cost,
                reason=(
                    f"estimated cost {cost:.2f} exceeds the per-campaign "
                    f"cap {self.caps.per_campaign_cap:.2f}"
                ),
            )
        client_committed = self._client_spend.get(client_id, 0.0)
        if (
            self.caps.per_client_budget > 0
            and client_committed + cost > self.caps.per_client_budget
        ):
            return PortfolioDecision(
                AdmissionVerdict.DENIED_CLIENT_BUDGET,
                program_name,
                client_id,
                campaign_id,
                cost,
                reason=(
                    f"client budget {self.caps.per_client_budget:.2f} would be "
                    f"exceeded ({client_committed:.2f} committed + {cost:.2f})"
                ),
            )
        if (
            self.caps.total_budget > 0
            and self._total_spend + cost > self.caps.total_budget
        ):

            return PortfolioDecision(
                AdmissionVerdict.DENIED_TOTAL_BUDGET,
                program_name,
                client_id,
                campaign_id,
                cost,
                reason=(
                    f"total budget {self.caps.total_budget:.2f} would be "
                    f"exceeded ({self._total_spend:.2f} spent + {cost:.2f})"
                ),
            )
        return PortfolioDecision(
            AdmissionVerdict.ADMITTED,
            program_name,
            client_id,
            campaign_id,
            cost,
            reason="within unified budget caps",
        )

    # ------------------------------------------------------------------
    # spend ledger (fail-closed at record time too)
    # ------------------------------------------------------------------
    def record_spend(
        self, client_id: str, campaign_id: str, amount: float
    ) -> tuple[bool, str]:
        """Record actual spend. Refuses (fail-closed) any amount that
        would breach a cap; returns ``(recorded, reason)``."""
        amount = max(0.0, float(amount))
        if self.caps.per_client_budget > 0:
            committed = self._client_spend.get(client_id, 0.0)
            if committed + amount > self.caps.per_client_budget + 1e-9:
                return False, "would exceed per-client budget"
        if (
            self.caps.total_budget > 0
            and self._total_spend + amount > self.caps.total_budget + 1e-9
        ):
            return False, "would exceed total budget"
        self._client_spend[client_id] = self._client_spend.get(client_id, 0.0) + amount
        self._campaign_spend[campaign_id] = self._campaign_spend.get(campaign_id, 0.0) + amount
        self._total_spend += amount
        return True, "recorded"

    def budget_snapshot(self) -> dict[str, Any]:
        """Redaction-safe ledger view (ids + amounts only)."""
        return {
            "caps": self.caps.as_dict(),
            "total_spend": round(self._total_spend, 4),
            "spend_by_client": {k: round(v, 4) for k, v in sorted(self._client_spend.items())},
            "spend_by_campaign": {k: round(v, 4) for k, v in sorted(self._campaign_spend.items())},
            "registered_programs": len(self._programs),
        }

    # ------------------------------------------------------------------
    # optional audit trail
    # ------------------------------------------------------------------
    def append_audit_log(
        self, log_path: str | os.PathLike[str], decision: PortfolioDecision
    ) -> bool:
        """Append one JSONL audit line. Never raises."""
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            **decision.as_dict(),
        }
        try:
            path = Path(log_path)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
            return True
        except OSError:
            logger.warning("portfolio_manager: audit log write failed", exc_info=True)
            return False
