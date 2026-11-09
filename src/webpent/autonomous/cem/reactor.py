"""CEM Reactor — the change reactor (v83, U-CEM-5).

When a diff reaches SIGNAL-HIGH or above, the reactor proposes a focused
mini-campaign against the changed surface only: at most 10% of the daily
budget per campaign, at most 4 campaigns active, and a cooldown so the
same change never re-triggers in a loop. Proposals are advisory; the
scheduler still gates every request, and promotion still happens only
through the sealed proof path.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import tempfile
from typing import Any

from webpent.autonomous.cem.diff_engine import is_actionable, is_wake_up
from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

MINI_CAMPAIGN_BUDGET_FRACTION = 0.10
MAX_ACTIVE_CAMPAIGNS = 4
#: History keeps four generations of past campaigns per active slot so
#: cooldowns and active-count checks survive restarts; anything older
#: is beyond every TTL and cooldown in this module.
MAX_CAMPAIGN_HISTORY = MAX_ACTIVE_CAMPAIGNS * 4
DEFAULT_CAMPAIGN_TTL_HOURS = 24.0
DEFAULT_COOLDOWN_HOURS = 12.0


def _change_key(diff: dict[str, Any]) -> str:
    """Stable short key for the change that triggered a proposal."""
    items = "|".join(
        f"{c.get('field')}:{c.get('kind')}:{c.get('item')}"
        for c in list(diff.get("changes") or [])[:8]
    )
    return hashlib.sha256(items.encode("utf-8")).hexdigest()[:12]


class ChangeReactor:
    """Bounded mini-campaign proposals on actionable diffs. Advisory only."""

    def __init__(
        self,
        persist_path: Any,
        *,
        daily_budget: int = 2000,
        campaign_ttl_hours: float = DEFAULT_CAMPAIGN_TTL_HOURS,
        cooldown_hours: float = DEFAULT_COOLDOWN_HOURS,
    ) -> None:
        self._path = persist_path
        self.daily_budget = max(1, int(daily_budget))
        self.campaign_ttl_hours = max(0.0, float(campaign_ttl_hours))
        self.cooldown_hours = max(0.0, float(cooldown_hours))
        self._campaigns: list[dict[str, Any]] = []
        self.load()

    def load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError, AttributeError):
            self._campaigns = []
            return
        self._campaigns = [c for c in raw if isinstance(c, dict)] if isinstance(raw, list) else []
        self._campaigns = self._campaigns[-MAX_CAMPAIGN_HISTORY:]

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=str(self._path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(self._campaigns[-MAX_CAMPAIGN_HISTORY:], handle, indent=2)
                os.replace(tmp_name, self._path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except (OSError, AttributeError) as exc:
            _LOG.warning("reactor save failed (memory stays in-process): %s", exc)

    def budget_per_campaign(self) -> int:
        return max(1, int(self.daily_budget * MINI_CAMPAIGN_BUDGET_FRACTION))

    def propose(self, diff: dict[str, Any], *, now: float) -> list[dict[str, Any]]:
        """Advisory proposal list for one diff; empty when not actionable.

        Compatible with the cycle's optional ``reactor`` hook signature.
        """
        now = float(now)
        if not isinstance(diff, dict) or not is_actionable(diff):
            return []
        target_id = redact(str(diff.get("target_id") or ""))[:120]
        if not target_id:
            return []
        key = _change_key(diff)
        if self._on_cooldown(target_id, key, now):
            return []
        if self._active_count(now) >= MAX_ACTIVE_CAMPAIGNS:
            return []
        proposal = {
            "kind": "wake_up" if is_wake_up(diff) else "mini_campaign",
            "target_id": target_id,
            "change_key": key,
            "reason": redact(str(diff.get("top_signal") or ""))[:40],
            "change_count": int(diff.get("change_count") or 0),
            "budget": self.budget_per_campaign(),
            "ttl_hours": self.campaign_ttl_hours,
            "advisory": True,
        }
        return [proposal]

    def register_launch(self, proposal: dict[str, Any], *, now: float) -> dict[str, Any] | None:
        """Record a launched campaign; refuses when the slot cap is full."""
        if not isinstance(proposal, dict) or not proposal.get("target_id"):
            return None
        now = float(now)
        if self._active_count(now) >= MAX_ACTIVE_CAMPAIGNS:
            return None
        campaign = {
            "target_id": redact(str(proposal["target_id"]))[:120],
            "change_key": str(proposal.get("change_key") or "")[:16],
            "budget": min(
                int(proposal.get("budget") or self.budget_per_campaign()),
                self.daily_budget if str(proposal.get("kind")) == "wake_up"
                else self.budget_per_campaign(),
            ),
            "kind": str(proposal.get("kind") or "mini_campaign")[:20],
            "launched_at": now,
            "expires_at": now + self.campaign_ttl_hours * 3600.0,
        }
        self._campaigns.append(campaign)
        self._campaigns = self._campaigns[-MAX_CAMPAIGN_HISTORY:]
        self.save()
        return dict(campaign)

    def active(self, now: float) -> list[dict[str, Any]]:
        now = float(now)
        return [dict(c) for c in self._campaigns if float(c.get("expires_at") or 0) > now]

    def _active_count(self, now: float) -> int:
        return len(self.active(now))

    def _on_cooldown(self, target_id: str, key: str, now: float) -> bool:
        cutoff = now - self.cooldown_hours * 3600.0
        for campaign in self._campaigns:
            if (
                campaign.get("target_id") == target_id
                and campaign.get("change_key") == key
                and float(campaign.get("launched_at") or 0) > cutoff
            ):
                return True
        return False


__all__ = [
    "DEFAULT_CAMPAIGN_TTL_HOURS",
    "DEFAULT_COOLDOWN_HOURS",
    "MAX_ACTIVE_CAMPAIGNS",
    "MINI_CAMPAIGN_BUDGET_FRACTION",
    "ChangeReactor",
]
