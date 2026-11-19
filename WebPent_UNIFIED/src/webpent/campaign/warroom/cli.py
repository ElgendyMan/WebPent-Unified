"""CampaignCLI — U-CAMPAIGN-13.

The operator's typed commands against the campaign store: list,
status, approve, reject. Nothing else. No shell is spawned, no network
is touched; every command resolves to a typed result — an unknown
command or unknown campaign is a failed result, never an exception
that escapes. The CLI is the operator's own hand on the brief: the
rulings it records are the operator's, which is exactly L-2.
"""
from __future__ import annotations

from dataclasses import replace

from webpent.campaign.schemas import Decision
from webpent.campaign.storage.campaign_store import CampaignStore

_VERBS = ("list", "status", "approve", "reject")


class CampaignCLI:
    """Executes operator command strings against the brief store."""

    def __init__(self, store: CampaignStore):
        self._store = store

    def execute(self, command: str) -> dict:
        parts = command.strip().split()
        if not parts:
            return {"ok": False, "output": "error: empty command"}
        verb, args = parts[0].lower(), parts[1:]
        if verb == "list":
            return self._list()
        if verb in ("status", "approve", "reject"):
            if not args:
                return {"ok": False,
                        "output": f"error: {verb} requires a campaign id"}
            return self._ruling_or_status(verb, args[0])
        return {"ok": False, "output": f"error: unknown command '{verb}' — "
                f"expected one of {list(_VERBS)}"}

    # -- internals ----------------------------------------------------------

    def _list(self) -> dict:
        briefs = self._store.list_briefs()
        ids = ", ".join(brief.campaign_id for brief in briefs) or "(none)"
        return {"ok": True, "output": f"briefs: {ids}"}

    def _ruling_or_status(self, verb: str, campaign_id: str) -> dict:
        brief = self._store.get_brief(campaign_id)
        if brief is None:
            return {"ok": False,
                    "output": f"error: unknown campaign '{campaign_id}'"}
        if verb == "status":
            return {
                "ok": True,
                "output": (
                    f"campaign {campaign_id} "
                    f"decision={brief.decision.value} "
                    f"phases={len(brief.phases)}"
                ),
            }
        decision = Decision.APPROVED if verb == "approve" \
            else Decision.REJECTED
        self._store.save_brief(replace(brief, decision=decision))
        return {"ok": True,
                "output": f"campaign {campaign_id} "
                          f"decision={decision.value}"}
