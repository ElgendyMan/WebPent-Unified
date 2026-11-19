"""Fail-closed critic for optional Copilot proposals."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class LLMCritic:
    """Validate proposal shape and reject authority escalation."""

    _FORBIDDEN = {
        "finding",
        "findings",
        "proof",
        "confirmed",
        "execute",
        "request",
        "exploit",
    }

    def review(self, proposal: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(proposal, Mapping):
            return {"accepted": False, "reason": "proposal_not_mapping"}
        keys = {str(key).lower() for key in proposal}
        forbidden = sorted(keys.intersection(self._FORBIDDEN))
        if forbidden:
            return {
                "accepted": False,
                "reason": "authority_escalation",
                "forbidden_keys": forbidden,
            }
        action_class = str(proposal.get("action_class", "")).strip()
        target = str(proposal.get("target", "")).strip()
        if action_class != "information_gathering" or not target:
            return {"accepted": False, "reason": "proposal_contract_invalid"}
        return {
            "accepted": True,
            "reason": "proposal_only",
            "action_class": action_class,
            "target": target[:240],
            "evidence_refs": list(proposal.get("evidence_refs") or [])[:20],
        }


__all__ = ["LLMCritic"]
