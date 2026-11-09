"""Human-in-the-loop policy projections for bounded autonomy.

This module does not authorize or execute actions.  The central
``ActionAuthority`` must still make the final decision for every dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from webpent.shared.action_authority import ActionRequest, ActionRisk


class HITLLevel(IntEnum):
    """Progressive autonomy levels from suggestion to bounded campaigns."""

    SUGGEST = 1
    LOW_RISK_AUTOMATION = 2
    BOUNDED_RESEARCH = 3
    AUTONOMOUS_CAMPAIGN = 4


@dataclass(frozen=True)
class HITLPolicy:
    """Immutable policy profile; it is advisory to the execution kernel."""

    level: HITLLevel
    name: str
    description: str
    autonomous_risks: tuple[ActionRisk, ...]
    requires_explicit_authorization: bool
    requires_human_approval: bool
    max_actions: int
    budget_fraction: float
    proof_required_for_confirmation: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "level": int(self.level),
            "name": self.name,
            "description": self.description,
            "autonomous_risks": [risk.value for risk in self.autonomous_risks],
            "requires_explicit_authorization": self.requires_explicit_authorization,
            "requires_human_approval": self.requires_human_approval,
            "max_actions": self.max_actions,
            "budget_fraction": self.budget_fraction,
            "proof_required_for_confirmation": self.proof_required_for_confirmation,
            "authority_final_decision_required": True,
        }


@dataclass(frozen=True)
class HITLDecision:
    """Decision to hand to ActionAuthority or a human review surface."""

    allowed_to_dispatch: bool
    requires_human_approval: bool
    requires_proof_for_confirmation: bool
    reasons: tuple[str, ...]
    policy: HITLPolicy

    @property
    def advisory_only(self) -> bool:
        return not self.allowed_to_dispatch

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed_to_dispatch": self.allowed_to_dispatch,
            "requires_human_approval": self.requires_human_approval,
            "requires_proof_for_confirmation": self.requires_proof_for_confirmation,
            "reasons": list(self.reasons),
            "advisory_only": self.advisory_only,
            "policy": self.policy.as_dict(),
        }


_POLICIES: dict[HITLLevel, HITLPolicy] = {
    HITLLevel.SUGGEST: HITLPolicy(
        HITLLevel.SUGGEST,
        "suggest",
        "AI proposes; a human approves dispatch.",
        (),
        False,
        True,
        0,
        0.0,
        True,
    ),
    HITLLevel.LOW_RISK_AUTOMATION: HITLPolicy(
        HITLLevel.LOW_RISK_AUTOMATION,
        "low_risk_automation",
        "AI may dispatch read-only actions; active actions require review.",
        (ActionRisk.READ_ONLY,),
        False,
        False,
        32,
        0.25,
        True,
    ),
    HITLLevel.BOUNDED_RESEARCH: HITLPolicy(
        HITLLevel.BOUNDED_RESEARCH,
        "bounded_research",
        "AI may run explicitly authorized bounded research within scope and budget.",
        (ActionRisk.READ_ONLY, ActionRisk.ACTIVE),
        True,
        False,
        128,
        0.60,
        True,
    ),
    HITLLevel.AUTONOMOUS_CAMPAIGN: HITLPolicy(
        HITLLevel.AUTONOMOUS_CAMPAIGN,
        "autonomous_campaign",
        "AI may run a bounded campaign; final authority and proof gates remain mandatory.",
        (ActionRisk.READ_ONLY, ActionRisk.ACTIVE),
        True,
        False,
        256,
        1.0,
        True,
    ),
}


def resolve_hitl_policy(level: int | HITLLevel) -> HITLPolicy:
    """Return a known policy and reject unknown levels rather than escalating."""
    try:
        normalized = HITLLevel(int(level))
    except (TypeError, ValueError) as exc:
        raise ValueError("HITL level must be an integer from 1 to 4") from exc
    return _POLICIES[normalized]


def evaluate_hitl_action(
    request: ActionRequest,
    level: int | HITLLevel,
    *,
    explicit_authorization: bool = False,
    scope_ready: bool = False,
    budget_available: bool = True,
    human_approved: bool = False,
) -> HITLDecision:
    """Check HITL prerequisites without replacing ActionAuthority.

    ``scope_ready`` and ``explicit_authorization`` are assertions supplied by
    the caller after its own package/policy checks; this function never widens
    scope and never turns an advisory decision into an executed action.
    """
    policy = resolve_hitl_policy(level)
    reasons: list[str] = []
    risk = request.risk
    if not scope_ready:
        reasons.append("hitl:scope_not_ready")
    if risk not in policy.autonomous_risks:
        reasons.append("hitl:risk_requires_human_review")
    if policy.requires_explicit_authorization and not explicit_authorization:
        reasons.append("hitl:explicit_authorization_required")
    if not budget_available:
        reasons.append("hitl:budget_unavailable")
    if policy.requires_human_approval and not human_approved:
        reasons.append("hitl:human_approval_required")
    allowed = not reasons and policy.level != HITLLevel.SUGGEST
    return HITLDecision(
        allowed_to_dispatch=allowed,
        requires_human_approval=policy.requires_human_approval or bool(reasons),
        requires_proof_for_confirmation=policy.proof_required_for_confirmation,
        reasons=tuple(reasons),
        policy=policy,
    )


def evaluate_hitl_confirmation(
    level: int | HITLLevel,
    *,
    impact: bool,
    root_cause: bool,
    reproducible: bool,
    evidence: bool,
    proof_bundle_sealed: bool,
    replay_passed: bool,
) -> HITLDecision:
    """Require every confirmation gate; missing proof can never be bypassed."""
    policy = resolve_hitl_policy(level)
    checks = {
        "impact": impact,
        "root_cause": root_cause,
        "reproducible": reproducible,
        "evidence": evidence,
        "proof_bundle_sealed": proof_bundle_sealed,
        "replay_passed": replay_passed,
    }
    reasons = tuple(f"confirmation:{name}:missing" for name, value in checks.items() if not value)
    return HITLDecision(
        allowed_to_dispatch=not reasons,
        requires_human_approval=bool(reasons),
        requires_proof_for_confirmation=policy.proof_required_for_confirmation,
        reasons=reasons,
        policy=policy,
    )


__all__ = [
    "HITLDecision",
    "HITLLevel",
    "HITLPolicy",
    "evaluate_hitl_action",
    "evaluate_hitl_confirmation",
    "resolve_hitl_policy",
]
