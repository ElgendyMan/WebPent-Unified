"""Centralized policy decisions for proof-of-concept execution.

This module is deliberately execution-free.  It only classifies a proposed
operation so planner, workflow, and future execution adapters can share the
same safety vocabulary.  A classification never authorizes a network request
or a shell command.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

PocGateStatus = Literal["allowed", "needs_approval", "rejected"]


@dataclass(frozen=True)
class PocGateDecision:
    """Auditable, side-effect-free result of a PoC safety gate."""

    status: PocGateStatus
    reason: str
    gate: str = "poc_safety"

    @property
    def allowed(self) -> bool:
        return self.status == "allowed"


def evaluate_poc_risk(
    risk_level: Any,
    *,
    human_approved: bool = False,
) -> PocGateDecision:
    """Classify a proposed PoC risk without executing it.

    ``destructive`` is rejected by the planner policy even when an operator
    has approved a high-risk read-only validation.  Destructive actions must
    use an explicitly reviewed, separate workflow rather than an autonomous
    planner proposal.  ``high`` is allowed only after an explicit human
    approval; low and medium read-only work remains automatable.
    """

    value = getattr(risk_level, "value", risk_level)
    value = str(value or "low").strip().lower()
    if value == "destructive":
        return PocGateDecision(
            status="rejected",
            reason="Destructive PoC actions are outside the autonomous planner allowlist.",
        )
    if value == "high" and not human_approved:
        return PocGateDecision(
            status="needs_approval",
            reason="High-risk PoC validation requires explicit human approval.",
        )
    if value not in {"low", "medium", "high"}:
        return PocGateDecision(
            status="rejected",
            reason=f"Unknown PoC risk level {value!r} is rejected fail-closed.",
        )
    return PocGateDecision(
        status="allowed",
        reason="The proposed operation is bounded and non-destructive under the planner policy.",
    )



_HIGH_RISK_VULN_CLASSES = frozenset({
    "rce",
    "command_injection",
    "ssti",
    "deserialization",
})


def _value(item: Any, key: str, default: Any = None) -> Any:
    """Read a key from either a checkpoint dict or a Pydantic model."""
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _normalise_value(value: Any) -> str:
    value = getattr(value, "value", value)
    return str(value or "").strip().lower()


def derive_execution_risk(state: dict[str, Any]) -> str:
    """Derive the maximum execution risk from trusted state projections.

    Planner output is advisory, but a declared ``destructive`` risk remains
    a hard rejection.  Finding severity and deterministic vulnerability class
    provide a conservative fallback when planner decisions are disabled.
    """
    planner = state.get("planner_decision") or {}
    proposal = _value(planner, "proposal", {}) or {}
    candidates = [
        _value(planner, "risk_level"),
        _value(proposal, "risk_level"),
    ]
    normalised = {
        _normalise_value(value)
        for value in candidates
        if value is not None
    }
    if "destructive" in normalised:
        return "destructive"
    if "high" in normalised:
        return "high"

    for finding in state.get("findings") or []:
        severity = _normalise_value(_value(finding, "severity", ""))
        vuln_class = _normalise_value(_value(finding, "vuln_class", ""))
        if severity == "critical":
            return "high"
        if severity == "high" or vuln_class in _HIGH_RISK_VULN_CLASSES:
            normalised.add("high")
    return "high" if "high" in normalised else "low"


def evaluate_execution_gate(state: dict[str, Any]) -> PocGateDecision:
    """Gate live PoC execution without weakening the existing HITL pause.

    ``auto_approve=False`` means the graph already paused before this node;
    that preceding human approval is accepted for bounded high-risk work.
    With ``auto_approve=True``, high-risk work is blocked and surfaced as
    ``needs_approval``.  Destructive work is always rejected.
    """
    risk_level = derive_execution_risk(state)
    human_approved = not bool(state.get("auto_approve", False))
    return evaluate_poc_risk(risk_level, human_approved=human_approved)


__all__ = [
    "PocGateDecision",
    "PocGateStatus",
    "derive_execution_risk",
    "evaluate_execution_gate",
    "evaluate_poc_risk",
]

# End of file
