"""Explicit multi-agent role contracts for the smart campaign.

The registry documents and validates role boundaries. It does not dispatch tools,
approve actions, or promote findings; those decisions remain in the existing
scope and proof gates.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class AgentRoleSpec:
    """Static responsibility contract for one agent role."""

    role: str
    implementation: str
    responsibilities: tuple[str, ...]
    required_inputs: tuple[str, ...]
    emitted_artifacts: tuple[str, ...]
    advisory_only: bool = True
    can_execute: bool = False
    can_create_findings: bool = False
    can_override_oracle: bool = False
    can_override_policy: bool = False


ROLE_SPECS: tuple[AgentRoleSpec, ...] = (
    AgentRoleSpec(
        role="recon",
        implementation="webpent.agents.recon.agent",
        responsibilities=("discover assets", "collect passive surface evidence"),
        required_inputs=("target_url", "scope"),
        emitted_artifacts=("surface_observation", "evidence_ref"),
    ),
    AgentRoleSpec(
        role="target_understanding",
        implementation="webpent.agents.target_understanding.agent",
        responsibilities=("build target model", "identify workflows and coverage gaps"),
        required_inputs=("target_url", "engagement_id"),
        emitted_artifacts=("target_knowledge", "coverage_gap"),
    ),
    AgentRoleSpec(
        role="hypothesis",
        implementation="webpent.agents.hypothesis_analyzer.agent",
        responsibilities=("rank structured hypotheses", "request bounded experiments"),
        required_inputs=("target_knowledge", "evidence_refs"),
        emitted_artifacts=("hypothesis", "research_action"),
    ),
    AgentRoleSpec(
        role="validator",
        implementation="webpent.agents.validator.agent",
        responsibilities=("replay evidence", "apply negative controls"),
        required_inputs=("hypothesis", "proof_bundle"),
        emitted_artifacts=("validation_result", "proof_bundle"),
    ),
    AgentRoleSpec(
        role="reviewer",
        implementation="webpent.agents.devils_advocate.agent",
        responsibilities=("challenge causal claims", "identify alternative explanations"),
        required_inputs=("validation_result", "negative_control"),
        emitted_artifacts=("review_decision", "review_evidence_ref"),
    ),
    AgentRoleSpec(
        role="arex_recon_researcher",
        implementation="webpent.agents.arex.recon_researcher",
        responsibilities=("propose bounded loopback observations", "deduplicate surface evidence"),
        required_inputs=("campaign_state", "scope_digest"),
        emitted_artifacts=("observation_proposal", "evidence_ref"),
    ),
    AgentRoleSpec(
        role="arex_authorization_researcher",
        implementation="webpent.agents.arex.authorization_researcher",
        responsibilities=("propose authorization comparisons", "identify safe negative controls"),
        required_inputs=("hypothesis", "target_knowledge"),
        emitted_artifacts=("authorization_proposal", "negative_control_plan"),
    ),
    AgentRoleSpec(
        role="arex_business_logic_researcher",
        implementation="webpent.agents.arex.business_logic_researcher",
        responsibilities=("propose read-only workflow comparisons", "record bounded preconditions"),
        required_inputs=("hypothesis", "workflow_state"),
        emitted_artifacts=("workflow_proposal", "precondition_ref"),
    ),
    AgentRoleSpec(
        role="arex_evidence_reviewer",
        implementation="webpent.agents.arex.evidence_reviewer",
        responsibilities=("review evidence completeness", "flag missing causal gates"),
        required_inputs=("observations", "negative_control", "proof_reference"),
        emitted_artifacts=("evidence_review", "review_evidence_ref"),
    ),
    AgentRoleSpec(
        role="arex_planner",
        implementation="webpent.agents.arex.planner",
        responsibilities=("rank bounded tasks", "respect budget and route capabilities"),
        required_inputs=("campaign_state", "candidate_tasks"),
        emitted_artifacts=("task_proposal", "planning_rationale"),
    ),
    AgentRoleSpec(
        role="application_analyst",
        implementation="webpent.agents.asros.application_analyst",
        responsibilities=("model workflows", "identify business-logic assumptions"),
        required_inputs=("world_model", "workflow_evidence"),
        emitted_artifacts=("workflow_model", "business_assumption"),
    ),
    AgentRoleSpec(
        role="authorization_analyst",
        implementation="webpent.agents.asros.authorization_analyst",
        responsibilities=("map trust boundaries", "propose identity comparisons"),
        required_inputs=("world_model", "invariant_evidence"),
        emitted_artifacts=("trust_boundary", "negative_control_plan"),
    ),
    AgentRoleSpec(
        role="adversarial_reasoner",
        implementation="webpent.agents.asros.adversarial_reasoner",
        responsibilities=("generate alternative hypotheses", "challenge causal explanations"),
        required_inputs=("argument_chain", "observations"),
        emitted_artifacts=("alternative_hypothesis", "challenge_note"),
    ),
    AgentRoleSpec(
        role="evidence_scientist",
        implementation="webpent.agents.asros.evidence_scientist",
        responsibilities=("assess proof completeness", "check redaction and replayability"),
        required_inputs=("observations", "proof_reference"),
        emitted_artifacts=("evidence_assessment", "proof_gap"),
    ),
    AgentRoleSpec(
        role="research_manager",
        implementation="webpent.agents.asros.research_manager",
        responsibilities=("sequence bounded research", "respect budget and policy gates"),
        required_inputs=("campaign_state", "quality_reviews", "candidate_tasks"),
        emitted_artifacts=("research_plan", "priority_rationale"),
    ),
)

_ROLE_BY_NAME = {spec.role: spec for spec in ROLE_SPECS}


def get_role_spec(role: str) -> AgentRoleSpec | None:
    """Return a role contract or None for an unknown role."""
    return _ROLE_BY_NAME.get(str(role).strip().lower())


def team_manifest() -> list[dict[str, Any]]:
    """Return JSON-safe role metadata for reports and capability artifacts."""
    return [asdict(spec) for spec in ROLE_SPECS]


_FORBIDDEN_ARTIFACT_KEYS = {
    "execute",
    "execution_request",
    "finding",
    "finding_id",
    "oracle_override",
    "policy_override",
    "scope_override",
}


def validate_role_artifact(role: str, artifact: Any) -> bool:
    """Accept only declared, advisory artifacts without authority-shaped keys."""
    spec = get_role_spec(role)
    if spec is None or not isinstance(artifact, dict) or not spec.advisory_only:
        return False
    if any(key in artifact for key in _FORBIDDEN_ARTIFACT_KEYS):
        return False
    declared = set(spec.emitted_artifacts)
    return any(key in artifact and artifact[key] not in (None, "", [], {}) for key in declared)


__all__ = [
    "AgentRoleSpec",
    "ROLE_SPECS",
    "get_role_spec",
    "team_manifest",
    "validate_role_artifact",
]
