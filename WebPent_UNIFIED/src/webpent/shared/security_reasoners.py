"""Deterministic, proposal-only security reasoners.

The reasoners turn observed target semantics into bounded investigation proposals.
They do not create findings, send requests, mint credentials, or bypass
``ActionAuthority``.  A proposal is useful only as an input to the existing
research/experiment and proof-gated execution paths.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.knowledge.target_knowledge import KnowledgeKind, TargetKnowledgeModel
from webpent.models.evidence import redact_sensitive
from webpent.models.findings import VulnClass

ReasonerName = Literal["authorization", "business_logic", "authentication"]


class ReasoningProposal(BaseModel):
    """A bounded hypothesis proposal; never a finding or executable task."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    proposal_id: str = Field(..., min_length=8, max_length=128)
    reasoner: ReasonerName
    vuln_class: VulnClass = VulnClass.UNKNOWN
    statement: str = Field(..., min_length=3, max_length=500)
    target_refs: list[str] = Field(default_factory=list, max_length=8)
    evidence_refs: list[str] = Field(default_factory=list, max_length=16)
    prerequisites: list[str] = Field(default_factory=list, max_length=12)
    expected_signal: str = Field(..., min_length=3, max_length=300)
    negative_control: str = Field(..., min_length=3, max_length=300)
    execution_mode: Literal["proposal_only"] = "proposal_only"
    requires_action_authority: bool = True
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    @field_validator(
        "proposal_id",
        "statement",
        "target_refs",
        "evidence_refs",
        "prerequisites",
        "expected_signal",
        "negative_control",
        mode="before",
    )
    @classmethod
    def _redact_text(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


_MAX_PROPOSALS = 32
_MAX_REFS = 16


def _bounded_unique(values: list[Any], *, limit: int = _MAX_REFS) -> list[str]:
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        clean, _ = redact_sensitive(value.strip())
        if not isinstance(clean, str) or not clean or len(clean) > 240:
            continue
        if clean not in result:
            result.append(clean)
        if len(result) >= limit:
            break
    return result


def _proposal_id(reasoner: str, *parts: str) -> str:
    material = "|".join([reasoner, *parts])
    return str(uuid5(NAMESPACE_URL, f"webpent:security-reasoner:{material}"))


def _evidence_for_node(model: TargetKnowledgeModel, node_id: str) -> list[str]:
    node = model.nodes.get(node_id)
    return list(node.evidence_refs) if node is not None else []


def _node_ids_of_kind(model: TargetKnowledgeModel, kind: KnowledgeKind) -> list[str]:
    return [node_id for node_id, node in model.nodes.items() if node.kind == kind]


def _confidence(*values: float) -> float:
    values = [value for value in values if 0.0 <= value <= 1.0]
    return round(sum(values) / len(values), 3) if values else 0.0


class AuthorizationReasoner:
    """Propose differential authorization checks from observed ownership edges."""

    name: ReasonerName = "authorization"

    def propose(self, model: TargetKnowledgeModel) -> list[ReasoningProposal]:
        identities = _node_ids_of_kind(model, KnowledgeKind.IDENTITY)
        if len(identities) < 2:
            return []
        proposals: list[ReasoningProposal] = []
        for edge in model.edges:
            relation = edge.relation.strip().casefold()
            source = model.nodes.get(edge.source_id)
            target = model.nodes.get(edge.target_id)
            if relation not in {"owns", "owner_of", "has_owner"}:
                continue
            if source is None or target is None:
                continue
            if source.kind != KnowledgeKind.IDENTITY or target.kind != KnowledgeKind.OBJECT:
                continue
            evidence = _bounded_unique(
                [*edge.evidence_refs, *source.evidence_refs, *target.evidence_refs]
            )
            if not evidence:
                continue
            proposals.append(
                ReasoningProposal(
                    proposal_id=_proposal_id(self.name, edge.source_id, edge.target_id),
                    reasoner=self.name,
                    vuln_class=VulnClass.IDOR,
                    statement=(
                        "Compare access to the observed object under the owning and "
                        "a separate observed identity."
                    ),
                    target_refs=_bounded_unique([edge.source_id, edge.target_id]),
                    evidence_refs=evidence,
                    prerequisites=[
                        "two_observed_identities",
                        "object_reference",
                        "same_object_baseline",
                        "independent_negative_control",
                        "sealed_replayable_proof",
                    ],
                    expected_signal=(
                        "The non-owner receives the owner's object response while "
                        "the owner baseline remains valid."
                    ),
                    negative_control=(
                        "Replay the owner request and a clearly unrelated object "
                        "reference; do not promote on status code alone."
                    ),
                    confidence=_confidence(edge.confidence, source.confidence, target.confidence),
                )
            )
            if len(proposals) >= _MAX_PROPOSALS:
                break
        return proposals


class BusinessLogicReasoner:
    """Propose workflow/state-machine checks from observed transitions."""

    name: ReasonerName = "business_logic"

    def propose(self, model: TargetKnowledgeModel) -> list[ReasoningProposal]:
        proposals: list[ReasoningProposal] = []
        for workflow_id, workflow in model.workflows.items():
            if not workflow.transitions:
                continue
            evidence = _bounded_unique(
                [*workflow.evidence_refs, *workflow.identity_refs]
            )
            if not evidence:
                continue
            transition = workflow.transitions[0]
            method = str(transition.get("method") or "").upper()
            if method not in {"POST", "PUT", "PATCH", "DELETE"}:
                continue
            refs = [workflow_id, *workflow.identity_refs]
            statement = (
                "Test whether the observed workflow transition can be replayed or "
                "reordered outside its expected state."
            )
            proposals.append(
                ReasoningProposal(
                    proposal_id=_proposal_id(self.name, workflow_id, method),
                    reasoner=self.name,
                    vuln_class=VulnClass.RACE_CONDITION,
                    statement=statement,
                    target_refs=_bounded_unique(refs),
                    evidence_refs=evidence,
                    prerequisites=[
                        "observed_state_transition",
                        "read_only_baseline_or_operator_approval",
                        "bounded_replay_budget",
                        "independent_negative_control",
                        "sealed_replayable_proof",
                    ],
                    expected_signal=(
                        "A state-changing transition succeeds more than once or "
                        "succeeds from an invalid observed state."
                    ),
                    negative_control=(
                        "Use a fresh control identity/object and compare the exact "
                        "state delta, not only HTTP status."
                    ),
                    confidence=_confidence(workflow.confidence),
                )
            )
            if workflow.required_role:
                proposals.append(
                    ReasoningProposal(
                        proposal_id=_proposal_id(self.name, workflow_id, "role-boundary"),
                        reasoner=self.name,
                        vuln_class=VulnClass.AUTH_BYPASS,
                        statement=(
                            "Compare the observed workflow role boundary for the "
                            "required role without inferring permission from its label."
                        ),
                        target_refs=_bounded_unique(refs),
                        evidence_refs=evidence,
                        prerequisites=[
                            "observed_role_boundary",
                            "two_identity_contexts",
                            "independent_negative_control",
                            "sealed_replayable_proof",
                        ],
                        expected_signal=(
                            "An identity lacking the observed role causes the same "
                            "authorized state transition."
                        ),
                        negative_control=(
                            "Replay with the observed role identity and a non-target "
                            "workflow object to rule out an application-wide success path."
                        ),
                        confidence=_confidence(workflow.confidence, 0.5),
                    )
                )
            if len(proposals) >= _MAX_PROPOSALS:
                break
        return proposals[:_MAX_PROPOSALS]


class AuthenticationReasoner:
    """Propose identity-lifecycle checks from explicit redacted observations."""

    name: ReasonerName = "authentication"

    def propose(self, observations: dict[str, Any]) -> list[ReasoningProposal]:
        if not isinstance(observations, dict):
            return []
        lifecycle = observations.get("lifecycle_observations") or []
        if not isinstance(lifecycle, list):
            return []
        stages = {
            str(item).strip().casefold()
            for item in lifecycle
            if isinstance(item, str) and item.strip()
        }
        evidence = _bounded_unique(observations.get("evidence_refs") or [])
        if not evidence or not ({"login", "session"} <= stages):
            return []
        if not stages.intersection({"register", "reset", "mfa", "logout"}):
            return []
        lifecycle_key = sha256("|".join(sorted(stages)).encode()).hexdigest()[:24]
        return [
            ReasoningProposal(
                proposal_id=_proposal_id(self.name, lifecycle_key),
                reasoner=self.name,
                vuln_class=VulnClass.AUTH_BYPASS,
                statement=(
                    "Compare authentication lifecycle boundaries across login, "
                    "session, and the observed adjacent identity stage."
                ),
                target_refs=_bounded_unique([str(observations.get("engagement_id") or "")]),
                evidence_refs=evidence,
                prerequisites=[
                    "observed_authentication_lifecycle",
                    "fresh_identity_or_operator_supplied_identity",
                    "session_invalidation_check",
                    "independent_negative_control",
                    "sealed_replayable_proof",
                ],
                expected_signal=(
                    "A session remains usable across an observed invalidation or "
                    "identity boundary where the control session is rejected."
                ),
                negative_control=(
                    "Verify a fresh unauthenticated session and a valid control "
                    "session separately; never treat cookie presence as proof."
                ),
                confidence=0.5,
            )
        ]


def propose_security_reasoning(
    model: TargetKnowledgeModel | None,
    authentication_observations: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Run deterministic reasoners and return bounded state-safe proposals.

    This is an advisory projection only.  The helper intentionally accepts an
    already-built knowledge model and never accepts a transport/client; any
    execution remains behind the existing action-authority and proof gates.
    """
    if model is None:
        return []
    proposals = [
        *AuthorizationReasoner().propose(model),
        *BusinessLogicReasoner().propose(model),
        *AuthenticationReasoner().propose(authentication_observations or {}),
    ]
    return [proposal.model_dump(mode="json") for proposal in proposals[:_MAX_PROPOSALS]]


__all__ = [
    "AuthenticationReasoner",
    "AuthorizationReasoner",
    "BusinessLogicReasoner",
    "ReasoningProposal",
    "propose_security_reasoning",
]
