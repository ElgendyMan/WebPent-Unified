"""AVRIP v2 cross-domain attack reasoning.

The output is a relationship hypothesis only.  It is intentionally unable to
approve, validate, execute, or promote a security finding.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from enum import Enum
from itertools import product

from pydantic import BaseModel, ConfigDict, Field

from webpent.avrip.assumptions import SecurityAssumption
from webpent.knowledge.model_v2 import KnowledgeRelation, TargetKnowledgeV2
from webpent.models.attack_graph import AttackGraph


class SecurityDomain(str, Enum):
    IDENTITY = "identity"
    RESOURCE = "resource"
    WORKFLOW = "workflow"
    PERMISSION = "permission"
    STATE = "state"


class CrossDomainLink(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    link_id: str = Field(min_length=1, max_length=220)
    domain: SecurityDomain
    node_id: str = Field(min_length=1, max_length=200)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)


class CrossDomainPath(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    path_id: str = Field(min_length=1, max_length=220)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    links: tuple[CrossDomainLink, ...] = Field(min_length=5, max_length=5)
    relationship_statement: str = Field(min_length=8, max_length=700)
    hypothesis_status: str = Field(default="potential", pattern="^(potential|blocked)$")
    missing_evidence: tuple[str, ...] = Field(default=(), max_length=16)
    advisory_only: bool = True

    @property
    def domains(self) -> tuple[SecurityDomain, ...]:
        return tuple(link.domain for link in self.links)


class CrossDomainReasoningReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: int = Field(default=2, frozen=True)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    paths: tuple[CrossDomainPath, ...] = Field(default=(), max_length=256)
    blocked_reasons: tuple[str, ...] = Field(default=(), max_length=32)
    advisory_only: bool = True


class CrossDomainAttackReasoner:
    """Join distinct security domains only when recorded graph links support it."""

    def reason(
        self,
        *,
        knowledge: TargetKnowledgeV2,
        attack_graph: AttackGraph,
        assumptions: Iterable[SecurityAssumption] = (),
    ) -> CrossDomainReasoningReport:
        if not isinstance(knowledge, TargetKnowledgeV2):
            raise TypeError("target_knowledge_v2_required")
        if not isinstance(attack_graph, AttackGraph):
            raise TypeError("attack_graph_required")
        graph_domains = _graph_domain_nodes(attack_graph)
        relation_domains = _knowledge_domain_nodes(knowledge)
        links_by_domain = {
            domain: tuple(
                dict.fromkeys((*graph_domains.get(domain, ()), *relation_domains.get(domain, ())))
            )
            for domain in SecurityDomain
        }
        paths: list[CrossDomainPath] = []
        blocked: list[str] = []
        required = (
            SecurityDomain.IDENTITY,
            SecurityDomain.RESOURCE,
            SecurityDomain.WORKFLOW,
            SecurityDomain.PERMISSION,
            SecurityDomain.STATE,
        )
        if any(not links_by_domain[domain] for domain in required):
            missing = ", ".join(domain.value for domain in required if not links_by_domain[domain])
            blocked.append(f"cross_domain_context_missing:{missing}")
        else:
            assumption_text = next(iter(assumptions), None)
            for index, selected in enumerate(
                product(*(links_by_domain[domain] for domain in required)),
                start=1,
            ):
                links = tuple(
                    CrossDomainLink(
                        link_id=f"link:{index}:{domain.value}",
                        domain=domain,
                        node_id=node_id,
                        evidence_refs=refs,
                    )
                    for domain, (node_id, refs) in zip(required, selected, strict=True)
                )
                refs = tuple(dict.fromkeys(ref for link in links for ref in link.evidence_refs))
                paths.append(
                    CrossDomainPath(
                        path_id=(
                            "cross:"
                            + _stable_id(
                                knowledge.target_id,
                                "|".join(link.node_id for link in links),
                            )
                        ),
                        engagement_id=knowledge.engagement_id,
                        target_id=knowledge.target_id,
                        links=links,
                        relationship_statement=(
                            "Identity reaches a resource through a workflow and permission "
                            "state transition; this is a potential boundary relationship, "
                            + "not proof of a vulnerability. Assumption context: "
                            + f"{getattr(assumption_text, 'statement', 'none')}"
                        ),
                        hypothesis_status="potential" if refs else "blocked",
                        missing_evidence=(
                            "causal_oracle",
                            "independent_negative_control",
                            "sealed_replayable_proof",
                        ),
                    )
                )
                if len(paths) >= 16:
                    break
        return CrossDomainReasoningReport(
            engagement_id=knowledge.engagement_id,
            target_id=knowledge.target_id,
            paths=tuple(paths),
            blocked_reasons=tuple(blocked),
        )


def _graph_domain_nodes(
    attack_graph: AttackGraph,
) -> dict[SecurityDomain, list[tuple[str, tuple[str, ...]]]]:
    result: dict[SecurityDomain, list[tuple[str, tuple[str, ...]]]] = {
        domain: [] for domain in SecurityDomain
    }
    for node in attack_graph.nodes.values():
        domain = _domain_for_kind(
            str(node.kind.value if hasattr(node.kind, "value") else node.kind)
        )
        if domain is not None:
            result[domain].append((node.id, tuple(node.source_refs)))
    return result


def _knowledge_domain_nodes(
    knowledge: TargetKnowledgeV2,
) -> dict[SecurityDomain, list[tuple[str, tuple[str, ...]]]]:
    result: dict[SecurityDomain, list[tuple[str, tuple[str, ...]]]] = {
        domain: [] for domain in SecurityDomain
    }
    for entity in knowledge.entities.values():
        domain = _domain_for_kind(entity.kind.value)
        if domain is not None:
            result[domain].append((entity.entity_id, tuple(entity.evidence_refs)))
    for relation in knowledge.relations:
        if not isinstance(relation, KnowledgeRelation):
            continue
        domain = _domain_for_relation(relation.relation)
        if domain is not None:
            result[domain].append((relation.relation_id, tuple(relation.evidence_refs)))
    return result


def _domain_for_kind(kind: str) -> SecurityDomain | None:
    return {
        "identity": SecurityDomain.IDENTITY,
        "user": SecurityDomain.IDENTITY,
        "role": SecurityDomain.PERMISSION,
        "permission": SecurityDomain.PERMISSION,
        "resource": SecurityDomain.RESOURCE,
        "object": SecurityDomain.RESOURCE,
        "workflow": SecurityDomain.WORKFLOW,
        "state": SecurityDomain.STATE,
    }.get(kind.lower())


def _domain_for_relation(relation: str) -> SecurityDomain | None:
    text = relation.lower()
    if any(token in text for token in ("state", "transition")):
        return SecurityDomain.STATE
    if any(token in text for token in ("permission", "role", "authorize")):
        return SecurityDomain.PERMISSION
    if "workflow" in text:
        return SecurityDomain.WORKFLOW
    if any(token in text for token in ("owner", "resource", "object")):
        return SecurityDomain.RESOURCE
    if any(token in text for token in ("identity", "user")):
        return SecurityDomain.IDENTITY
    return None


def _stable_id(target_id: str, value: str) -> str:
    return hashlib.sha256(f"{target_id}|{value}".encode()).hexdigest()[:24]


__all__ = [
    "CrossDomainAttackReasoner",
    "CrossDomainLink",
    "CrossDomainPath",
    "CrossDomainReasoningReport",
    "SecurityDomain",
]
