"""Evidence-linked, target-neutral vulnerability hypothesis generation.

The generator is deliberately a reasoning layer. It creates bounded hypotheses
from recorded knowledge and graph relations; it never sends requests, chooses
payloads, creates findings, or authorizes a validator.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import NAMESPACE_URL, uuid5

from webpent.attack_graph.chain_reasoning import VulnerabilityChainReasoner
from webpent.intelligence.contracts import ResearchHypothesis
from webpent.knowledge.model_v2 import KnowledgeEntityKind, TargetKnowledgeV2
from webpent.models.attack_graph import AttackGraph
from webpent.models.findings import Severity, VulnClass


@dataclass(frozen=True)
class VulnerabilityPattern:
    """A safe pattern description; it contains no payloads or executable actions."""

    name: str
    vuln_class: VulnClass
    required_capability: str
    risk: Severity
    required_relations: tuple[str, ...]
    required_entity_kinds: tuple[KnowledgeEntityKind, ...]
    evidence_needed: tuple[str, ...]
    validation_steps: tuple[str, ...]
    relation_match: str = "any"
    confidence_prior: float = 0.35


DEFAULT_PATTERNS: tuple[VulnerabilityPattern, ...] = (
    VulnerabilityPattern(
        name="object_authorization_boundary",
        vuln_class=VulnClass.IDOR,
        required_capability="http_read",
        risk=Severity.HIGH,
        required_relations=("can_access", "exposes"),
        required_entity_kinds=(KnowledgeEntityKind.ENDPOINT, KnowledgeEntityKind.RESOURCE),
        evidence_needed=(
            "owner baseline response",
            "non-owner candidate response",
            "independent negative control",
        ),
        validation_steps=(
            "compare owner and non-owner response semantics",
            "check an unrelated protected object as negative control",
            "require the existing causal oracle and replayable evidence",
        ),
        relation_match="all",
        confidence_prior=0.55,
    ),
    VulnerabilityPattern(
        name="sensitive_observation_exposure",
        vuln_class=VulnClass.INFO_DISCLOSURE,
        required_capability="http_read",
        risk=Severity.MEDIUM,
        required_relations=("exposes",),
        required_entity_kinds=(KnowledgeEntityKind.ENDPOINT,),
        evidence_needed=(
            "redacted response semantics",
            "sensitivity classification",
            "negative control",
        ),
        validation_steps=(
            "confirm the observation is reproducible",
            "classify impact without retaining raw content",
            "require an independent non-sensitive control",
        ),
        confidence_prior=0.4,
    ),
    VulnerabilityPattern(
        name="permission_boundary_mismatch",
        vuln_class=VulnClass.AUTH_BYPASS,
        required_capability="http_read",
        risk=Severity.HIGH,
        required_relations=("grants", "can_access", "exposes"),
        required_entity_kinds=(KnowledgeEntityKind.ENDPOINT, KnowledgeEntityKind.IDENTITY),
        evidence_needed=(
            "identity-to-permission relationship",
            "authorized and unauthorized response pair",
            "independent denial control",
        ),
        validation_steps=(
            "compare equivalent requests across explicit identity contexts",
            "verify the permission boundary is the only changed variable",
            "require causal oracle, denial control, and replayable evidence",
        ),
        relation_match="all",
        confidence_prior=0.5,
    ),
    VulnerabilityPattern(
        name="privilege_escalation_boundary",
        vuln_class=VulnClass.AUTH_BYPASS,
        required_capability="http_read",
        risk=Severity.CRITICAL,
        required_relations=("grants", "requires_role", "can_access", "exposes"),
        required_entity_kinds=(
            KnowledgeEntityKind.ENDPOINT,
            KnowledgeEntityKind.ROLE,
            KnowledgeEntityKind.PERMISSION,
        ),
        evidence_needed=(
            "role and permission mapping",
            "lower-privilege baseline",
            "higher-privilege comparison or denial control",
        ),
        validation_steps=(
            "compare the same protected operation across role contexts",
            "verify no role or session state changed during comparison",
            "stop unless the oracle separates authorization from reachability",
        ),
        relation_match="all",
        confidence_prior=0.6,
    ),
    VulnerabilityPattern(
        name="tenant_isolation_boundary",
        vuln_class=VulnClass.IDOR,
        required_capability="http_read",
        risk=Severity.HIGH,
        required_relations=("belongs_to", "scoped_by", "can_access", "exposes"),
        required_entity_kinds=(
            KnowledgeEntityKind.ENDPOINT,
            KnowledgeEntityKind.RESOURCE,
            KnowledgeEntityKind.TRUST_BOUNDARY,
        ),
        evidence_needed=(
            "resource-to-tenant relationship",
            "same-object owner-tenant baseline",
            "foreign-tenant denial control",
        ),
        validation_steps=(
            "compare identical object access across tenant contexts",
            "verify tenant identity and object identity independently",
            "require a causal cross-boundary oracle and replayable proof",
        ),
        relation_match="all",
        confidence_prior=0.58,
    ),
    VulnerabilityPattern(
        name="workflow_authorization_boundary",
        vuln_class=VulnClass.AUTH_BYPASS,
        required_capability="http_read",
        risk=Severity.HIGH,
        required_relations=("transitions", "requires", "can_access", "can_modify"),
        required_entity_kinds=(KnowledgeEntityKind.ENDPOINT, KnowledgeEntityKind.WORKFLOW),
        evidence_needed=(
            "workflow state model",
            "authorized transition baseline",
            "out-of-order or unauthorized transition control",
        ),
        validation_steps=(
            "compare allowed and disallowed workflow states without mutation",
            "verify state and identity are recorded independently",
            "require a state-aware oracle and safe reset before any active test",
        ),
        relation_match="all",
        confidence_prior=0.48,
    ),
    VulnerabilityPattern(
        name="parameter_reflection_surface",
        vuln_class=VulnClass.XSS,
        required_capability="http_read",
        risk=Severity.MEDIUM,
        required_relations=("accepts", "has_parameter", "contains_parameter", "reflects"),
        required_entity_kinds=(KnowledgeEntityKind.ENDPOINT, KnowledgeEntityKind.PARAMETER),
        evidence_needed=(
            "parameter-to-endpoint relationship",
            "redacted reflection context",
            "context-specific negative control",
        ),
        validation_steps=(
            "classify reflection context from recorded metadata",
            "require a non-executable canary comparison",
            "confirm only through a context-aware oracle and replayable evidence",
        ),
        relation_match="all",
        confidence_prior=0.32,
    ),
    VulnerabilityPattern(
        name="query_interpretation_surface",
        vuln_class=VulnClass.SQLI,
        required_capability="http_read",
        risk=Severity.HIGH,
        required_relations=("accepts", "has_parameter", "contains_parameter", "queries"),
        required_entity_kinds=(KnowledgeEntityKind.ENDPOINT, KnowledgeEntityKind.PARAMETER),
        evidence_needed=(
            "parameter-to-query relationship",
            "stable baseline semantics",
            "independent parser oracles and negative control",
        ),
        validation_steps=(
            "identify the parser boundary from recorded metadata only",
            "compare safe, non-destructive semantic controls",
            "require an oracle that distinguishes parser behavior from errors",
        ),
        relation_match="all",
        confidence_prior=0.3,
    ),
    VulnerabilityPattern(
        name="server_side_fetch_boundary",
        vuln_class=VulnClass.SSRF,
        required_capability="http_read",
        risk=Severity.HIGH,
        required_relations=("fetches", "resolves", "flows_to", "accepts"),
        required_entity_kinds=(KnowledgeEntityKind.ENDPOINT, KnowledgeEntityKind.DATA_FLOW),
        evidence_needed=(
            "endpoint-to-fetch data-flow relationship",
            "safe local canary semantics",
            "independent non-fetch control",
        ),
        validation_steps=(
            "confirm a server-side data-flow edge from recorded evidence",
            "use only an approved local canary in any future controlled lab",
            "require source-attribution oracle and replayable proof before promotion",
        ),
        relation_match="all",
        confidence_prior=0.38,
    ),
    VulnerabilityPattern(
        name="path_resolution_boundary",
        vuln_class=VulnClass.PATH_TRAVERSAL,
        required_capability="http_read",
        risk=Severity.HIGH,
        required_relations=("resolves", "reads", "accepts", "references"),
        required_entity_kinds=(KnowledgeEntityKind.ENDPOINT, KnowledgeEntityKind.PARAMETER),
        evidence_needed=(
            "path-like parameter relationship",
            "bounded canary or fixture reference",
            "independent safe path control",
        ),
        validation_steps=(
            "require a bounded fixture or canary rather than broad filesystem access",
            "compare canonical and non-canonical resolution semantics",
            "stop when raw traversal markers or external filesystem access are needed",
        ),
        relation_match="all",
        confidence_prior=0.3,
    ),
)


class HypothesisGenerator:
    """Generate ranked hypotheses from explicit model and graph facts only."""

    def __init__(
        self,
        patterns: tuple[VulnerabilityPattern, ...] = DEFAULT_PATTERNS,
        *,
        max_hypotheses: int = 256,
    ) -> None:
        self.patterns = tuple(sorted(patterns, key=lambda item: item.name))
        self.max_hypotheses = max(1, min(2000, int(max_hypotheses)))

    def generate(
        self,
        knowledge: TargetKnowledgeV2,
        graph: AttackGraph,
    ) -> tuple[ResearchHypothesis, ...]:
        if knowledge.engagement_id == "" or knowledge.target_id == "":
            return ()
        chains = VulnerabilityChainReasoner(max_hops=4, max_chains=64).derive(graph)
        hypotheses: list[ResearchHypothesis] = []
        for pattern in self.patterns:
            for endpoint in sorted(
                knowledge.entities_of_kind(KnowledgeEntityKind.ENDPOINT),
                key=lambda entity: entity.entity_id,
            ):
                related = self._related_edges(graph, endpoint.entity_id)
                relation_names = {str(edge.kind) for edge in related}
                if not self._relations_match(pattern, relation_names):
                    continue
                available_kinds = self._connected_kinds(knowledge, endpoint.entity_id, related)
                if any(kind.value not in available_kinds for kind in pattern.required_entity_kinds):
                    continue
                refs = tuple(
                    dict.fromkeys(
                        [
                            *endpoint.evidence_refs,
                            *(ref for edge in related for ref in edge.evidence_refs),
                        ]
                    )
                )[:32]
                if not refs:
                    continue
                chain = self._chain_for_endpoint(chains, endpoint.entity_id)
                chain_nodes = list(chain.node_ids) if chain else [endpoint.entity_id]
                chain_text = [f"node:{node_id}" for node_id in chain_nodes]
                chain_text.extend(
                    f"relation:{edge.kind}:{edge.source_id}->{edge.target_id}"
                    for edge in related[:8]
                )
                hypothesis_key = (
                    f"{knowledge.engagement_id}|{knowledge.target_id}|{pattern.name}|"
                    f"{endpoint.entity_id}"
                )
                edge_strength = 0.1 if all(edge.evidence_refs for edge in related) else 0.0
                endpoint_confidence = max(0.0, min(1.0, endpoint.confidence))
                confidence = min(
                    0.85,
                    max(
                        0.2,
                        (endpoint_confidence * 0.65) + pattern.confidence_prior + edge_strength,
                    ),
                )
                hypotheses.append(
                    ResearchHypothesis(
                        id=uuid5(NAMESPACE_URL, hypothesis_key),
                        target_url=endpoint.canonical_key,
                        reason=(
                            f"{pattern.name} is plausible for the observed endpoint; "
                            "the model does not establish exploitability."
                        ),
                        evidence_needed=list(pattern.evidence_needed),
                        attack_plan=list(pattern.validation_steps),
                        risk=pattern.risk,
                        confidence=round(confidence, 6),
                        vuln_class=pattern.vuln_class,
                        evidence_refs=list(refs),
                        affected_asset=endpoint.canonical_key,
                        reasoning_chain=chain_text[:16],
                        required_capability=pattern.required_capability,
                    )
                )
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return tuple(
            sorted(
                hypotheses,
                key=lambda item: (
                    -item.confidence,
                    -severity_order.get(
                        item.risk.value if hasattr(item.risk, "value") else str(item.risk),
                        0,
                    ),
                    -len(item.evidence_needed),
                    str(item.vuln_class),
                    str(item.id),
                ),
            )[: self.max_hypotheses]
        )

    @staticmethod
    def _related_edges(graph: AttackGraph, endpoint_id: str, *, max_hops: int = 2):
        frontier = {endpoint_id}
        visited = {endpoint_id}
        selected: dict[str, object] = {}
        for _ in range(max(1, min(4, max_hops))):
            next_frontier: set[str] = set()
            for edge in graph.edges:
                if edge.source_id not in frontier and edge.target_id not in frontier:
                    continue
                selected[edge.id] = edge
                for node_id in (edge.source_id, edge.target_id):
                    if node_id not in visited:
                        next_frontier.add(node_id)
            visited.update(next_frontier)
            frontier = next_frontier
            if not frontier:
                break
        return tuple(sorted(selected.values(), key=lambda edge: edge.id))

    @staticmethod
    def _connected_kinds(knowledge: TargetKnowledgeV2, endpoint_id: str, related) -> set[str]:
        node_ids = {endpoint_id}
        for edge in related:
            node_ids.update((edge.source_id, edge.target_id))
        return {
            entity.kind.value if hasattr(entity.kind, "value") else str(entity.kind)
            for entity in knowledge.entities.values()
            if entity.entity_id in node_ids
        }

    @staticmethod
    def _relations_match(pattern: VulnerabilityPattern, relation_names: set[str]) -> bool:
        required = set(pattern.required_relations)
        if pattern.relation_match == "all":
            return required.issubset(relation_names)
        return bool(required.intersection(relation_names))

    @staticmethod
    def _chain_for_endpoint(chains, endpoint_id: str):
        for chain in chains:
            if endpoint_id in chain.node_ids:
                return chain
        return None


__all__ = ["DEFAULT_PATTERNS", "HypothesisGenerator", "VulnerabilityPattern"]
