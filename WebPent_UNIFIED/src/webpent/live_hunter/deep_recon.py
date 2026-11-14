"""TEAM-1 DEEP RECON & SCHEMA-TO-HYPOTHESIS V1 — producer of structured knowledge.

Pipeline: REAL TARGET OBSERVATION → DEEP RECON → NORMALIZED TARGET SCHEMA →
PRINCIPALS → RESOURCES/OBJECTS → ACTIONS → PARAMETERS → RELATIONSHIPS →
AUTHORIZATION/TRUST BOUNDARIES → ATTACK SURFACES → HYPOTHESES → UNRESOLVED QUESTIONS →
DISCRIMINATING EXPERIMENTS → EXISTING AUTONOMOUS RESEARCH LOOP.

HARD CONSTRAINTS:
- Deep Recon is a PRODUCER for the world model and the research decision path. NOT a second planner.
- ONE authoritative research decision path remains: ResearchDecisionEngine +
  SmartNextBestActionEngine (shared/research_contracts.py + shared/research_intelligence.py),
  invoked from smart_campaigns / active_research nodes. (FV-2 note: an earlier revision of
  this docstring named ResearchControlLoop as the authority; that class is a library
  component with unit coverage but zero runtime call sites — the runtime authority is
  ResearchDecisionEngine, verified live during the final verification pass.)
- Schema data marked STRUCTURAL/SCHEMA-DERIVED — NOT proof of vulnerability.
- "GET /users/{id}" does NOT imply IDOR — only creates attack-relevant surface/hypothesis candidate.
- Relationships: OBSERVED (direct evidence) / INFERRED (reason+confidence+uncertainty) / UNKNOWN (→ unresolved question).
- Trust boundaries are QUESTIONS, not confirmed authorization vulnerabilities.
- Generic — no hardcoded app/endpoint/vuln/branch/hypothesis sequence/candidate order/planted marker.
- No unrestricted crawling, no scope bypass, no ToolBoundary bypass, no unauthorized requests.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Final

from webpent.live_hunter.world_model import (
    Entity,
    EntityType,
    EvidenceGraph,
    Relation,
    RelationType,
    _uid,
    _utc,
    sanitize_text,
)


# ---------- Evidence tiers (Phase 1+3) ----------
class EvidenceTier(str, Enum):
    OBSERVED = "observed_runtime"          # direct runtime observation — strongest
    SCHEMA_DERIVED = "schema_derived"       # from OpenAPI/GraphQL/route — structural, NOT proof
    INFERRED = "inferred"                   # deterministic inference with confidence
    UNKNOWN = "unknown"                     # creates unresolved question, not a fact


class PrincipalCategory(str, Enum):
    ANONYMOUS = "anonymous"
    AUTHENTICATED_USER = "authenticated_user"
    PRIVILEGED_USER = "privileged_user"
    SERVICE_IDENTITY = "service_identity"
    ADMINISTRATOR = "administrator"
    TEST_PRINCIPAL = "test_principal"


class ParameterLocation(str, Enum):
    PATH = "path"; QUERY = "query"; BODY = "body"; HEADER = "header"
    COOKIE = "cookie"; GRAPHQL_ARG = "graphql_argument"; JSON_FIELD = "json_field"


class ActionType(str, Enum):
    READ = "read"; CREATE = "create"; UPDATE = "update"; DELETE = "delete"
    RPC = "rpc_action"; GRAPHQL = "graphql_operation"; UNKNOWN = "unknown"


# ---------- Phase 1: Reconnaissance contract entities ----------
@dataclass(frozen=True)
class ReconPrincipal:
    """Principal discovered via recon. Role NOT assumed from string alone — requires evidence."""
    principal_id: str
    category: PrincipalCategory
    normalized_identifier: str  # safe, sanitized
    source_evidence_refs: tuple[str, ...]
    confidence: float  # 0.0-1.0, derived from evidence strength
    observation_provenance: str  # where observed (e.g. "response_401", "login_endpoint", "schema")
    attributes: dict[str, Any] = field(default_factory=dict)
    evidence_tier: EvidenceTier = EvidenceTier.OBSERVED

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True, default=str).encode()).hexdigest()[:16]


@dataclass(frozen=True)
class ReconResource:
    """Discovered application object/resource. Structural identity only."""
    resource_id: str
    normalized_identity: str  # e.g. "user", "order", "document" — structural, not target-specific
    source_evidence_refs: tuple[str, ...]
    observed_identifiers: tuple[str, ...]  # parameter names that identify it
    relationship_hints: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)
    evidence_tier: EvidenceTier = EvidenceTier.OBSERVED


@dataclass(frozen=True)
class ReconAction:
    """Discovered action/endpoint. Structural only."""
    action_id: str
    endpoint_identity: str  # path_shape, e.g. "/api/{resource}/{id}"
    action_type: ActionType
    method_or_operation: str  # GET/POST/PUT/DELETE/query/mutation
    principal_context: str | None  # which principal category observed
    parameter_refs: tuple[str, ...] = ()
    response_observation: str = ""  # structural digest, sanitized
    provenance: str = ""
    evidence_tier: EvidenceTier = EvidenceTier.OBSERVED


@dataclass(frozen=True)
class ReconParameter:
    """Discovered parameter. NOT classified security-sensitive purely from name."""
    parameter_id: str
    name: str
    location: ParameterLocation
    structural_type: str  # int/str/json/uuid/path — structural only
    referenced_resource: str | None = None  # if it identifies a resource (structural hint)
    evidence_tier: EvidenceTier = EvidenceTier.OBSERVED
    security_sensitive: bool = False  # only set from evidence, never from name alone


# ---------- Phase 4: Relationship inference ----------
class RelationshipStrength(str, Enum):
    OBSERVED = "observed"          # direct evidence — may be treated as fact
    INFERRED = "inferred"          # carries reason + confidence + uncertainty
    UNKNOWN = "unknown"            # creates unresolved question, NOT a fact


@dataclass(frozen=True)
class InferredRelationship:
    relation_id: str
    relation_type: str  # e.g. "principal_owns_resource", "action_mutates_resource"
    source_id: str
    target_id: str
    strength: RelationshipStrength
    inference_reason: str = ""      # required for INFERRED
    supporting_observations: tuple[str, ...] = ()
    confidence: float = 0.0         # required for INFERRED
    uncertainty: float = 1.0        # required for INFERRED (1.0 = fully uncertain)

    def __post_init__(self):
        if self.strength is RelationshipStrength.INFERRED:
            if not self.inference_reason: raise ValueError("INFERRED relationship requires inference_reason")
            if not self.supporting_observations: raise ValueError("INFERRED relationship requires supporting_observations")
            if self.confidence <= 0.0: raise ValueError("INFERRED relationship requires confidence > 0")
        if self.strength is RelationshipStrength.UNKNOWN:
            pass  # UNKNOWN creates unresolved question, validated at graph insertion


# ---------- Phase 5: Trust boundaries (questions, not confirmed vulns) ----------
@dataclass(frozen=True)
class TrustBoundary:
    """Potential security boundary. A QUESTION, not a confirmed authorization vulnerability."""
    boundary_id: str
    from_principal_category: PrincipalCategory
    to_principal_category: PrincipalCategory
    resource_ref: str | None = None
    boundary_type: str = ""  # e.g. "anonymous_to_authenticated", "user_to_admin", "tenant_to_tenant"
    question_text: str = ""  # the unresolved question this boundary raises
    confidence: float = 0.0
    evidence_refs: tuple[str, ...] = ()

    def to_unresolved_question(self) -> dict[str, Any]:
        """Trust boundary becomes an unresolved question — NEVER a confirmed vuln."""
        return {
            "question_id": f"q_{self.boundary_id}",
            "text": sanitize_text(self.question_text or
                f"Does crossing boundary {self.boundary_type} enforce authorization on resource {self.resource_ref}?"),
            "hypothesis_refs": (),
            "resolution_status": "open",
            "boundary_origin": True,
            "confidence": self.confidence,
        }


# ---------- Phase 2+3: Surface discovery + schema ingestion ----------
class DeepReconEngine:
    """Deep Recon: producer of structured knowledge for World Model + ResearchControlLoop.
    NOT a planner. Answers 'What exists? What relationships? What trust boundaries? What's missing?'."""

    MAX_RESOURCES: Final[int] = 500
    MAX_ACTIONS: Final[int] = 2000
    MAX_PARAMETERS: Final[int] = 5000
    MAX_PRINCIPALS: Final[int] = 50
    MAX_TRUST_BOUNDARIES: Final[int] = 100

    def __init__(self, *, engagement_id: str, graph: EvidenceGraph | None = None) -> None:
        self.engagement_id = engagement_id
        self.graph = graph or EvidenceGraph(engagement_id=engagement_id)
        self.principals: dict[str, ReconPrincipal] = {}
        self.resources: dict[str, ReconResource] = {}
        self.actions: dict[str, ReconAction] = {}
        self.parameters: dict[str, ReconParameter] = {}
        self.relationships: list[InferredRelationship] = []
        self.trust_boundaries: list[TrustBoundary] = []
        self.hypotheses_generated: list[str] = []
        self.unresolved_questions: list[dict[str, Any]] = []
        self._update_log: list[dict[str, Any]] = []

    # ---------- Phase 2: Surface discovery (generic) ----------
    def ingest_route_observation(self, *, path: str, method: str, status_code: int,
                                 response_body: str = "", response_headers: dict | None = None,
                                 parameters: dict | None = None, principal_context: str | None = None) -> str:
        """Generic route observation → normalized schema entities. Structural only."""
        path_shape = re.sub(r"/\d+", "/{id}", str(path or ""))
        path_shape = re.sub(r"/[0-9a-f]{8,}", "/{id}", path_shape)
        action_type = self._infer_action_type(method)
        action_id = _uid("act")
        action = ReconAction(
            action_id=action_id, endpoint_identity=path_shape, action_type=action_type,
            method_or_operation=str(method or "").upper(), principal_context=principal_context,
            response_observation=self._response_structural_digest(response_body, response_headers or {}),
            provenance="route_observation", evidence_tier=EvidenceTier.OBSERVED)
        if len(self.actions) >= self.MAX_ACTIONS:
            raise RuntimeError(f"deep_recon_bounded: action limit {self.MAX_ACTIONS} reached")
        self.actions[action_id] = action
        # Parameters
        params = parameters or {}
        param_refs = []
        for pname, pval in sorted(params.items()):
            pid = _uid("param")
            location = self._infer_param_location(pname, path)
            ptype = self._infer_structural_type(pval)
            param = ReconParameter(parameter_id=pid, name=sanitize_text(pname), location=location,
                                   structural_type=ptype, evidence_tier=EvidenceTier.OBSERVED,
                                   security_sensitive=False)  # never from name alone
            if len(self.parameters) < self.MAX_PARAMETERS:
                self.parameters[pid] = param
                param_refs.append(pid)
        # Resource inference from path
        resource_id = self._infer_resource_from_path(path_shape)
        if resource_id and resource_id not in self.resources and len(self.resources) < self.MAX_RESOURCES:
            self.resources[resource_id] = ReconResource(
                resource_id=resource_id, normalized_identity=resource_id,
                source_evidence_refs=(action_id,), observed_identifiers=tuple(param_refs),
                evidence_tier=EvidenceTier.INFERRED)
        # Auth observation → principal
        if status_code in (401, 403) and "anonymous" not in self.principals:
            self._register_principal("anonymous", PrincipalCategory.ANONYMOUS, "anonymous",
                                     (action_id,), 0.9, "auth_challenge_observed")
        self._update_log.append({"event": "route_ingested", "action_id": action_id, "path_shape": path_shape,
                                 "timestamp": _utc()})
        return action_id

    @staticmethod
    def _infer_action_type(method: str) -> ActionType:
        m = str(method or "").upper()
        if m in {"GET", "HEAD", "OPTIONS"}: return ActionType.READ
        if m == "POST": return ActionType.CREATE
        if m in {"PUT", "PATCH"}: return ActionType.UPDATE
        if m == "DELETE": return ActionType.DELETE
        return ActionType.UNKNOWN

    @staticmethod
    def _infer_param_location(name: str, path: str) -> ParameterLocation:
        if "{" in path and f"{{{name}}}" in path: return ParameterLocation.PATH
        if name.lower() in {"authorization", "cookie", "x-api-key"}: return ParameterLocation.HEADER
        return ParameterLocation.QUERY

    @staticmethod
    def _infer_structural_type(value) -> str:
        v = str(value or "")
        if re.match(r"^\d+$", v): return "int"
        if re.match(r"^[0-9a-f]{8}-", v, re.IGNORECASE): return "uuid"
        if v.startswith("{") or v.startswith("["): return "json"
        return "str"

    @staticmethod
    def _infer_resource_from_path(path_shape: str) -> str | None:
        """Structural resource inference from path. No target-specific labels."""
        segments = [s for s in path_shape.split("/") if s and "{" not in s]
        if not segments: return None
        # Last non-id segment is the resource (structural)
        return segments[-1].lower()

    @staticmethod
    def _response_structural_digest(body: str, headers: dict) -> str:
        struct = {"header_keys": sorted(str(k).lower() for k in headers),
                  "body_length_class": len(body or "") // 1000}
        try:
            parsed = json.loads(body or "{}")
            if isinstance(parsed, dict): struct["body_keys"] = sorted(str(k) for k in parsed.keys())[:20]
        except Exception: struct["body_is_text"] = True
        return hashlib.sha256(json.dumps(struct, sort_keys=True).encode()).hexdigest()[:12]

    def _register_principal(self, pid: str, category: PrincipalCategory, identifier: str,
                            evidence_refs: tuple, confidence: float, provenance: str) -> None:
        if len(self.principals) >= self.MAX_PRINCIPALS: raise RuntimeError("principal limit")
        self.principals[pid] = ReconPrincipal(
            principal_id=pid, category=category, normalized_identifier=sanitize_text(identifier),
            source_evidence_refs=evidence_refs, confidence=confidence,
            observation_provenance=provenance, evidence_tier=EvidenceTier.OBSERVED)

    # ---------- Phase 3: Schema ingestion (OpenAPI/GraphQL) — STRUCTURAL, NOT proof ----------
    def ingest_openapi_schema(self, schema: dict[str, Any]) -> int:
        """Generic OpenAPI/Swagger ingestion → World Model entities.
        Marked SCHEMA_DERIVED. A schema saying GET /users/{id} does NOT imply IDOR."""
        if not isinstance(schema, dict): raise ValueError("schema must be dict")
        paths = schema.get("paths", {})
        count = 0
        for path, methods in paths.items():
            if not isinstance(methods, dict): continue
            for method, op in methods.items():
                if method.lower() not in {"get","post","put","patch","delete","head","options"}: continue
                action_id = _uid("act")
                path_shape = re.sub(r"\{[^}]+\}", "{id}", str(path))
                action_type = self._infer_action_type(method)
                params = []
                for p in op.get("parameters", []) if isinstance(op, dict) else []:
                    if isinstance(p, dict): params.append(p.get("name", "unknown"))
                action = ReconAction(
                    action_id=action_id, endpoint_identity=path_shape, action_type=action_type,
                    method_or_operation=method.upper(), principal_context=None,
                    parameter_refs=tuple(_uid("param") for _ in params),
                    provenance="openapi_schema", evidence_tier=EvidenceTier.SCHEMA_DERIVED)
                if len(self.actions) < self.MAX_ACTIONS:
                    self.actions[action_id] = action; count += 1
                # Resource from path (structural)
                rid = self._infer_resource_from_path(path_shape)
                if rid and rid not in self.resources and len(self.resources) < self.MAX_RESOURCES:
                    self.resources[rid] = ReconResource(
                        resource_id=rid, normalized_identity=rid, source_evidence_refs=(action_id,),
                        observed_identifiers=(), evidence_tier=EvidenceTier.SCHEMA_DERIVED)
        self._update_log.append({"event": "openapi_ingested", "actions_added": count, "timestamp": _utc()})
        return count

    def ingest_graphql_schema(self, schema: dict[str, Any]) -> int:
        """Generic GraphQL schema ingestion. Marked SCHEMA_DERIVED."""
        if not isinstance(schema, dict): raise ValueError("schema must be dict")
        types = schema.get("__schema", {}).get("types", []) if "__schema" in schema else schema.get("types", [])
        count = 0
        for t in types:
            if not isinstance(t, dict): continue
            kind = t.get("kind", "")
            name = t.get("name", "")
            if kind in {"QUERY", "MUTATION"}:
                for f in t.get("fields", []):
                    if not isinstance(f, dict): continue
                    action_id = _uid("act")
                    action = ReconAction(
                        action_id=action_id, endpoint_identity=f"graphql:{name}.{f.get('name','?')}",
                        action_type=ActionType.GRAPHQL if kind=="QUERY" else ActionType.GRAPHQL,
                        method_or_operation=kind, principal_context=None,
                        provenance="graphql_schema", evidence_tier=EvidenceTier.SCHEMA_DERIVED)
                    if len(self.actions) < self.MAX_ACTIONS:
                        self.actions[action_id] = action; count += 1
        self._update_log.append({"event": "graphql_ingested", "actions_added": count, "timestamp": _utc()})
        return count

    # ---------- Phase 4: Relationship inference (deterministic, OBSERVED/INFERRED/UNKNOWN) ----------
    def infer_relationships(self) -> tuple[InferredRelationship, ...]:
        """Deterministic relationship extraction. INFERRED carries reason+confidence+uncertainty.
        UNKNOWN creates unresolved questions, not facts."""
        inferred = []
        # Action → targets → Resource (INFERRED from path, structural)
        for action in self.actions.values():
            rid = self._infer_resource_from_path(action.endpoint_identity)
            if rid and rid in self.resources:
                rel = InferredRelationship(
                    relation_id=_uid("rel"), relation_type="action_targets_resource",
                    source_id=action.action_id, target_id=rid,
                    strength=RelationshipStrength.INFERRED,
                    inference_reason=f"path {action.endpoint_identity} structurally references resource {rid}",
                    supporting_observations=(action.action_id,), confidence=0.6, uncertainty=0.4)
                inferred.append(rel)
        # Parameter → identifies → Resource (INFERRED if param name matches resource id pattern)
        for param in self.parameters.values():
            if param.structural_type in {"int", "uuid"} and param.location == ParameterLocation.PATH:
                rid = self._infer_resource_from_path(
                    next((a.endpoint_identity for a in self.actions.values()
                          if param.parameter_id in a.parameter_refs), ""))
                if rid and rid in self.resources:
                    rel = InferredRelationship(
                        relation_id=_uid("rel"), relation_type="parameter_identifies_resource",
                        source_id=param.parameter_id, target_id=rid,
                        strength=RelationshipStrength.INFERRED,
                        inference_reason=f"path parameter {param.name} structurally identifies resource {rid}",
                        supporting_observations=(param.parameter_id,), confidence=0.5, uncertainty=0.5)
                    inferred.append(rel)
        self.relationships.extend(inferred)
        return tuple(inferred)

    # ---------- Phase 5: Trust boundary extraction (questions, not confirmed vulns) ----------
    def extract_trust_boundaries(self) -> tuple[TrustBoundary, ...]:
        """Semantic representation of potential security boundaries.
        A suspected trust boundary is NOT a confirmed authorization vulnerability — it becomes a QUESTION."""
        boundaries = []
        cats = {p.category for p in self.principals.values()}
        # anonymous → authenticated (if both observed)
        if PrincipalCategory.ANONYMOUS in cats and PrincipalCategory.AUTHENTICATED_USER in cats:
            boundaries.append(self._make_boundary(PrincipalCategory.ANONYMOUS, PrincipalCategory.AUTHENTICATED_USER,
                                                  "anonymous_to_authenticated"))
        # user → administrator
        if PrincipalCategory.AUTHENTICATED_USER in cats and PrincipalCategory.ADMINISTRATOR in cats:
            boundaries.append(self._make_boundary(PrincipalCategory.AUTHENTICATED_USER, PrincipalCategory.ADMINISTRATOR,
                                                  "user_to_administrator"))
        # user → privileged
        if PrincipalCategory.AUTHENTICATED_USER in cats and PrincipalCategory.PRIVILEGED_USER in cats:
            boundaries.append(self._make_boundary(PrincipalCategory.AUTHENTICATED_USER, PrincipalCategory.PRIVILEGED_USER,
                                                  "user_to_privileged"))
        # client → server (always present as structural boundary)
        boundaries.append(self._make_boundary(PrincipalCategory.ANONYMOUS, PrincipalCategory.SERVICE_IDENTITY,
                                              "client_to_server"))
        self.trust_boundaries.extend(boundaries)
        # Each boundary → unresolved question (NOT a confirmed vuln)
        for b in boundaries:
            self.unresolved_questions.append(b.to_unresolved_question())
        return tuple(boundaries)

    def _make_boundary(self, from_cat, to_cat, btype) -> TrustBoundary:
        return TrustBoundary(
            boundary_id=_uid("tb"), from_principal_category=from_cat, to_principal_category=to_cat,
            resource_ref=None, boundary_type=btype,
            question_text=f"Does crossing {btype} enforce authorization? (unresolved question — NOT confirmed vuln)",
            confidence=0.3, evidence_refs=tuple(p.principal_id for p in self.principals.values()
                                                if p.category in {from_cat, to_cat}))

    # ---------- Integration: produce hypotheses + unresolved questions for ResearchControlLoop ----------
    def generate_hypothesis_candidates(self) -> tuple[dict[str, Any], ...]:
        """Produce attack-relevant surface/hypothesis candidates from recon.
        STRUCTURAL only — 'GET /users/{id}' does NOT imply IDOR. These feed the existing loop."""
        candidates = []
        for action in self.actions.values():
            rid = self._infer_resource_from_path(action.endpoint_identity)
            if not rid: continue
            # Structural hypothesis: "parameter on resource may have authorization boundary question"
            # NOT "this is IDOR"
            hyp_id = _uid("hyp")
            statement = (f"Action {action.method_or_operation} on resource '{rid}' "
                         f"(path {action.endpoint_identity}) may expose an authorization/trust boundary question. "
                         f"Evidence tier: {action.evidence_tier.value}. Requires discriminating experiment.")
            candidates.append({
                "hypothesis_id": hyp_id, "statement": sanitize_text(statement),
                "branch_id": f"surface_{rid}", "source": "deep_recon",
                "evidence_tier": action.evidence_tier.value,
                "unresolved_questions": [q["question_id"] for q in self.unresolved_questions],
                "attack_surface": True, "confirmed_vulnerability": False,
            })
        self.hypotheses_generated = [c["hypothesis_id"] for c in candidates]
        return tuple(candidates)

    def project_to_world_model(self) -> EvidenceGraph:
        """Phase 3+9: Project recon entities into World Model. Schema-derived marked appropriately.
        LLM cannot mutate truth — all provenance deterministic."""
        g = self.graph
        # Principals
        for p in self.principals.values():
            g.add_entity(Entity(p.principal_id, EntityType.PRINCIPAL,
                                {"category": p.category.value, "identifier": p.normalized_identifier,
                                 "confidence": p.confidence, "evidence_tier": p.evidence_tier.value},
                                provenance="deep_recon_observed"))
        # Resources
        for r in self.resources.values():
            g.add_entity(Entity(r.resource_id, EntityType.RESOURCE,
                                {"identity": r.normalized_identity, "evidence_tier": r.evidence_tier.value},
                                provenance="deep_recon_schema_derived" if r.evidence_tier is EvidenceTier.SCHEMA_DERIVED else "deep_recon_inferred"))
        # Actions
        for a in self.actions.values():
            g.add_entity(Entity(a.action_id, EntityType.ACTION,
                                {"endpoint": a.endpoint_identity, "method": a.method_or_operation,
                                 "type": a.action_type.value, "evidence_tier": a.evidence_tier.value},
                                provenance="deep_recon_schema_derived" if a.evidence_tier is EvidenceTier.SCHEMA_DERIVED else "deep_recon_observed"))
        # Relationships (only OBSERVED + INFERRED with confidence; UNKNOWN → unresolved questions)
        for rel in self.relationships:
            if rel.strength is RelationshipStrength.UNKNOWN:
                g.register_unresolved_question(f"q_{rel.relation_id}",
                    f"Unknown relationship between {rel.source_id} and {rel.target_id} — needs evidence",
                    hypothesis_refs=())
            else:
                g.add_relation(Relation(rel.relation_id, RelationType.ACTION_TARGETED_RESOURCE,
                                        rel.source_id, rel.target_id,
                                        {"strength": rel.strength.value, "confidence": rel.confidence,
                                         "uncertainty": rel.uncertainty, "reason": sanitize_text(rel.inference_reason)},
                                        provenance="schema_derived" if rel.strength is RelationshipStrength.INFERRED else "validated_observation"))
        # Unresolved questions from trust boundaries
        for q in self.unresolved_questions:
            g.register_unresolved_question(q["question_id"], q["text"], hypothesis_refs=q.get("hypothesis_refs", ()))
        return g

    def summary(self) -> dict[str, Any]:
        return {"engagement_id": self.engagement_id,
                "principals": len(self.principals), "resources": len(self.resources),
                "actions": len(self.actions), "parameters": len(self.parameters),
                "relationships": len(self.relationships), "trust_boundaries": len(self.trust_boundaries),
                "hypotheses_generated": len(self.hypotheses_generated),
                "unresolved_questions": len(self.unresolved_questions),
                "is_producer_not_planner": True, "schema_derived_not_proof": True,
                "bounded": True}


__all__ = [
    "EvidenceTier", "PrincipalCategory", "ParameterLocation", "ActionType",
    "ReconPrincipal", "ReconResource", "ReconAction", "ReconParameter",
    "RelationshipStrength", "InferredRelationship", "TrustBoundary", "DeepReconEngine",
]
