"""Typed, report-safe observations for broad web-security surface coverage.

These records are not Findings. They describe what the passive/read-only
collection layer observed and what requires a bounded validator or human
review before any vulnerability can be confirmed.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.application_intent import ApplicationIntentModel
from webpent.models.surface_graph import SurfaceEvidenceGraph


class SurfaceSecurityCategory(str, Enum):
    SQL_INJECTION = "sql_injection"
    AUTHENTICATION = "authentication"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    BUSINESS_LOGIC = "business_logic"
    INFORMATION_DISCLOSURE = "information_disclosure"
    ACCESS_CONTROL = "access_control"
    FILE_UPLOAD = "file_upload"
    RACE_CONDITION = "race_condition"
    SSRF = "ssrf"
    XXE = "xxe"
    NOSQL_INJECTION = "nosql_injection"
    API = "api"
    CACHE_DECEPTION = "cache_deception"
    XSS = "xss"
    CSRF = "csrf"
    CORS = "cors_misconfiguration"
    CLICKJACKING = "clickjacking"
    DOM = "dom_based_vulnerability"
    WEBSOCKETS = "websockets"
    DESERIALIZATION = "insecure_deserialization"
    SSTI = "ssti"
    CACHE_POISONING = "cache_poisoning"
    HOST_HEADER = "host_header"
    HTTP_REQUEST_SMUGGLING = "http_request_smuggling"
    OAUTH = "oauth"
    JWT = "jwt"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    WEB_LLM = "web_llm"
    GRAPHQL = "graphql"
    SECRETS_EXPOSURE = "secrets_exposure"


class SurfaceObservationStatus(str, Enum):
    OBSERVED = "observed"
    CANDIDATE = "candidate"
    NEEDS_ACTIVE_VALIDATION = "needs_active_validation"
    CLEAN = "clean"
    NOT_SCANNED = "not_scanned"


class SurfaceSecurityObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    category: SurfaceSecurityCategory
    status: SurfaceObservationStatus
    title: str = Field(min_length=3, max_length=160)
    reason: str = Field(min_length=1, max_length=2000)
    endpoint_refs: list[str] = Field(default_factory=list, max_length=50)
    signal_refs: list[str] = Field(default_factory=list, max_length=50)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)
    active_validation_required: bool = False
    human_review_required: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class SurfaceSecuritySummary(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    schema_version: str = "surface-security-v1"
    observations: list[SurfaceSecurityObservation] = Field(default_factory=list, max_length=500)
    categories_scanned: list[SurfaceSecurityCategory] = Field(default_factory=list, max_length=100)
    coverage_gaps: list[str] = Field(default_factory=list, max_length=100)
    application_intent: list[str] = Field(default_factory=list, max_length=20)
    identity_context_refs: list[str] = Field(default_factory=list, max_length=50)
    workflow_refs: list[str] = Field(default_factory=list, max_length=50)
    application_intent_model: ApplicationIntentModel | None = None
    surface_graph: SurfaceEvidenceGraph | None = None
    # Project Zero (2026-10-22): parameter-name-level influence graph built
    # from the same input as surface_graph; attached only when the operator
    # enables it (default-off). Stored as its JSON-ready dict (the model is
    # a plain dataclass in webpent.shared.surface_influence_graph).
    surface_influence_graph: dict[str, Any] | None = None
    bounded: bool = True
    passive_only: bool = True

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
