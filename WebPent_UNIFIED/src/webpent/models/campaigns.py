"""Typed contracts for bounded campaign planning and hypothesis DAGs."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import redact_sensitive


class CampaignExecutionContract(BaseModel):
    """A declarative, non-executing contract for one coverage campaign."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    preconditions: list[str] = Field(default_factory=list, max_length=12)
    # Evidence-backed materialization populated only when the planner matched
    # a concrete surface/workflow observation.  It is intentionally separate
    # from declared preconditions so the executor can remain fail-closed.
    observed_preconditions: list[str] = Field(default_factory=list, max_length=12)
    identities: list[str] = Field(default_factory=list, max_length=8)
    actions: list[str] = Field(default_factory=list, max_length=12)
    payload_strategy: list[str] = Field(default_factory=list, max_length=12)
    oracle: list[str] = Field(default_factory=list, max_length=12)
    negative_control: list[str] = Field(default_factory=list, max_length=8)
    cleanup: list[str] = Field(default_factory=list, max_length=8)
    budget: int = Field(default=0, ge=0, le=20)
    method: Literal["GET", "HEAD", "OPTIONS", "POST"] = "GET"
    action_family: str = Field(default="http_read", max_length=64)
    body_schema: str = Field(default="none", max_length=64)
    content_type: str = Field(default="", max_length=120)
    tenant_context: str = Field(default="unknown", max_length=120)
    confidence_state: Literal["unplanned", "ready", "blocked", "inconclusive"] = "unplanned"

    @field_validator(
        "preconditions",
        "observed_preconditions",
        "identities",
        "actions",
        "payload_strategy",
        "oracle",
        "negative_control",
        "cleanup",
        mode="before",
    )
    @classmethod
    def _redact_text(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class CampaignPlanEntry(BaseModel):
    """One planner output; it never asserts that a campaign was tested."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: int = Field(ge=1)
    key: str = Field(min_length=1, max_length=120)
    surfaces: list[str] = Field(default_factory=list, max_length=20)
    validator: str | None = Field(default=None, max_length=80)
    validator_id: str | None = Field(default=None, max_length=120)
    plugin_id: str | None = Field(default=None, max_length=160)
    evidence_schema: str = Field(default="EvidenceLedgerEntry:v1", max_length=120)
    status: str = Field(default="not_observed", max_length=40)
    matched_observation_refs: list[str] = Field(default_factory=list, max_length=20)
    gaps: list[str] = Field(default_factory=list, max_length=12)
    contract: CampaignExecutionContract


class HypothesisDAGNode(BaseModel):
    """A node in the passive campaign-to-evidence hypothesis graph."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    node_id: str = Field(min_length=3, max_length=160)
    node_type: Literal[
        "campaign",
        "surface_observation",
        "workflow_observation",
        "coverage_gap",
    ]
    ref: str = Field(min_length=1, max_length=200)
    status: str = Field(default="unobserved", max_length=40)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ref", "metadata", mode="before")
    @classmethod
    def _redact_metadata(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class HypothesisDAGEdge(BaseModel):
    """A typed dependency edge; edges do not authorize execution."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source: str = Field(min_length=3, max_length=160)
    target: str = Field(min_length=3, max_length=160)
    relation: Literal[
        "campaign_requires_observation",
        "campaign_blocked_by_gap",
        "observation_supports_campaign",
    ]


class CampaignPlannerResult(BaseModel):
    """Bounded planner output suitable for state/report persistence."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    version: int = 1
    target_url: str = Field(min_length=1, max_length=1000)
    entries: list[CampaignPlanEntry] = Field(default_factory=list, max_length=100)
    nodes: list[HypothesisDAGNode] = Field(default_factory=list, max_length=300)
    edges: list[HypothesisDAGEdge] = Field(default_factory=list, max_length=600)
    coverage_gaps: list[str] = Field(default_factory=list, max_length=200)
    summary: dict[str, int] = Field(default_factory=dict)

    @field_validator("target_url", "coverage_gaps", "summary", mode="before")
    @classmethod
    def _redact_fields(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


__all__ = [
    "CampaignExecutionContract",
    "CampaignPlanEntry",
    "CampaignPlannerResult",
    "HypothesisDAGEdge",
    "HypothesisDAGNode",
]
