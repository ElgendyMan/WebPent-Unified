"""Typed, redacted outputs for client-side JavaScript intelligence."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class JavaScriptAsset(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True, str_strip_whitespace=True)

    asset_url: str = Field(..., min_length=1, max_length=1200)
    content_type: str = Field(default="unknown", min_length=1, max_length=120)
    status_code: int = Field(default=0, ge=0, le=999)
    size_bytes: int = Field(default=0, ge=0, le=20_000_000)
    content_sha256: str = Field(..., min_length=16, max_length=128)
    source_map_url: str | None = Field(default=None, max_length=1200)
    source_map_sources: list[str] = Field(default_factory=list, max_length=200)
    in_scope: bool = True
    redacted: bool = True
    duplicate_of: str | None = Field(default=None, max_length=1200)


class JavaScriptRoute(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True, str_strip_whitespace=True)

    route: str = Field(..., min_length=1, max_length=1200)
    source_asset: str = Field(..., min_length=1, max_length=1200)
    method_hint: str = Field(default="UNKNOWN", min_length=1, max_length=16)
    discovery_kind: Literal[
        "fetch", "axios", "xhr", "http_client", "route_literal", "graphql", "source_map"
    ]
    line: int | None = Field(default=None, ge=1, le=1_000_000)
    in_scope: bool = True
    evidence_ref: str = Field(..., min_length=8, max_length=160)


class JavaScriptSink(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True, str_strip_whitespace=True)

    category: Literal[
        "dom_xss", "code_execution", "navigation", "message_handling", "html_injection"
    ]
    sink: str = Field(..., min_length=1, max_length=120)
    source_asset: str = Field(..., min_length=1, max_length=1200)
    line: int | None = Field(default=None, ge=1, le=1_000_000)
    snippet_sha256: str = Field(..., min_length=16, max_length=128)
    evidence_ref: str = Field(..., min_length=8, max_length=160)


class JavaScriptSecretCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True, str_strip_whitespace=True)

    kind: str = Field(..., min_length=1, max_length=100)
    source_asset: str = Field(..., min_length=1, max_length=1200)
    line: int | None = Field(default=None, ge=1, le=1_000_000)
    value_sha256: str = Field(..., min_length=16, max_length=128)
    redacted_value: Literal["[REDACTED]"] = "[REDACTED]"
    confidence: Literal["low", "medium", "high"] = "low"
    validation_status: Literal["advisory", "needs_safe_validation", "validated"] = "advisory"
    evidence_ref: str = Field(..., min_length=8, max_length=160)


class JavaScriptAuthHint(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True, str_strip_whitespace=True)

    hint: str = Field(..., min_length=1, max_length=100)
    identifier: str = Field(..., min_length=1, max_length=120)
    source_asset: str = Field(..., min_length=1, max_length=1200)
    line: int | None = Field(default=None, ge=1, le=1_000_000)
    evidence_ref: str = Field(..., min_length=8, max_length=160)


class JavaScriptTargetedTask(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True, str_strip_whitespace=True)

    task_id: str = Field(..., min_length=16, max_length=128)
    task_type: Literal["js_route_mapping", "js_auth_review", "js_source_map_review"]
    target_ref: str = Field(..., min_length=1, max_length=1200)
    source_asset: str = Field(..., min_length=1, max_length=1200)
    reason: str = Field(..., min_length=1, max_length=300)
    in_scope: bool = True
    destructive: bool = False


class JavaScriptIntelligence(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True, str_strip_whitespace=True)

    version: str = "1"
    assets: list[JavaScriptAsset] = Field(default_factory=list, max_length=200)
    routes: list[JavaScriptRoute] = Field(default_factory=list, max_length=1000)
    sinks: list[JavaScriptSink] = Field(default_factory=list, max_length=1000)
    secret_candidates: list[JavaScriptSecretCandidate] = Field(default_factory=list, max_length=500)
    auth_hints: list[JavaScriptAuthHint] = Field(default_factory=list, max_length=500)
    targeted_tasks: list[JavaScriptTargetedTask] = Field(default_factory=list, max_length=1500)
    coverage_gaps: list[str] = Field(default_factory=list, max_length=200)
    redaction: str = "source_content_and_secret_values_omitted"


__all__ = [
    "JavaScriptAsset",
    "JavaScriptAuthHint",
    "JavaScriptIntelligence",
    "JavaScriptRoute",
    "JavaScriptSecretCandidate",
    "JavaScriptSink",
    "JavaScriptTargetedTask",
]
