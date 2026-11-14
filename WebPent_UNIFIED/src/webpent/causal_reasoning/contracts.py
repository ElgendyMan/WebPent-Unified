# src/webpent/causal_reasoning/contracts.py
"""Typed contracts for Proposal #1 — Causal Reasoning Engine.

Additive, non-breaking, read-only inference layer.  This module has NO
execution authority: it never issues a request, promotes a finding, or
mutates engagement state.  It consumes already-collected observations and
emits bounded, confidence-scored inferences that downstream agents MAY use
to reprioritise their search queue.  All models are redaction-safe and
bounded; secret-like keys are stripped at the boundary.

Three sub-systems share these contracts:
  1. ArchitectureInferrer  — infers systemic weakness from one finding
     and enumerates sibling regions sharing that weakness.
  2. ContextualMemory      — cross-engagement persistent context store
     with fingerprint similarity and knowledge transfer.
  3. RootCauseAnalyzer     — clusters findings by root cause and maps a
     single detection back to every path sharing the causal pattern.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_SECRET_MARKERS = (
    "authorization", "cookie", "password", "passwd", "secret", "token",
    "api_key", "apikey", "session", "jwt", "bearer", "credential",
)
_SAFE_TOKEN = re.compile(r"[^\w.\-/:]+", re.UNICODE)


def _bounded(value: Any, limit: int = 240) -> str:
    return str(value or "").strip()[:limit]


def _safe_scalar(value: Any) -> Any:
    if isinstance(value, str):
        return " ".join(value.split())[:320]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)[:320]


def _safe_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    """Keep metadata bounded and remove secret-like keys recursively."""
    safe: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key).strip().lower()
        if not key or any(marker in key for marker in _SECRET_MARKERS):
            continue
        if isinstance(raw_value, Mapping):
            safe[key] = _safe_mapping(raw_value)
        elif isinstance(raw_value, (list, tuple)):
            safe[key] = [_safe_scalar(item) for item in raw_value[:20]]
        else:
            safe[key] = _safe_scalar(raw_value)
    return safe


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class WeaknessCategory(StrEnum):
    """Closed vocabulary of systemic (architectural) weakness patterns.

    These are NOT vulnerability classes (those live in VulnClass).  A
    weakness category is the *architectural cause* that produces one or
    more vuln classes.  Example: AUTH_CHECK_AFTER_MUTATION produces IDOR,
    AUTH_BYPASS, and PRIVILEGE_ESCALATION findings across many routes.
    """

    MISSING_SHARED_VALIDATION = "missing_shared_validation"
    AUTH_CHECK_AFTER_MUTATION = "auth_check_after_mutation"
    BROKEN_ACCESS_CONTROL_LAYER = "broken_access_control_layer"
    INCONSISTENT_INPUT_SANITISATION = "inconsistent_input_sanitisation"
    TRUSTED_CLIENT_SIDE_CONTROL = "trusted_client_side_control"
    WEAK_OR_MISSING_AUTHN_POLICY = "weak_or_missing_authn_policy"
    DIRECT_OBJECT_REFERENCE_WITHOUT_SCOPE = "direct_object_reference_without_scope"
    MASS_ASSIGNMENT_UNBOUND_FIELDS = "mass_assignment_unbound_fields"
    ERROR_HANDLING_LEAKS_INTERNALS = "error_handling_leaks_internals"
    UNPATCHED_FRAMEWORK_PATTERN = "unpatched_framework_pattern"
    CORS_MISCONFIGURATION_WILDCARD = "cors_misconfiguration_wildcard"
    SESSION_FIXATION_OR_WEAK_BINDING = "session_fixation_or_weak_binding"
    UNKNOWN = "unknown"


class InferenceLifecycle(StrEnum):
    HYPOTHESISED = "hypothesised"
    CORROBORATED = "corroborated"
    REFUTED = "refuted"
    PRIORITISED = "prioritised"


class TransferStrength(StrEnum):
    DIRECT = "direct"        # same framework + same pattern observed before
    ANALOGOUS = "analogous"  # same family, different framework
    SPECULATIVE = "speculative"


# ---------------------------------------------------------------------------
# Core inference models
# ---------------------------------------------------------------------------

class CausalHypothesis(BaseModel):
    """An inference: finding X is caused by architectural weakness Y.

    Emitted by ArchitectureInferrer.  Never treated as a finding itself;
    downstream agents decide whether to probe the predicted sibling paths.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    hypothesis_id: str = Field(min_length=1, max_length=200)
    source_finding_id: str = Field(min_length=1, max_length=200)
    weakness_category: WeaknessCategory
    rationale: str = Field(min_length=1, max_length=600)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    predicted_sibling_count: int = Field(default=0, ge=0)
    lifecycle: InferenceLifecycle = InferenceLifecycle.HYPOTHESISED
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    created_at: datetime = _EPOCH
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("created_at")
    @classmethod
    def _utc_ts(cls, v: datetime) -> datetime:
        return _utc(v)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(_bounded(x, 240) for x in v if _bounded(x, 240)))

    @field_validator("metadata")
    @classmethod
    def _safe_meta(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _safe_mapping(v)


class AtRiskRegion(BaseModel):
    """A region (endpoint / parameter / role-path) inferred vulnerable.

    Produced by propagating a CausalHypothesis across the knowledge graph.
    `priority_score` = confidence * severity_proxy * coverage_gap_weight,
    bounded to [0, 1].  Higher = probe first.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    region_id: str = Field(min_length=1, max_length=200)
    kind: str = Field(min_length=1, max_length=80)  # endpoint|parameter|role_path|data_flow
    canonical_key: str = Field(min_length=1, max_length=320)
    supporting_hypothesis_ids: tuple[str, ...] = Field(default=(), max_length=16)
    priority_score: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: str = Field(default="", max_length=600)
    already_covered: bool = False
    lifecycle: InferenceLifecycle = InferenceLifecycle.HYPOTHESISED
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("supporting_hypothesis_ids")
    @classmethod
    def _unique_ids(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(_bounded(x, 200) for x in v if _bounded(x, 200)))

    @field_validator("metadata")
    @classmethod
    def _safe_meta(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _safe_mapping(v)


class InferenceResult(BaseModel):
    """Aggregate output of ingesting one finding through the engine."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    source_finding_id: str = Field(min_length=1, max_length=200)
    hypotheses: tuple[CausalHypothesis, ...] = Field(default=(), max_length=8)
    at_risk_regions: tuple[AtRiskRegion, ...] = Field(default=(), max_length=200)
    root_cause_cluster_id: str | None = Field(default=None, max_length=200)
    generated_at: datetime = _EPOCH

    @field_validator("generated_at")
    @classmethod
    def _utc_ts(cls, v: datetime) -> datetime:
        return _utc(v)

    def top_regions(self, limit: int = 10) -> tuple[AtRiskRegion, ...]:
        ordered = sorted(
            self.at_risk_regions, key=lambda r: r.priority_score, reverse=True
        )
        return tuple(ordered[: max(0, int(limit))])


# ---------------------------------------------------------------------------
# Contextual memory models
# ---------------------------------------------------------------------------

class ContextFingerprint(BaseModel):
    """Redacted, bounded fingerprint of a target's technical context.

    Stored per engagement in ContextualMemory.  Used to find analogous
    past engagements and transfer lessons.  Contains NO secrets, NO URLs
    with userinfo, NO credentials — only framework/stack/policy signals.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    fingerprint_id: str = Field(min_length=1, max_length=200)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_type: str = Field(default="generic_web", min_length=1, max_length=80)
    frameworks: tuple[str, ...] = Field(default=(), max_length=24)   # e.g. ("django","drf")
    languages: tuple[str, ...] = Field(default=(), max_length=12)
    auth_scheme: str = Field(default="unknown", max_length=80)        # jwt|session|oauth|api_key|none
    auth_policy_pattern: str = Field(default="unknown", max_length=120)  # middleware|decorator|inline
    validation_pattern: str = Field(default="unknown", max_length=120)   # shared_layer|per_route|none
    error_behavior_signature: str = Field(default="unknown", max_length=160)  # stacktrace|generic|blank
    orm_in_use: str = Field(default="unknown", max_length=80)
    api_style: str = Field(default="unknown", max_length=80)          # rest|graphql|rpc|mixed
    observed_route_count: int = Field(default=0, ge=0, le=1_000_000)
    created_at: datetime = _EPOCH
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("frameworks", "languages")
    @classmethod
    def _norm_tuple(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({_SAFE_TOKEN.sub("", str(x).lower().strip())[:60] for x in v if str(x).strip()}))

    @field_validator("created_at")
    @classmethod
    def _utc_ts(cls, v: datetime) -> datetime:
        return _utc(v)

    @field_validator("metadata")
    @classmethod
    def _safe_meta(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _safe_mapping(v)

    def digest(self) -> str:
        payload = self.model_dump(mode="json", exclude={"fingerprint_id", "engagement_id", "created_at", "metadata"})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:32]

    def similarity(self, other: "ContextFingerprint") -> float:
        """Deterministic [0,1] similarity — no embeddings required.

        Weighted token overlap on the categorical fields.  Only fields that
        are non-unknown in at least one of the two fingerprints contribute to
        the normalising weight, so a fingerprint with many unknown signals
        still scores 1.0 against its exact self.  Deterministic so that the
        same pair always scores identically (replay-safe).
        """
        if not isinstance(other, ContextFingerprint):
            return 0.0
        score = 0.0
        weight = 0.0
        # frameworks (high weight) — active if either side names a framework
        fw_self, fw_other = set(self.frameworks), set(other.frameworks)
        if fw_self or fw_other:
            score += 0.28 * (len(fw_self & fw_other) / max(1, len(fw_self | fw_other)))
            weight += 0.28
        # auth scheme + policy pattern (high weight)
        if self.auth_scheme != "unknown" or other.auth_scheme != "unknown":
            if self.auth_scheme == other.auth_scheme:
                score += 0.18
            weight += 0.18
        if self.auth_policy_pattern != "unknown" or other.auth_policy_pattern != "unknown":
            if self.auth_policy_pattern == other.auth_policy_pattern:
                score += 0.14
            weight += 0.14
        # validation pattern + error behavior (medium)
        if self.validation_pattern != "unknown" or other.validation_pattern != "unknown":
            if self.validation_pattern == other.validation_pattern:
                score += 0.10
            weight += 0.10
        if self.error_behavior_signature != "unknown" or other.error_behavior_signature != "unknown":
            if self.error_behavior_signature == other.error_behavior_signature:
                score += 0.08
            weight += 0.08
        # orm + api style + languages (lower)
        if self.orm_in_use != "unknown" or other.orm_in_use != "unknown":
            if self.orm_in_use == other.orm_in_use:
                score += 0.06
            weight += 0.06
        if self.api_style != "unknown" or other.api_style != "unknown":
            if self.api_style == other.api_style:
                score += 0.06
            weight += 0.06
        lang_self, lang_other = set(self.languages), set(other.languages)
        if lang_self or lang_other:
            score += 0.10 * (len(lang_self & lang_other) / max(1, len(lang_self | lang_other)))
            weight += 0.10
        if weight <= 0:
            return 0.0
        return round(min(1.0, score / weight), 4)


class TransferredLesson(BaseModel):
    """A lesson transferred from a past analogous engagement."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    lesson_id: str = Field(min_length=1, max_length=200)
    source_engagement_id: str = Field(min_length=1, max_length=200)
    source_fingerprint_digest: str = Field(min_length=1, max_length=64)
    transfer_strength: TransferStrength
    similarity_score: float = Field(default=0.0, ge=0.0, le=1.0)
    weakness_category: WeaknessCategory = WeaknessCategory.UNKNOWN
    typical_route_globs: tuple[str, ...] = Field(default=(), max_length=24)
    typical_parameters: tuple[str, ...] = Field(default=(), max_length=24)
    recommendation: str = Field(min_length=1, max_length=600)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    created_at: datetime = _EPOCH

    @field_validator("typical_route_globs", "typical_parameters")
    @classmethod
    def _norm_strs(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(_bounded(x, 240) for x in v if _bounded(x, 240)))

    @field_validator("created_at")
    @classmethod
    def _utc_ts(cls, v: datetime) -> datetime:
        return _utc(v)


class EngagementContextRecord(BaseModel):
    """Full persisted record for one engagement (fingerprint + outcomes)."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    record_id: str = Field(min_length=1, max_length=200)
    fingerprint: ContextFingerprint
    finding_families_observed: tuple[str, ...] = Field(default=(), max_length=64)
    weakness_categories_confirmed: tuple[WeaknessCategory, ...] = Field(default=(), max_length=32)
    routes_affected_by_weakness: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    total_findings: int = Field(default=0, ge=0)
    ended_at: datetime = _EPOCH

    @field_validator("finding_families_observed")
    @classmethod
    def _norm_families(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({_bounded(x, 64).upper() for x in v if _bounded(x, 64)}))

    @field_validator("routes_affected_by_weakness")
    @classmethod
    def _safe_routes(cls, v: dict[str, tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
        safe: dict[str, tuple[str, ...]] = {}
        for k, vals in v.items():
            key = _bounded(k, 80)
            if not key:
                continue
            safe[key] = tuple(dict.fromkeys(_bounded(x, 240) for x in vals if _bounded(x, 240)))[:64]
        return safe

    @field_validator("ended_at")
    @classmethod
    def _utc_ts(cls, v: datetime) -> datetime:
        return _utc(v)


# ---------------------------------------------------------------------------
# Root-cause cluster models
# ---------------------------------------------------------------------------

class RootCauseCluster(BaseModel):
    """A group of findings inferred to share one architectural root cause."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    cluster_id: str = Field(min_length=1, max_length=200)
    weakness_category: WeaknessCategory
    member_finding_ids: tuple[str, ...] = Field(default=(), max_length=512)
    sibling_paths_predicted: tuple[str, ...] = Field(default=(), max_length=512)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    remediation_hint: str = Field(default="", max_length=600)
    created_at: datetime = _EPOCH

    @field_validator("member_finding_ids", "sibling_paths_predicted")
    @classmethod
    def _unique(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(_bounded(x, 240) for x in v if _bounded(x, 240)))

    @field_validator("created_at")
    @classmethod
    def _utc_ts(cls, v: datetime) -> datetime:
        return _utc(v)

    @property
    def size(self) -> int:
        return len(self.member_finding_ids)


def stable_id(prefix: str, *parts: str) -> str:
    """Deterministic, replay-safe identifier from bounded parts."""
    joined = "|".join(_bounded(p, 240) for p in parts)
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:20]
    return f"{_bounded(prefix, 40)}:{digest}"


def route_to_glob(route: str) -> str:
    """Normalise a concrete route into a transferable glob pattern.

    /api/users/123/profile  ->  /api/users/*/profile
    /api/v2/orders/abc-123  ->  /api/v2/orders/*
    Deterministic; used both for storage and for matching at transfer time.
    """
    text = _bounded(route, 240)
    if not text:
        return "/*"
    # strip query/fragment
    text = text.split("?", 1)[0].split("#", 1)[0]
    segments = [seg for seg in text.split("/") if seg]
    globbed: list[str] = []
    uuid_like = re.compile(r"^[0-9a-fA-F-]{8,}$")
    for seg in segments:
        if seg.isdigit() or uuid_like.match(seg) or (len(seg) > 12 and not seg.isalpha()):
            globbed.append("*")
        else:
            globbed.append(seg)
    result = "/" + "/".join(globbed)
    return result[:240] or "/*"


def glob_matches(glob: str, route: str) -> bool:
    """Deterministic glob match: '*' matches exactly one path segment."""
    g = [s for s in _bounded(glob, 240).split("/") if s]
    r = [s for s in _bounded(route, 240).split("?", 1)[0].split("#", 1)[0].split("/") if s]
    if len(g) != len(r):
        return False
    for gseg, rseg in zip(g, r):
        if gseg == "*":
            continue
        if gseg.lower() != rseg.lower():
            return False
    return True


__all__ = [
    "WeaknessCategory", "InferenceLifecycle", "TransferStrength",
    "CausalHypothesis", "AtRiskRegion", "InferenceResult",
    "ContextFingerprint", "TransferredLesson", "EngagementContextRecord",
    "RootCauseCluster", "stable_id", "route_to_glob", "glob_matches",
]
