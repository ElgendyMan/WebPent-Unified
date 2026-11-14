"""Reusable vulnerability-research patterns for AVRP.

Patterns describe reasoning templates only. They do not identify a target,
confirm a vulnerability, alter ground truth, or authorize an action.
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import canonical_json, redact_sensitive


def _clean(value: Any, limit: int = 500) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return " ".join(clean.split())[:limit]


def _clean_list(value: Any, limit: int = 30) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    result: list[str] = []
    for item in value[:limit]:
        item = _clean(item, 240)
        if item and item not in result:
            result.append(item)
    return result


class VulnerabilityPattern(BaseModel):
    """Generic, target-neutral template for future research hypotheses."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    pattern_id: str = Field(min_length=3, max_length=120)
    vulnerability_class: Literal[
        "authorization_failure",
        "ownership_violation",
        "privilege_boundary",
        "workflow_abuse",
        "data_exposure",
    ]
    name: str = Field(min_length=3, max_length=160)
    prerequisites: list[str] = Field(min_length=1, max_length=20)
    security_assumption: str = Field(min_length=3, max_length=500)
    typical_evidence: list[str] = Field(min_length=1, max_length=30)
    validation_strategy: str = Field(min_length=3, max_length=500)
    common_false_positives: list[str] = Field(min_length=1, max_length=30)
    advisory_only: bool = True

    @field_validator(
        "pattern_id",
        "vulnerability_class",
        "name",
        "prerequisites",
        "security_assumption",
        "typical_evidence",
        "validation_strategy",
        "common_false_positives",
        mode="before",
    )
    @classmethod
    def _redact(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple)):
            return _clean_list(value)
        return _clean(value)

    def stable_hash(self) -> str:
        payload = self.model_dump(mode="json")
        payload.pop("advisory_only", None)
        return hashlib.sha256(canonical_json(payload).encode()).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(self.model_dump(mode="json"))
        clean["stable_hash"] = self.stable_hash()
        return clean


class VulnerabilityPatternLibrary:
    """Immutable-in-practice catalog of target-neutral research templates."""

    def __init__(self, patterns: tuple[VulnerabilityPattern, ...] | None = None) -> None:
        self._patterns = patterns or self.default_patterns()

    @staticmethod
    def default_patterns() -> tuple[VulnerabilityPattern, ...]:
        return (
            VulnerabilityPattern(
                pattern_id="pattern:authorization-boundary",
                vulnerability_class="authorization_failure",
                name="Authorization boundary mismatch",
                prerequisites=["distinct requester contexts", "object or action reference"],
                security_assumption=(
                    "A requester must not receive an object or action outside "
                    "its authorization boundary."
                ),
                typical_evidence=[
                    "role differential",
                    "object identifier",
                    "candidate/control contrast",
                ],
                validation_strategy=(
                    "Use a causal candidate/control pair and an approved central oracle; "
                    "route reachability alone is insufficient."
                ),
                common_false_positives=["public object", "same-owner access", "HTTP status alone"],
            ),
            VulnerabilityPattern(
                pattern_id="pattern:ownership-boundary",
                vulnerability_class="ownership_violation",
                name="Ownership relation violation",
                prerequisites=["owner/requester model", "stable object reference"],
                security_assumption=(
                    "Only the owner or explicitly authorized principal may access the object."
                ),
                typical_evidence=[
                    "owner reference",
                    "requester contrast",
                    "object-level response difference",
                ],
                validation_strategy=(
                    "Prove owner versus non-owner behavior with independent negative "
                    "control and replayable evidence."
                ),
                common_false_positives=[
                    "shared resource",
                    "administrative access",
                    "fixture mismatch",
                ],
            ),
            VulnerabilityPattern(
                pattern_id="pattern:privilege-boundary",
                vulnerability_class="privilege_boundary",
                name="Privilege boundary inconsistency",
                prerequisites=["ordered privilege contexts", "protected operation reference"],
                security_assumption=(
                    "A lower-privilege context must not obtain a protected operation "
                    "reserved for a higher context."
                ),
                typical_evidence=[
                    "privilege differential",
                    "protected operation",
                    "negative control",
                ],
                validation_strategy=(
                    "Require policy-approved identities and a causal oracle; keep blocked "
                    "when identity or state preconditions are unavailable."
                ),
                common_false_positives=[
                    "intentionally public operation",
                    "feature flag",
                    "test fixture artifact",
                ],
            ),
            VulnerabilityPattern(
                pattern_id="pattern:workflow-abuse",
                vulnerability_class="workflow_abuse",
                name="Workflow transition abuse",
                prerequisites=["documented workflow states", "safe transition observation"],
                security_assumption=(
                    "A workflow transition must respect its required predecessor state "
                    "and actor permissions."
                ),
                typical_evidence=["state transition", "actor context", "business rule contrast"],
                validation_strategy=(
                    "Use read-only or pre-approved controlled transitions and verify causality; "
                    "do not infer abuse from a reachable route."
                ),
                common_false_positives=[
                    "valid alternate flow",
                    "idempotent retry",
                    "unrecorded state",
                ],
            ),
            VulnerabilityPattern(
                pattern_id="pattern:data-exposure",
                vulnerability_class="data_exposure",
                name="Unintended sensitive-data exposure",
                prerequisites=["sensitive-data classification", "response or storage reference"],
                security_assumption=(
                    "Sensitive data must only be disclosed to an authorized context "
                    "and approved purpose."
                ),
                typical_evidence=[
                    "redacted field classification",
                    "authorization context",
                    "response-shape contrast",
                ],
                validation_strategy=(
                    "Confirm only with redacted evidence, a causal oracle, and an independent "
                    "control that rules out intentionally public data."
                ),
                common_false_positives=[
                    "documentation example",
                    "public metadata",
                    "redaction artifact",
                ],
            ),
        )

    def all(self) -> tuple[VulnerabilityPattern, ...]:
        return tuple(sorted(self._patterns, key=lambda pattern: pattern.pattern_id))

    def get(self, pattern_id: str) -> VulnerabilityPattern | None:
        wanted = _clean(pattern_id, 120)
        return next((item for item in self._patterns if item.pattern_id == wanted), None)

    def match(
        self, *, evidence_kinds: list[str] | tuple[str, ...]
    ) -> tuple[VulnerabilityPattern, ...]:
        kinds = {item.lower().replace("-", "_") for item in _clean_list(evidence_kinds)}
        matched: list[VulnerabilityPattern] = []
        for pattern in self._patterns:
            required = {item.lower().replace("-", "_") for item in pattern.typical_evidence}
            if required & kinds:
                matched.append(pattern)
        return tuple(sorted(matched, key=lambda pattern: pattern.pattern_id))


__all__ = ["VulnerabilityPattern", "VulnerabilityPatternLibrary"]
