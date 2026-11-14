"""Typed contracts for the advisory campaign-learning layer.

The learning layer can rank hypotheses but has no authority to execute, validate,
seal, replay, or promote anything.  These contracts deliberately contain only
bounded structural metadata and campaign provenance.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Iterable
from uuid import uuid4

SUPPORTED_FAMILIES = frozenset({
    "IDOR", "BOLA", "SSRF", "OPEN_REDIRECT", "INFO_DISCLOSURE", "XSS", "SQLI",
})
_SAFE_TEXT = re.compile(r"[^\w./*{}:$?=-]+", re.UNICODE)


def _bounded(value: Any, limit: int = 240) -> str:
    return str(value or "").strip()[:limit]


def normalize_family(value: Any) -> str | None:
    text = _bounded(value, 64).upper().replace("-", "_").replace(" ", "_")
    aliases = {"OPENREDIRECT": "OPEN_REDIRECT", "INFO": "INFO_DISCLOSURE", "SQL_INJECTION": "SQLI"}
    text = aliases.get(text, text)
    return text if text in SUPPORTED_FAMILIES else None


def normalize_route_pattern(value: Any) -> str:
    text = _bounded(value, 240)
    if not text:
        return "/"
    if not text.startswith("/"):
        text = "/" + text
    text = _SAFE_TEXT.sub("", text)
    return text[:240] or "/"


class LessonType(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    PRIORITY = "priority"
    COVERAGE_GAP = "coverage_gap"


@dataclass(frozen=True)
class StructuredLesson:
    lesson_type: LessonType | str
    route_pattern: str = "/"
    parameter_name: str | None = None
    family: str | None = None
    target_type: str = "generic_web"
    reason: str = ""
    boost_factor: float | None = None
    evidence_count: int = 1
    confidence: float = 0.5
    source_campaign_ids: tuple[str, ...] = ()
    source_finding_ids: tuple[str, ...] = ()
    client_id: str | None = None
    lesson_id: str = field(default_factory=lambda: f"lesson_{uuid4().hex[:16]}")
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        lesson_type = LessonType(str(self.lesson_type))
        object.__setattr__(self, "lesson_type", lesson_type)
        object.__setattr__(self, "route_pattern", normalize_route_pattern(self.route_pattern))
        object.__setattr__(self, "parameter_name", _bounded(self.parameter_name, 100) or None)
        object.__setattr__(self, "family", normalize_family(self.family))
        object.__setattr__(self, "target_type", _bounded(self.target_type, 80) or "generic_web")
        object.__setattr__(self, "reason", _bounded(self.reason, 500))
        object.__setattr__(self, "evidence_count", max(1, min(100000, int(self.evidence_count))))
        object.__setattr__(self, "confidence", min(1.0, max(0.0, float(self.confidence))))
        if self.boost_factor is not None:
            object.__setattr__(self, "boost_factor", min(0.5, max(-0.5, float(self.boost_factor))))
        campaigns = tuple(_bounded(item, 160) for item in self.source_campaign_ids if _bounded(item, 160))
        findings = tuple(_bounded(item, 160) for item in self.source_finding_ids if _bounded(item, 160))
        object.__setattr__(self, "source_campaign_ids", campaigns[:50])
        object.__setattr__(self, "source_finding_ids", findings[:100])
        object.__setattr__(self, "client_id", _bounded(self.client_id, 128) or None)
        object.__setattr__(self, "lesson_id", _bounded(self.lesson_id, 160))
        object.__setattr__(self, "created_at", _bounded(self.created_at, 64))

    def as_dict(self) -> dict[str, Any]:
        return {
            "lesson_id": self.lesson_id,
            "lesson_type": str(self.lesson_type),
            "route_pattern": self.route_pattern,
            "parameter_name": self.parameter_name,
            "family": self.family,
            "target_type": self.target_type,
            "reason": self.reason,
            "boost_factor": self.boost_factor,
            "evidence_count": self.evidence_count,
            "confidence": self.confidence,
            "source_campaign_ids": list(self.source_campaign_ids),
            "source_finding_ids": list(self.source_finding_ids),
            "client_id": self.client_id,
            "created_at": self.created_at,
        }

    def fingerprint(self) -> str:
        payload = self.as_dict().copy()
        payload.pop("lesson_id", None)
        payload.pop("created_at", None)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class PriorityAdjustmentMap:
    target_type: str = "generic_web"
    route_modifiers: dict[str, float] = field(default_factory=dict)
    family_modifiers: dict[str, float] = field(default_factory=dict)
    minimum_family_quota: dict[str, int] = field(default_factory=dict)
    applied_lesson_ids: tuple[str, ...] = ()
    route_hits: int = 0
    family_hits: int = 0
    knowledge_hits: int = 0
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def adjustment_for(self, route_pattern: str, family: str) -> float:
        route = normalize_route_pattern(route_pattern)
        fam = normalize_family(family) or _bounded(family, 64).upper()
        route_modifier = float(self.route_modifiers.get(route, 0.0))
        for pattern, modifier in self.route_modifiers.items():
            if pattern.endswith("*") and route.startswith(pattern[:-1]):
                route_modifier = max(route_modifier, float(modifier))
        return route_modifier + float(self.family_modifiers.get(fam, 0.0))

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_type": self.target_type,
            "route_modifiers": dict(self.route_modifiers),
            "family_modifiers": dict(self.family_modifiers),
            "minimum_family_quota": dict(self.minimum_family_quota),
            "applied_lesson_ids": list(self.applied_lesson_ids),
            "route_hits": self.route_hits,
            "family_hits": self.family_hits,
            "knowledge_hits": self.knowledge_hits,
            "generated_at": self.generated_at,
        }


def lessons_from_rows(rows: Iterable[dict[str, Any]]) -> list[StructuredLesson]:
    result: list[StructuredLesson] = []
    for row in rows:
        try:
            campaigns = row.get("source_campaign_ids") or row.get("source_campaign_id") or []
            if isinstance(campaigns, str):
                campaigns = [campaigns]
            findings = row.get("source_finding_ids") or []
            if isinstance(findings, str):
                findings = [findings]
            result.append(StructuredLesson(
                lesson_id=row.get("lesson_id") or row.get("id") or f"lesson_{uuid4().hex[:16]}",
                lesson_type=row.get("lesson_type") or LessonType.NEGATIVE,
                route_pattern=row.get("route_pattern") or "/",
                parameter_name=row.get("parameter_name"),
                family=row.get("family"),
                target_type=row.get("target_type") or "generic_web",
                reason=row.get("reason") or row.get("content") or "",
                boost_factor=row.get("boost_factor"),
                evidence_count=row.get("evidence_count", 1),
                confidence=row.get("confidence", 0.5),
                source_campaign_ids=tuple(campaigns),
                source_finding_ids=tuple(findings),
                client_id=row.get("client_id"),
                created_at=row.get("created_at") or datetime.now(timezone.utc).isoformat(),
            ))
        except (TypeError, ValueError):
            continue
    return result


__all__ = [
    "LessonType", "StructuredLesson", "PriorityAdjustmentMap", "SUPPORTED_FAMILIES",
    "normalize_family", "normalize_route_pattern", "lessons_from_rows",
]
