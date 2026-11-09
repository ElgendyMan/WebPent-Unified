"""Coverage intelligence for AVRP, based on recorded evidence only."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import canonical_json, redact_sensitive


def _clean(value: Any, limit: int = 500) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return " ".join(clean.split())[:limit]


def _items(value: Any, limit: int = 40) -> tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        return ()
    result: list[str] = []
    for item in value:
        clean = _clean(item, 240)
        if clean and clean not in result:
            result.append(clean)
    return tuple(result[:limit])


class CoverageRecord(BaseModel):
    """Report-safe coverage fact; no fact implies vulnerability."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    record_id: str = Field(min_length=3, max_length=120)
    asset_ref: str = Field(min_length=1, max_length=240)
    vulnerability_classes_seen: tuple[str, ...] = Field(default=(), max_length=30)
    workflows_seen: tuple[str, ...] = Field(default=(), max_length=50)
    roles_seen: tuple[str, ...] = Field(default=(), max_length=50)
    states_seen: tuple[str, ...] = Field(default=(), max_length=50)
    unknown_areas: tuple[str, ...] = Field(default=(), max_length=50)
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=40)
    completeness: float = Field(ge=0.0, le=1.0)
    status: Literal["observed", "partial", "unknown"] = "partial"
    advisory_only: bool = True

    @field_validator(
        "record_id",
        "asset_ref",
        "vulnerability_classes_seen",
        "workflows_seen",
        "roles_seen",
        "states_seen",
        "unknown_areas",
        "evidence_refs",
        "status",
        mode="before",
    )
    @classmethod
    def _redact(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple, set)):
            return _items(value)
        return _clean(value)

    def stable_hash(self) -> str:
        payload = self.model_dump(mode="json")
        payload.pop("advisory_only", None)
        return hashlib.sha256(canonical_json(payload).encode()).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(self.model_dump(mode="json"))
        clean["stable_hash"] = self.stable_hash()
        return clean


class CoverageIntelligence:
    """Summarize coverage without converting reachability into security claims."""

    def summarize(
        self,
        observations: Iterable[Mapping[str, Any]],
        *,
        target_ref: str,
        required_classes: Iterable[str] = (),
    ) -> CoverageRecord:
        target = _clean(target_ref, 240)
        if not target:
            raise ValueError("target_ref is required")
        records = tuple(observations)
        if any(not isinstance(item, Mapping) for item in records):
            raise TypeError("observations must be mappings")
        classes: set[str] = set()
        workflows: set[str] = set()
        roles: set[str] = set()
        states: set[str] = set()
        unknown: set[str] = set()
        evidence: set[str] = set()
        assets: set[str] = set()
        for item in records:
            metadata = item.get("metadata", item)
            if not isinstance(metadata, Mapping):
                unknown.add("malformed metadata")
                continue
            classes.update(_items(metadata.get("vulnerability_classes")))
            workflows.update(_items(metadata.get("workflows")))
            roles.update(_items(metadata.get("roles")))
            states.update(_items(metadata.get("states")))
            evidence.update(_items(item.get("evidence_refs", metadata.get("evidence_refs"))))
            asset = _clean(item.get("asset", metadata.get("asset", "")), 240)
            if asset:
                assets.add(asset)
            unknown.update(_items(metadata.get("unknown_areas")))
        required = set(_items(tuple(required_classes)))
        if required:
            unknown.update(sorted(required - classes))
        dimensions = (classes, workflows, roles, states, evidence)
        completeness = round(sum(bool(group) for group in dimensions) / len(dimensions), 3)
        if not records:
            status: Literal["observed", "partial", "unknown"] = "unknown"
        elif completeness >= 0.8 and not unknown:
            status = "observed"
        else:
            status = "partial"
        asset_ref = sorted(assets)[0] if assets else target
        record_id = (
            "coverage:"
            + hashlib.sha256(
                canonical_json({"target_ref": target, "asset_ref": asset_ref}).encode()
            ).hexdigest()[:24]
        )
        return CoverageRecord(
            record_id=record_id,
            asset_ref=asset_ref,
            vulnerability_classes_seen=tuple(sorted(classes)),
            workflows_seen=tuple(sorted(workflows)),
            roles_seen=tuple(sorted(roles)),
            states_seen=tuple(sorted(states)),
            unknown_areas=tuple(sorted(unknown)),
            evidence_refs=tuple(sorted(evidence)) or ("evidence:unavailable",),
            completeness=completeness,
            status=status,
        )


__all__ = ["CoverageIntelligence", "CoverageRecord"]
