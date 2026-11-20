"""Behavioral surface discovery and security-invariant mining."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field

from webpent.asros.world_model import SecurityWorldModel
from webpent.models.evidence import redact_sensitive


class BehavioralSurface(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    surface_id: str = Field(min_length=16, max_length=128)
    asset: str = Field(min_length=1, max_length=240)
    dimensions: tuple[str, ...] = Field(min_length=1, max_length=12)
    observed_variants: tuple[str, ...] = Field(min_length=1, max_length=32)
    stability: float = Field(ge=0.0, le=1.0)
    source_refs: tuple[str, ...] = Field(min_length=1, max_length=32)


class BehavioralSurfaceDiscovery:
    """Build a redacted, deterministic projection of observable behavior."""

    def discover(
        self, observations: Iterable[Mapping[str, object]]
    ) -> tuple[BehavioralSurface, ...]:
        grouped: dict[str, dict[str, set[str]]] = {}
        refs: dict[str, set[str]] = {}
        for raw in observations:
            if not isinstance(raw, Mapping):
                raise TypeError("mapping_required")
            asset = str(raw.get("asset", raw.get("path", ""))).strip()
            if not asset:
                raise ValueError("behavior_asset_required")
            dimensions = grouped.setdefault(asset, {})
            for key in ("method", "role", "subject", "status", "response_class"):
                if key in raw and raw[key] is not None:
                    dimensions.setdefault(key, set()).add(redact_sensitive(str(raw[key]))[0][:120])
            refs.setdefault(asset, set()).update(
                re.sub(
                    r"(?i)(token|secret|password|cookie|authorization)\s*[:=]\s*[^\s,;]+",
                    "[REDACTED]",
                    redact_sensitive(str(ref))[0],
                )[:200]
                for ref in raw.get("source_refs", (asset,))
            )
        surfaces: list[BehavioralSurface] = []
        for asset, dimension_values in grouped.items():
            variants = tuple(
                f"{key}={value}"
                for key in sorted(dimension_values)
                for value in sorted(dimension_values[key])
            )
            payload = json.dumps(
                {"asset": asset, "variants": variants}, sort_keys=True, separators=(",", ":")
            )
            surfaces.append(
                BehavioralSurface(
                    surface_id=hashlib.sha256(payload.encode()).hexdigest(),
                    asset=asset,
                    dimensions=tuple(sorted(dimension_values)),
                    observed_variants=variants or ("unclassified",),
                    stability=1.0 if len(variants) <= 1 else 0.75,
                    source_refs=tuple(sorted(refs[asset])),
                )
            )
        return tuple(sorted(surfaces, key=lambda item: item.surface_id))


class SecurityInvariantCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    invariant_id: str = Field(min_length=16, max_length=128)
    asset: str = Field(min_length=1, max_length=240)
    statement: str = Field(min_length=8, max_length=500)
    predicate: str = Field(min_length=8, max_length=500)
    affected_entities: tuple[str, ...] = Field(min_length=1, max_length=12)
    validation_method: str = Field(min_length=8, max_length=240)
    source_refs: tuple[str, ...] = Field(min_length=1, max_length=32)
    confidence: float = Field(ge=0.0, le=1.0)
    requires_negative_control: bool = True


class SecurityInvariantMiner:
    """Infer only explicit, testable invariants from role/ownership contrasts."""

    def mine(
        self, surfaces: Iterable[BehavioralSurface], world_model: SecurityWorldModel
    ) -> tuple[SecurityInvariantCandidate, ...]:
        if not isinstance(world_model, SecurityWorldModel):
            raise TypeError("security_world_model_required")
        output: list[SecurityInvariantCandidate] = []
        for surface in surfaces:
            contrast = any(
                sum(variant.startswith(f"{dimension}=") for variant in surface.observed_variants)
                >= 2
                for dimension in ("role", "subject")
            )
            if not contrast:
                continue
            invariant = next(
                (
                    item
                    for item in world_model.invariants
                    if item.protected_resource == surface.asset
                ),
                None,
            )
            if invariant is None:
                continue
            intents = tuple(
                item
                for item in world_model.business_intents
                if surface.asset in item.workflow or surface.asset in item.goal
            )
            statement = invariant.statement
            predicate = (
                "candidate and independent negative control differ only in the "
                f"authorized subject for {surface.asset}; expected conditions are "
                f"{', '.join(invariant.allowed_conditions) or 'lineage-defined'}."
            )
            affected_entities = tuple(
                dict.fromkeys(
                    (
                        surface.asset,
                        invariant.subject,
                        *(item.workflow for item in intents),
                    )
                )
            )
            validation_method = (
                "candidate/control comparison with causal oracle, independent "
                "negative control, and central verifier"
            )
            source_refs = tuple(
                dict.fromkeys(
                    (*surface.source_refs, *invariant.lineage.evidence_refs)
                    + tuple(ref for item in intents for ref in item.lineage.evidence_refs)
                )
            )
            payload = json.dumps(
                {
                    "asset": surface.asset,
                    "statement": statement,
                    "predicate": predicate,
                    "source_refs": source_refs,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            output.append(
                SecurityInvariantCandidate(
                    invariant_id=hashlib.sha256(payload.encode()).hexdigest(),
                    asset=surface.asset,
                    statement=statement,
                    predicate=predicate,
                    affected_entities=affected_entities,
                    validation_method=validation_method,
                    source_refs=source_refs,
                    confidence=surface.stability * 0.8,
                )
            )
        return tuple(sorted(output, key=lambda item: item.invariant_id))


__all__ = [
    "BehavioralSurface",
    "BehavioralSurfaceDiscovery",
    "SecurityInvariantCandidate",
    "SecurityInvariantMiner",
]
