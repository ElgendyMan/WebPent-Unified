"""Safe adapters from existing advisory projections into research planning."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator

_SECRET_MARKERS = (
    "password",
    "passwd",
    "token",
    "secret",
    "cookie",
    "authorization",
    "api_key",
    "payload",
    "raw_body",
)


def _hint(value: object) -> str | None:
    clean = str(value or "").strip()[:240]
    if not clean or any(marker in clean.lower() for marker in _SECRET_MARKERS):
        return None
    return clean


def _projection_scope(source: Mapping[str, object], *, engagement_id: str, target_id: str) -> None:
    source_engagement = source.get("engagement_id") or source.get("engagement_ref")
    source_target = source.get("target_id") or source.get("target_ref")
    if source_engagement is not None and str(source_engagement) != engagement_id:
        raise ValueError("projection_engagement_mismatch")
    if source_target is not None and str(source_target) != target_id:
        raise ValueError("projection_target_mismatch")


def _collect_labels(source: Mapping[str, object], keys: tuple[str, ...]) -> set[str]:
    labels: set[str] = set()
    for key in keys:
        value = source.get(key)
        values = value if isinstance(value, (list, tuple, set)) else [value]
        for item in values:
            label = _hint(item)
            if label:
                labels.add(label)
    return labels


class ProjectionPlanningInput(BaseModel):
    """Frozen planning inputs detached from executable graph nodes."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    engagement_id: str = Field(..., min_length=1, max_length=160)
    target_id: str = Field(..., min_length=1, max_length=160)
    has_application_model: bool = False
    has_target_backed_observation: bool = False
    has_negative_control: bool = False
    has_replayable_proof: bool = False
    planning_hints: tuple[str, ...] = Field(default=(), max_length=64)

    @field_validator("planning_hints")
    @classmethod
    def _unique_hints(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(value[:240] for value in values if value.strip()))[:64]

    def as_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")


class ProjectionPlanningAdapter:
    """Convert already-built projections into bounded planner signals."""

    @staticmethod
    def from_sources(
        *,
        engagement_id: str,
        target_id: str,
        target_brain: Mapping[str, object] | None = None,
        attack_graph: Mapping[str, object] | None = None,
        application_model: Mapping[str, object] | None = None,
        knowledge_gaps: Iterable[str] = (),
        has_target_backed_observation: bool = False,
        has_negative_control: bool = False,
        has_replayable_proof: bool = False,
    ) -> ProjectionPlanningInput:
        engagement_id = str(engagement_id or "").strip()
        target_id = str(target_id or "").strip()
        if not engagement_id or not target_id:
            raise ValueError("projection_scope_required")
        sources = [source for source in (target_brain, attack_graph, application_model) if source]
        for source in sources:
            if isinstance(source, Mapping):
                _projection_scope(source, engagement_id=engagement_id, target_id=target_id)

        hints: set[str] = set()
        for source in sources:
            if not isinstance(source, Mapping):
                continue
            hints.update(
                _collect_labels(
                    source,
                    ("coverage_gaps", "knowledge_gaps", "runtime_capability_gaps", "gaps"),
                )
            )
        for value in knowledge_gaps:
            label = _hint(value)
            if label:
                hints.add(label)
        return ProjectionPlanningInput(
            engagement_id=engagement_id,
            target_id=target_id,
            has_application_model=bool(target_brain or application_model),
            has_target_backed_observation=has_target_backed_observation,
            has_negative_control=has_negative_control,
            has_replayable_proof=has_replayable_proof,
            planning_hints=tuple(sorted(hints))[:64],
        )


__all__ = ["ProjectionPlanningAdapter", "ProjectionPlanningInput"]
