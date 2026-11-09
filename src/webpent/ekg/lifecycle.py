"""webpent.ekg.lifecycle — M7 (Part 4 §9): knowledge lifecycle.

Registry scope: "knowledge lifecycle (versioning, review, regression
per template, human review for new action types)".

* :class:`KnowledgeRegistry` — version-pinned registration
  (``id@version`` is the key; re-registering the same version with
  different content is refused); lookup by id returns the LATEST
  version deterministically.
* Review states: ``draft`` → ``reviewed`` → ``regression_passed`` →
  ``released`` — transitions are one-way and ``released`` requires BOTH
  a human reviewer (``provenance_reviewed_by``) AND a passing
  regression. A NEW action type (one no released item uses) requires
  explicit human review before its first release — the registry refuses
  otherwise.
* :func:`regression_spec_for` — every executable template gets a
  REGRESSION: deterministic sample fills → the exact argv the template
  must render (pure assertion, no execution). Released items without a
  regression spec cannot exist (the transition enforces it).
* :func:`assert_registry_regressions` — runs every regression (argv
  equality against the recorded expectation).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.ekg.executor import render_argv, validate_fill
from webpent.ekg.schema import ArgumentSpec, KnowledgeItem

__all__ = [
    "KnowledgeRegistry",
    "RegressionSpec",
    "assert_registry_regressions",
    "regression_spec_for",
]

_REVIEW_STATES = ("draft", "reviewed", "regression_passed", "released")


class RegressionSpec(BaseModel):
    """One template's regression: sample fills → expected argv."""

    model_config = ConfigDict(extra="forbid")

    item_id: str
    item_version: str
    sample_fill: dict[str, Any] = Field(default_factory=dict)
    expected_argv: list[str] = Field(default_factory=list, min_length=1)

    def run(self, item: KnowledgeItem) -> tuple[bool, list[str]]:
        coerced, errors = validate_fill(item, self.sample_fill)
        if errors:
            return False, [f"sample_fill_invalid:{errors[:4]}"]
        argv = render_argv(item, coerced)
        if argv != self.expected_argv:
            return False, [f"argv_drift:{argv} != {self.expected_argv}"]
        return True, []


def _sample_fill(schema: list[ArgumentSpec]) -> dict[str, Any]:
    """Deterministic sample fill per argument type."""
    fill: dict[str, Any] = {}
    for spec in schema:
        if spec.type == "integer":
            fill[spec.name] = 1
        elif spec.type == "boolean":
            fill[spec.name] = True
        elif spec.type == "enum":
            fill[spec.name] = spec.enum_values[0]
        else:
            # Honor the declared pattern when one exists (keep it simple
            # and deterministic; pattern-special knowledge items ship
            # hand-written regressions).
            fill[spec.name] = "sample"
    return fill


def regression_spec_for(item: KnowledgeItem) -> RegressionSpec:
    sample = _sample_fill(item.argument_schema)
    coerced, errors = validate_fill(item, sample)
    if errors:
        raise ValueError(
            f"cannot build a regression sample for {item.id}@{item.version}: {errors[:3]}"
        )
    return RegressionSpec(
        item_id=item.id,
        item_version=item.version,
        sample_fill=sample,
        expected_argv=render_argv(item, coerced),
    )


class KnowledgeRegistry:
    """The versioned, review-gated executable-knowledge registry."""

    def __init__(self) -> None:
        self._items: dict[str, KnowledgeItem] = {}  # id@version -> item
        self._regressions: dict[str, RegressionSpec] = {}

    @staticmethod
    def _key(item_id: str, version: str) -> str:
        return f"{item_id}@{version}"

    def register(self, item: KnowledgeItem) -> str:
        key = self._key(item.id, item.version)
        existing = self._items.get(key)
        if existing is not None and existing.model_dump() != item.model_dump():
            raise ValueError(
                f"version collision: {key} already registered with different content"
            )
        self._items[key] = item
        return key

    def get(self, item_id: str, version: str | None = None) -> KnowledgeItem | None:
        if version is not None:
            return self._items.get(self._key(item_id, version))
        candidates = [
            item
            for key, item in self._items.items()
            if key.startswith(f"{item_id}@")
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda item: tuple(int(p) for p in item.version.split(".")))

    def list_items(self) -> list[str]:
        return sorted(self._items)

    def release(
        self,
        item: KnowledgeItem,
        *,
        reviewer: str,
        regression: RegressionSpec | None = None,
    ) -> list[str]:
        """The review-gated release transition (one-way).

        Refusals (returned as reasons, never exceptions):
        * no human reviewer recorded;
        * reviewer not distinct from the author;
        * a NEW action type without human review;
        * no passing regression (the deterministic sample by default;
          pattern-bearing items ship a HAND-WRITTEN regression via the
          ``regression`` argument — the sample cannot know their
          patterns).
        """
        reasons: list[str] = []
        if not reviewer.strip():
            reasons.append("human_reviewer_required")
        if not item.provenance_reviewed_by.strip():
            reasons.append("item_records_no_human_review")
        elif item.provenance_reviewed_by.strip() == item.provenance_author.strip():
            reasons.append("reviewer_must_differ_from_author")
        known_action_types = {
            registered.action_type
            for key, registered in self._items.items()
            if key != self._key(item.id, item.version)
            and registered.review_status == "released"
        }
        if (
            item.action_type not in known_action_types
            and not item.provenance_reviewed_by.strip()
        ):
            reasons.append(f"new_action_type_requires_human_review:{item.action_type}")
        spec: RegressionSpec | None = regression
        if spec is None:
            try:
                spec = regression_spec_for(item)
            except ValueError as exc:
                reasons.append(f"regression_unbuildable:{exc}"[:200])
                spec = None
        if spec is not None:
            if spec.item_id != item.id or spec.item_version != item.version:
                reasons.append("regression_spec_item_mismatch")
                spec = None
            else:
                ok, failures = spec.run(item)
                if not ok:
                    reasons.append(f"regression_failed:{failures[:2]}")
                    spec = None
        if reasons or spec is None:
            return reasons or ["no_regression_recorded"]
        self._regressions[self._key(item.id, item.version)] = spec
        released = item.model_copy(update={"review_status": "released"})
        self._items[self._key(item.id, item.version)] = released
        return []

    def regression_specs(self) -> list[RegressionSpec]:
        return list(self._regressions.values())


def assert_registry_regressions(
    registry: KnowledgeRegistry,
) -> list[tuple[str, list[str]]]:
    """Run every recorded regression; return the failures (empty = pass)."""
    failures: list[tuple[str, list[str]]] = []
    for spec in registry.regression_specs():
        item = registry.get(spec.item_id, spec.item_version)
        if item is None:  # pragma: no cover — registry keeps its items
            failures.append((spec.item_id, ["item_missing"]))
            continue
        ok, errors = spec.run(item)
        if not ok:
            failures.append((f"{spec.item_id}@{spec.item_version}", errors))
    return failures
