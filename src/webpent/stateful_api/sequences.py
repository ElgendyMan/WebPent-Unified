"""webpent.stateful_api.sequences — M5 (Part 4 §7): bounded stateful
sequence generation.

The acceptance: "seeded multi-request states discovered + replayable
with same preconditions/identity; causal evidence bundle for sequences;
bounded budgets/cleanup".

* :func:`generate_sequences` — walks the inferred dependency graph from
  each creator: a sequence is a deterministic chain of operations where
  each step consumes state a previous step produces. Bounded TWICE
  (max_sequences × max_depth) plus a per-sequence request budget.
* :class:`SequencePlan` — carries the replay contract: preconditions
  (identities, seed state), per-step request specs, expected effects,
  the negative control, and the CLEANUP plan (reverse order; DELETE
  where the contract has one — a sequence that cannot clean up says so
  honestly).
* :func:`sequence_hypotheses` — the advisory projection: each plan
  becomes a typed :class:`Hypothesis` (status ``unexplored``, origin
  ``heuristic``, provenance ``stateful_api_sequence``) carrying the M3
  research-contract fields (preconditions / expected_behavior /
  negative_control) — advisory guidance for the hunt, never a finding.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field

from webpent.stateful_api.contracts import (
    ApiOperation,
    StateDependency,
    infer_dependencies,
)

__all__ = [
    "SequencePlan",
    "SequenceStep",
    "generate_sequences",
    "sequence_hypotheses",
]

_DEFAULT_MAX_SEQUENCES = 16
_DEFAULT_MAX_DEPTH = 6


class SequenceStep(BaseModel):
    """One step of a stateful sequence: the operation plus the role that
    must execute it and the state it expects."""

    model_config = ConfigDict(extra="forbid")

    operation_id: str
    method: str
    path: str
    role: str = "primary"
    consumes: list[str] = Field(default_factory=list, max_length=10)
    produces: list[str] = Field(default_factory=list, max_length=10)
    request_spec: dict[str, Any] = Field(default_factory=dict)


class SequencePlan(BaseModel):
    """A bounded, replayable stateful sequence."""

    model_config = ConfigDict(extra="forbid")

    sequence_id: str = Field(min_length=3, max_length=120)
    steps: list[SequenceStep] = Field(default_factory=list, max_length=12)
    preconditions: list[str] = Field(default_factory=list, max_length=20)
    expected_effects: list[str] = Field(default_factory=list, max_length=20)
    negative_control: str = Field(default="", max_length=400)
    cleanup_steps: list[str] = Field(default_factory=list, max_length=12)
    cleanup_complete: bool = False
    budget_requests: int = Field(default=0, ge=0, le=64)
    provenance: str = "stateful_api:inferred_dependencies"

    def replay_spec(self) -> dict[str, Any]:
        """The deterministic replay contract (same preconditions, same
        identities, same requests — byte-stable ordering)."""
        return {
            "sequence_id": self.sequence_id,
            "preconditions": list(self.preconditions),
            "steps": [step.model_dump(mode="json") for step in self.steps],
            "expected_effects": list(self.expected_effects),
            "budget_requests": self.budget_requests,
        }


def _stable_id(parts: Iterable[str]) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8", "replace")).hexdigest()[:16]
    return f"seq-{digest}"


def generate_sequences(
    operations: Iterable[ApiOperation],
    *,
    max_sequences: int = _DEFAULT_MAX_SEQUENCES,
    max_depth: int = _DEFAULT_MAX_DEPTH,
) -> list[SequencePlan]:
    """Generate bounded stateful sequences from inferred dependencies.

    Deterministic: operations are processed in their given order; a
    sequence per creator, extended while a consumer of the running
    state exists. A second-level chain (update-after-create) is allowed
    when the same collection offers both.
    """
    operations = list(operations)
    dependencies = infer_dependencies(operations)
    by_id = {operation.operation_id: operation for operation in operations}

    # consumer prefix -> dependencies
    consumers_by_producer: dict[str, list[StateDependency]] = {}
    for dependency in dependencies:
        consumers_by_producer.setdefault(
            dependency.producer_operation_id, []
        ).append(dependency)

    creators = [
        operation
        for operation in operations
        if operation.method in {"POST", "PUT", "PATCH"} and operation.collection_path
    ]

    plans: list[SequencePlan] = []
    for creator in creators:
        if len(plans) >= max_sequences:
            break
        resource_names: list[str] = []
        steps: list[SequenceStep] = []
        prefix = creator.collection_path or ""
        resource = prefix.rstrip("/").rsplit("/", 1)[-1] or "resource"
        resource_names.append(f"{resource}_id")
        steps.append(
            SequenceStep(
                operation_id=creator.operation_id,
                method=creator.method,
                path=creator.path,
                role="primary",
                consumes=[],
                produces=[f"{resource}_id"],
                request_spec={
                    "method": creator.method,
                    "path": creator.path,
                    "body_properties": creator.body_properties[:20],
                },
            )
        )
        # Extend while an unvisited consumer of the running state exists.
        visited = {creator.operation_id}
        produced = set(resource_names)
        while len(steps) < max_depth:
            extended = False
            for dependency in consumers_by_producer.get(steps[-1].operation_id, []):
                consumer = by_id.get(dependency.consumer_operation_id)
                if consumer is None or consumer.operation_id in visited:
                    continue
                if dependency.resource_name not in produced:
                    continue
                visited.add(consumer.operation_id)
                steps.append(
                    SequenceStep(
                        operation_id=consumer.operation_id,
                        method=consumer.method,
                        path=consumer.path,
                        role="primary",
                        consumes=[dependency.resource_name],
                        produces=[],
                        request_spec={
                            "method": consumer.method,
                            "path": consumer.path,
                            "path_params": consumer.path_params[:10],
                        },
                    )
                )
                extended = True
                break
            if not extended:
                break

        if len(steps) < 2:
            continue  # a single request is not a stateful sequence

        deleters = {
            operation.item_path_prefix or "": operation
            for operation in operations
            if operation.method == "DELETE" and operation.item_path_prefix
        }
        cleanup_steps: list[str] = []
        for step in reversed(steps):
            if step.method in {"POST", "PUT", "PATCH"}:
                deleter = deleters.get(
                    (by_id[step.operation_id].collection_path or "")
                )
                if deleter is not None:
                    cleanup_steps.append(deleter.operation_id)
        cleanup_complete = bool(cleanup_steps) and len(cleanup_steps) == len(
            [s for s in steps if s.method in {"POST", "PUT", "PATCH"}]
        )

        plans.append(
            SequencePlan(
                sequence_id=_stable_id([step.operation_id for step in steps]),
                steps=steps,
                preconditions=[
                    "identity:primary (operator-supplied, authorized)",
                    f"seed:create {resource} via {creator.operation_id}",
                ],
                expected_effects=[
                    f"{step.operation_id} succeeds and state advances"
                    for step in steps[1:]
                ],
                negative_control=(
                    "a randomized non-existent resource id must reproduce "
                    "the baseline (404/403) — a step whose control fires "
                    "refutes the sequence's state assumption"
                ),
                cleanup_steps=cleanup_steps,
                cleanup_complete=cleanup_complete,
                budget_requests=len(steps) + len(cleanup_steps),
            )
        )
    return plans


def sequence_hypotheses(
    plans: Iterable[SequencePlan],
    *,
    target_url: str,
    hypothesis_factory: Any = None,
) -> list[Any]:
    """Project plans as advisory hypotheses (M3 research-contract fields)."""
    import uuid

    out: list[Any] = []
    for plan in plans:
        if hypothesis_factory is not None:
            hypothesis = hypothesis_factory(plan, target_url)
            if hypothesis is not None:
                out.append(hypothesis)
            continue
        from webpent.models.hypothesis import Hypothesis, HypothesisStatus

        hypothesis = Hypothesis(
            id=uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"webpent:stateful_api:sequence:{plan.sequence_id}",
            ),
            target_url=target_url,
            statement=(
                f"Stateful sequence ({len(plan.steps)} steps) may expose "
                "state-dependent behavior: "
                + " -> ".join(s.operation_id for s in plan.steps)
            )[:500],
            status=HypothesisStatus.UNEXPLORED,
            origin_detail=f"stateful_api_sequence:{plan.sequence_id}",
            preconditions=list(plan.preconditions),
            expected_behavior=("; ".join(plan.expected_effects))[:500],
            negative_control=plan.negative_control,
        )
        out.append(hypothesis)
    return out
