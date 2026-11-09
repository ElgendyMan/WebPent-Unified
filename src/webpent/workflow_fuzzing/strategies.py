# src/webpent/workflow_fuzzing/strategies.py
"""Mutation strategies for workflow-integrity fuzzing (Proposal 9).

Deterministic, bounded mutation of a recorded workflow: reorder steps,
skip a step, replay a step, tamper a semantic field (price/quantity/
coupon), or mark a step for a race. EVERY mutation carries a benign
control twin — the SAME kind of mutation applied to the workflow's
benign step — so the validator can demand that a CONFIRMED break be
specific to the sensitive path, not a property of the mutation itself.

The LLM may suggest semantic field VALUES only; it never decides
whether an integrity break is confirmed — that is the validator's
pure contract.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

MUTATION_KINDS: tuple[str, ...] = (
    "reorder_steps",
    "skip_step",
    "replay_step",
    "price_tamper",
    "race_on_step",
)

# Hard bound on workflow length accepted for mutation. Fail-closed:
# longer workflows are rejected for fuzzing rather than unboundedly
# exploded (replay/ordering explode combinatorially).
MAX_MUTATED_STEPS = 8

# Deterministic semantic-field fill (Proposal 9 step 1). Realistic
# values so tampering tests a real purchase semantics, not a null.
SEMANTIC_FILL: dict[str, Any] = {
    "price": 19.99,
    "quantity": 2,
    "coupon_code": "SAVE10",
    "discount": 10,
    "currency": "USD",
    "shipping_method": "standard",
}

# Fields the price-tamper mutation rewrites, and the value it writes.
PRICE_FIELDS = ("price", "amount", "total", "unit_price")
TAMPER_PRICE = 0.01


@dataclass(frozen=True)
class WorkflowStep:
    """One recorded request of a workflow."""

    name: str
    method: str = "POST"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] = field(default_factory=dict)
    is_benign_control: bool = False


@dataclass(frozen=True)
class MutatedWorkflow:
    """One bounded mutation plus its benign control twin.

    ``steps`` is the mutated workflow; ``control_steps`` the original
    (unmutated) workflow; ``control_mutated`` the SAME kind of mutation
    applied to the benign step (None when the workflow has no benign
    step the kind can act on — the executor then fails closed to
    inconclusive rather than confirming without a control).
    """

    kind: str
    label: str
    steps: tuple[WorkflowStep, ...]
    control_steps: tuple[WorkflowStep, ...]
    control_mutated: tuple[WorkflowStep, ...] | None = None
    race: bool = False
    # Indices into control_steps (the original workflow): the sensitive
    # step the mutation acted on, and the benign step the control twin
    # acted on (-1 when there is no twin).
    target_index: int = -1
    control_index: int = -1

    def __post_init__(self) -> None:
        if self.kind not in MUTATION_KINDS:
            raise ValueError(f"unknown mutation kind: {self.kind}")


def semantically_fill(body: dict[str, Any], llm_hint: dict[str, Any] | None = None) -> dict[str, Any]:
    """Normalize semantic fields (price, quantity, coupon id) deterministically.

    Only fields ALREADY PRESENT in the body are filled — present-but-empty
    (None, wrong type) gets the deterministic default, or the LLM's
    proposed VALUE via ``llm_hint`` when that hint is a plain value.
    Keys the body never had are never invented.
    """
    filled = dict(body)
    for key, default in SEMANTIC_FILL.items():
        if key in filled and not isinstance(filled[key], (int, float, str)):
            value = (llm_hint or {}).get(key)
            filled[key] = value if isinstance(value, (int, float, str)) else default
    return filled


def _tamper_prices(body: dict[str, Any], value: float = TAMPER_PRICE) -> dict[str, Any]:
    # semantically_fill first: a present-but-None semantic field would
    # survive tampering untouched (nothing to overwrite) and mute the
    # mutation — filling gives the tamper something real to attack
    # (the v3.0 defect: semantically_fill existed but was never wired
    # into any mutation — dead code).
    out = semantically_fill(body)
    for k in PRICE_FIELDS:
        if k in out:
            out[k] = value
    return out


def _steps_ok(steps: Iterable[WorkflowStep]) -> tuple[WorkflowStep, ...]:
    tup = tuple(steps)
    if not 2 <= len(tup) <= MAX_MUTATED_STEPS:
        raise ValueError(
            f"workflow length must be 2..{MAX_MUTATED_STEPS}, got {len(tup)}"
        )
    return tup


def mutate_workflow_at(
    steps: tuple[WorkflowStep, ...], kind: str, target_index: int
) -> tuple[WorkflowStep, ...]:
    """Apply ONE bounded mutation at an explicit index; pure tuple out.

    Raises when the kind cannot act at ``target_index`` (reorder needs a
    predecessor, skip needs a successor). Deterministic for the triple.
    """
    tup = _steps_ok(steps)
    if not 0 <= target_index < len(tup):
        raise ValueError(f"target index {target_index} out of range")
    i = target_index
    if kind == "reorder_steps":
        if i == 0:
            raise ValueError("reorder needs a predecessor step")
        reordered = list(tup)
        reordered[i - 1], reordered[i] = reordered[i], reordered[i - 1]
        return tuple(reordered)
    if kind == "skip_step":
        if i + 1 >= len(tup):
            raise ValueError("skip needs a successor step to observe")
        return tup[:i] + tup[i + 1:]
    if kind == "replay_step":
        return tup[: i + 1] + (tup[i],) + tup[i + 1:]
    if kind == "price_tamper":
        s = tup[i]
        out = list(tup)
        out[i] = WorkflowStep(
            s.name, s.method, s.url, s.headers, _tamper_prices(s.body),
            s.is_benign_control,
        )
        return tuple(out)
    if kind == "race_on_step":
        return tup + (tup[i],)
    raise ValueError(f"unknown mutation kind: {kind}")


def _control_index(tup: tuple[WorkflowStep, ...], kind: str) -> int | None:
    """First benign index the kind can act on, or None (fail-closed)."""
    for j, s in enumerate(tup):
        if not s.is_benign_control:
            continue
        if kind == "reorder_steps" and j == 0:
            continue
        if kind == "skip_step" and j + 1 >= len(tup):
            continue
        return j
    return None


def _kind_targets(tup: tuple[WorkflowStep, ...], kind: str) -> list[int]:
    """Sensitive indices the kind can act on (fail-closed per kind)."""
    targets = []
    for i, s in enumerate(tup):
        if s.is_benign_control:
            continue
        if kind == "reorder_steps" and i == 0:
            continue  # no predecessor to move before
        if kind == "skip_step" and i + 1 >= len(tup):
            continue  # no successor to observe the skip through
        targets.append(i)
    return targets


def mutate_workflow(
    steps: tuple[WorkflowStep, ...], kind: str, index: int = 0
) -> MutatedWorkflow:
    """Apply ONE bounded mutation; deterministic for (steps, kind, index).

    The result carries the benign control twin: the same kind applied to
    the first benign step the kind can act on, or None when there is
    none (the executor then cannot confirm anything for this mutation).
    """
    tup = _steps_ok(steps)
    targets = _kind_targets(tup, kind)
    if not targets:
        raise ValueError(f"mutation kind {kind} has no applicable target step")
    i = targets[index % len(targets)]
    mutated = mutate_workflow_at(tup, kind, i)
    labels = {
        "reorder_steps": f"reorder {tup[i].name} before {tup[i-1].name}"
        if i > 0
        else f"reorder {tup[i+1].name} before {tup[i].name}",
        "skip_step": f"skip {tup[i].name}",
        "replay_step": f"replay {tup[i].name}",
        "price_tamper": f"tamper price of {tup[i].name} to {TAMPER_PRICE}",
        "race_on_step": f"race on {tup[i].name}",
    }
    control_mutated: tuple[WorkflowStep, ...] | None = None
    j = _control_index(tup, kind)
    if j is not None:
        control_mutated = mutate_workflow_at(tup, kind, j)
    return MutatedWorkflow(
        kind,
        labels[kind],
        mutated,
        tup,
        control_mutated=control_mutated,
        race=(kind == "race_on_step"),
        target_index=i,
        control_index=(j if j is not None else -1),
    )


def enumerate_mutations(steps: tuple[WorkflowStep, ...]) -> list[MutatedWorkflow]:
    """All bounded mutations, one per (kind, sensitive index), deterministic."""
    tup = _steps_ok(steps)
    out: list[MutatedWorkflow] = []
    for kind in MUTATION_KINDS:
        targets = _kind_targets(tup, kind)
        for index in range(len(targets)):
            out.append(mutate_workflow(tup, kind, index=index))
    return out


def control_for(steps: tuple[WorkflowStep, ...]) -> tuple[WorkflowStep, ...]:
    """The benign control path — the mutation is replayed against it."""
    tup = _steps_ok(steps)
    control = [s for s in tup if s.is_benign_control]
    return tuple(control) if control else tup[:1]
