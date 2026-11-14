# src/webpent/business_logic/value_fuzzer.py
"""Business-logic value fuzzer (PROPOSALS_ULTIMATE_V3 §2, 2026-10-31).

The manual workflows behind the most valuable bug-bounty reports —
price tampering, quantity/overflow tricks, IDOR-style ID swaps — are
not SQLi payloads: they exploit semantic values. This module mutates
those values along a DOCUMENTED MANUAL LIST (nothing auto-generated,
no ML, no LLM) and replays a captured flow with each mutation through
an injected executor, so one mechanism serves both HTTP request plans
and pure unit tests.

Design:
  - Pure logic here; network is ALWAYS an injected callable
    (``executor(step, mutated_value)``). The module never opens a
    socket.
  - Mandatory safety path per mutated request, in order:
    ``scope_enforcer.check_url`` (refused before send with
    ``inconclusive: out_of_scope``) → ``request_ledger.record`` (a
    request the ledger cannot record is not sent). The LLM spend
    governor is not in this path because the fuzzer makes zero LLM
    calls by construction.
  - Success under a mutated value is a CANDIDATE observation
    (``needs_verification=True``); nothing is ever labeled confirmed
    at this layer — confirmation belongs to the verifier, and the
    operator sees ``verification_pending`` until then.
  - Every mutation across the whole plan is bounded by
    ``logic_fuzz_max_mutations`` (default 50, hard cap 500) so a plan
    with many fields cannot fan out unboundedly.

Flag-gated by ``enable_logic_fuzzing`` (default False): with the flag
off ``run_plan`` raises before touching the executor, the ledger or
the scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

__all__ = [
    "ART_LOGIC_MUTATION",
    "KINDS",
    "Mutation",
    "MoneyValue",
    "CountValue",
    "IdValue",
    "make_value",
    "FlowStep",
    "FlowPlan",
    "ResponseOutcome",
    "LogicFuzzError",
    "logic_fuzz_refusal",
    "run_plan",
]

ART_LOGIC_MUTATION = "logic-mutation"

KINDS = frozenset({"money", "count", "id"})

# Hard cap on total mutations per plan run, independent of settings
# (a mistyped cap cannot fan out unboundedly).
MAX_MUTATIONS_CAP = 500


class LogicFuzzError(ValueError):
    """Raised when logic fuzzing cannot proceed fail-closed."""


# ---------------------------------------------------------------------------
# Value kinds with their documented manual mutation lists.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Mutation:
    label: str
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"label": self.label, "value": self.value}


def _numeric(raw: str) -> float | None:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


class MoneyValue:
    """Price/amount fields. Manual list: zero, negative, tiny fraction,
    scientific notation, precision spoofing, string injection."""

    kind = "money"

    def __init__(self, field_name: str, original: str):
        self.field_name = field_name
        self.original = str(original)

    def mutations(self) -> list[Mutation]:
        num = _numeric(self.original)
        negative = str(-abs(num)) if num is not None else "-1.00"
        return [
            Mutation("zero", "0.00"),
            Mutation("negative", negative),
            Mutation("tiny_fraction", "0.01"),
            Mutation("scientific", "1e-9"),
            Mutation(
                "precision_spoof",
                self.original + "0000001" if num is not None else "100.0000001",
            ),
            Mutation("string_injection", f"{self.original}; price 0"),
        ]


class CountValue:
    """Quantity/limit fields. Manual list: zero, negative, one less,
    one more, huge, float."""

    kind = "count"

    def __init__(self, field_name: str, original: str):
        self.field_name = field_name
        self.original = str(original)

    def mutations(self) -> list[Mutation]:
        num = _numeric(self.original)
        one_less = str(int(num) - 1) if num is not None and num == int(num) else "0"
        one_more = str(int(num) + 1) if num is not None and num == int(num) else "2"
        return [
            Mutation("zero", "0"),
            Mutation("negative", "-1"),
            Mutation("one_less", one_less),
            Mutation("one_more", one_more),
            Mutation("huge", str(10**9)),
            Mutation("overflow_string", "9" * 20),
            Mutation("float", "1.5"),
        ]


class IdValue:
    """Object-identifier fields (IDOR-style, in-scope only). Manual
    list: zero, negative, empty, off-by-one, huge."""

    kind = "id"

    def __init__(self, field_name: str, original: str):
        self.field_name = field_name
        self.original = str(original)

    def mutations(self) -> list[Mutation]:
        num = _numeric(self.original)
        off_by_one = (
            str(int(num) + 1) if num is not None and num == int(num) else "2"
        )
        return [
            Mutation("zero", "0"),
            Mutation("negative", "-1"),
            Mutation("empty", ""),
            Mutation("off_by_one_up", off_by_one),
            Mutation("huge", str(10**9)),
        ]


_KIND_TO_CLASS = {"money": MoneyValue, "count": CountValue, "id": IdValue}


def make_value(field_name: str, original: str, kind: str) -> MoneyValue | CountValue | IdValue:
    """Build a value wrapper by kind (fail-closed on unknown kind)."""
    if kind not in KINDS:
        raise LogicFuzzError(
            f"logic_fuzz_unknown_kind: {kind!r} (expected one of {sorted(KINDS)})"
        )
    return _KIND_TO_CLASS[kind](field_name, original)


def money_mutations(field_name: str, original: str) -> list[Mutation]:
    """MoneyValue mutation list (helper mirroring the class API)."""
    return MoneyValue(field_name, original).mutations()


def count_mutations(field_name: str, original: str) -> list[Mutation]:
    """CountValue mutation list (helper mirroring the class API)."""
    return CountValue(field_name, original).mutations()


def id_mutations(field_name: str, original: str) -> list[Mutation]:
    """IdValue mutation list (helper mirroring the class API)."""
    return IdValue(field_name, original).mutations()


# ---------------------------------------------------------------------------
# Plans and responses.
# ---------------------------------------------------------------------------


@dataclass
class FlowStep:
    """One captured request in a flow, plus one field to mutate."""

    step_id: str
    method: str
    url: str
    field: str
    kind: str
    original: str
    # the operator/plan declares the normal-flow outcome so the fuzzer
    # can distinguish 'flow succeeded as usual' from 'flow succeeded
    # DESPITE the mutation'; baseline itself is never an observation.
    baseline_accepted: bool = False


@dataclass
class FlowPlan:
    plan_id: str
    steps: list[FlowStep] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not str(self.plan_id).strip():
            raise LogicFuzzError("logic_fuzz_schema: empty plan_id")
        for step in self.steps:
            if not (step.url or "").strip():
                raise LogicFuzzError(
                    f"logic_fuzz_schema: step {step.step_id!r} has empty url"
                )
            if not (step.field or "").strip():
                raise LogicFuzzError(
                    f"logic_fuzz_schema: step {step.step_id!r} has empty field"
                )
            if step.kind not in KINDS:
                raise LogicFuzzError(
                    f"logic_fuzz_unknown_kind: {step.kind!r} (expected one of {sorted(KINDS)})"
                )


@dataclass
class ResponseOutcome:
    """What the executor reports back for one mutated request.

    ``accepted`` is the caller's judgment that the flow COMPLETED
    successfully (e.g. the order was placed, the final total was
    charged as mutated). ``status``/``body`` are pass-through context.
    """

    status: int = 0
    body: str = ""
    accepted: bool = False


# ---------------------------------------------------------------------------
# Observations.
# ---------------------------------------------------------------------------


@dataclass
class Observation:
    step_id: str
    field: str
    kind: str
    original: str
    label: str
    mutated: str
    request_sent: bool = False
    status: int | None = None
    accepted: bool = False
    needs_verification: bool = False
    inconclusive: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "field": self.field,
            "kind": self.kind,
            "original": self.original,
            "mutation": self.label,
            "mutated_value": self.mutated,
            "request_sent": self.request_sent,
            "status": self.status,
            "accepted": self.accepted,
            "needs_verification": self.needs_verification,
            "inconclusive": self.inconclusive,
            # fixed marker: this layer NEVER confirms — the verifier does
            "verified": False,
        }

    def to_artifact(self) -> dict[str, Any]:
        """Chain v3 artifact shape (type ``ART_LOGIC_MUTATION``)."""
        return {
            "type": ART_LOGIC_MUTATION,
            "plan_step": self.step_id,
            "field": self.field,
            "mutation": self.label,
            "mutated_value": self.mutated,
            "status": self.status,
            "needs_verification": self.needs_verification,
            "verified": False,
        }


# ---------------------------------------------------------------------------
# Gate and execution.
# ---------------------------------------------------------------------------


def logic_fuzz_refusal() -> str | None:
    """Refusal code when the operator's flag is off, else None."""
    from webpent.config.settings import get_settings

    if not get_settings().enable_logic_fuzzing:
        return "logic_fuzzing_flag_off"
    return None


def _mutation_budget(max_mutations: int | None) -> int:
    from webpent.config.settings import get_settings

    if max_mutations is None:
        max_mutations = get_settings().logic_fuzz_max_mutations
    try:
        budget = int(max_mutations)
    except (TypeError, ValueError) as exc:
        raise LogicFuzzError(f"logic_fuzz_invalid_max_mutations: {max_mutations!r}") from exc
    if budget <= 0:
        raise LogicFuzzError(f"logic_fuzz_invalid_max_mutations: {max_mutations!r}")
    return min(budget, MAX_MUTATIONS_CAP)


def run_plan(
    plan: FlowPlan,
    executor: Callable[[FlowStep, str], ResponseOutcome],
    ledger: Any,
    scope: Any,
    *,
    max_mutations: int | None = None,
) -> list[Observation]:
    """Replay a flow with every documented mutation, bounded and gated.

    Mandatory per mutated request, in order: the flag gate, the scope
    check (refused BEFORE send, observation marked
    ``inconclusive: out_of_scope``), the ledger record (a request the
    ledger cannot record is not sent). The executor is a plain
    callable — never a network client owned by this module.
    """
    refusal = logic_fuzz_refusal()
    if refusal:
        raise LogicFuzzError(refusal)
    if ledger is None or not hasattr(ledger, "record"):
        raise LogicFuzzError("logic_fuzz_ledger_required")
    if scope is None or not hasattr(scope, "check_url"):
        raise LogicFuzzError("logic_fuzz_scope_required")
    budget = _mutation_budget(max_mutations)

    observations: list[Observation] = []
    for step in plan.steps:
        value = make_value(step.field, step.original, step.kind)
        for mutation in value.mutations():
            if budget <= 0:
                return observations
            budget -= 1

            decision = scope.check_url(step.url, method=step.method)
            if decision is not None and not getattr(decision, "allowed", True):
                observations.append(
                    Observation(
                        step_id=step.step_id,
                        field=step.field,
                        kind=step.kind,
                        original=step.original,
                        label=mutation.label,
                        mutated=mutation.value,
                        inconclusive="out_of_scope",
                    )
                )
                continue

            try:
                recorded = ledger.record(
                    step.method,
                    step.url,
                    engagement_id=getattr(ledger, "active_engagement_id", "") or "",
                    flags="logic_fuzz",
                )
            except Exception:  # noqa: BLE001 — ledger failure must not bypass
                recorded = False
            if not recorded:
                observations.append(
                    Observation(
                        step_id=step.step_id,
                        field=step.field,
                        kind=step.kind,
                        original=step.original,
                        label=mutation.label,
                        mutated=mutation.value,
                        inconclusive="ledger_refused",
                    )
                )
                continue

            try:
                outcome = executor(step, mutation.value)
                if not isinstance(outcome, ResponseOutcome):
                    outcome = ResponseOutcome(
                        status=int(getattr(outcome, "status", 0)),
                        body=str(getattr(outcome, "body", "")),
                        accepted=bool(getattr(outcome, "accepted", False)),
                    )
            except Exception as exc:  # noqa: BLE001 — executor errors are observations
                observations.append(
                    Observation(
                        step_id=step.step_id,
                        field=step.field,
                        kind=step.kind,
                        original=step.original,
                        label=mutation.label,
                        mutated=mutation.value,
                        inconclusive=f"executor_error: {type(exc).__name__}",
                    )
                )
                continue

            accepted = bool(outcome.accepted)
            observations.append(
                Observation(
                    step_id=step.step_id,
                    field=step.field,
                    kind=step.kind,
                    original=step.original,
                    label=mutation.label,
                    mutated=mutation.value,
                    request_sent=True,
                    status=int(outcome.status),
                    accepted=accepted,
                    # candidate only: success DESPITE the mutation. The
                    # normal flow (baseline_accepted) never produces an
                    # observation, and nothing here is ever "confirmed".
                    needs_verification=accepted and not step.baseline_accepted,
                )
            )
    return observations
