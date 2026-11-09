"""L9 §2 — red-first tests for structured preconditions.

The mission rule under test: an inferred precondition is never a
verified fact, and an unattainable precondition blocks execution
without ever becoming a negative security verdict.
"""

from webpent.egaie.prerequisites import (
    Precondition,
    PreconditionKind,
    PreconditionStatus,
    PrerequisiteLedger,
    UnattainableEffect,
)


def _ledger_with(hyp: str, *preconds: Precondition) -> PrerequisiteLedger:
    ledger = PrerequisiteLedger()
    ledger.declare(hyp, preconds)
    return ledger


def test_observed_precondition_requires_basis() -> None:
    import pytest
    with pytest.raises(ValueError):
        Precondition(
            kind=PreconditionKind.APP_STATE,
            target="order:open",
            status=PreconditionStatus.OBSERVED)


def test_inferred_is_not_verified_until_backed_by_observation() -> None:
    ledger = _ledger_with(
        "h-1",
        Precondition(kind=PreconditionKind.WORKFLOW_TRANSITION,
                     target="transition:submit"),
    )
    assert not ledger.get("h-1")[0].verified
    assert ledger.unverified("h-1")

    ledger.verify("h-1", "transition:submit", "obs-77")
    precondition = ledger.get("h-1")[0]
    assert precondition.status is PreconditionStatus.OBSERVED
    assert precondition.basis == "obs-77"
    assert not ledger.unverified("h-1")


def test_verify_requires_a_declared_target() -> None:
    import pytest
    ledger = _ledger_with(
        "h-1",
        Precondition(kind=PreconditionKind.IDENTITY,
                     target="actor:owner"),
    )
    with pytest.raises(KeyError):
        ledger.verify("h-1", "transition:submit", "obs-77")


def test_unattainable_blocks_execution_never_a_verdict() -> None:
    ledger = _ledger_with(
        "h-1",
        Precondition(kind=PreconditionKind.WORKFLOW_TRANSITION,
                     target="transition:approve",
                     establish_via="authorized transition as owner"),
    )
    ledger.mark_unattainable("h-1", "transition:approve",
                             via="transition forbidden to investigator")
    blockers = ledger.execution_blockers("h-1")
    assert blockers, "unattainable precondition must block execution"
    assert blockers[0].verdict_effect is UnattainableEffect.NEVER_A_VERDICT


def test_establishable_then_verified_status_chain() -> None:
    ledger = _ledger_with(
        "h-1",
        Precondition(kind=PreconditionKind.APP_STATE,
                     target="ticket:source-state"),
    )
    ledger.mark_establishable("h-1", "ticket:source-state",
                              via="owner submits")
    assert ledger.get("h-1")[0].status is (
        PreconditionStatus.ESTABLISHABLE)
    ledger.verify("h-1", "ticket:source-state", "obs-9")
    assert ledger.get("h-1")[0].verified


def test_tally_counts_by_status() -> None:
    ledger = _ledger_with(
        "h-1",
        Precondition(kind=PreconditionKind.IDENTITY,
                     target="actor:owner"),
        Precondition(kind=PreconditionKind.PRIOR_OBSERVATION,
                     target="obs:denied-read", basis="obs-3",
                     status=PreconditionStatus.OBSERVED),
    )
    ledger.declare(
        "h-2",
        (Precondition(kind=PreconditionKind.BUDGET,
                      target="budget:>=2"),))
    tally = ledger.tally()
    assert tally == {
        "observed": 1, "inferred": 2, "establishable": 0,
        "unattainable": 0}


def test_declare_merges_by_target() -> None:
    ledger = _ledger_with(
        "h-1",
        Precondition(kind=PreconditionKind.APP_STATE,
                     target="ticket:source-state"))
    ledger.declare(
        "h-1",
        (Precondition(kind=PreconditionKind.APP_STATE,
                      target="ticket:source-state",
                      establish_via="owner submits"),))
    assert len(ledger.get("h-1")) == 1
    assert ledger.get("h-1")[0].establish_via == "owner submits"
