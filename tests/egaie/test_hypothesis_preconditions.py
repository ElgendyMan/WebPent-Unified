"""L9 §2 Phase 1 — hypotheses carry structured preconditions.

Red-first rule under test: an inferred precondition is never a
verified fact. Generation attaches preconditions from the same wire
view the probes use; only PrerequisiteLedger.verify — backed by a
recorded observation id — may move one to OBSERVED, and until then
the verdict gate is 'unverified', which precludes confirmation
without ever becoming a negative security verdict.
"""

from webpent.egaie.differential import (
    DifferentialGenerator,
    FAMILY_WORKFLOW_IDENTITY,
    RelationshipView,
)
from webpent.egaie.prerequisites import (
    PreconditionKind,
    PreconditionStatus,
    PrerequisiteLedger,
)


def _workflow_view() -> RelationshipView:
    return RelationshipView(
        accounts=("owner-1", "ext-1"),
        workflow_paths=("workflows/wf-1", "workflows/wf-2"),
        workflow_owner={"workflows/wf-1": "owner-1",
                        "workflows/wf-2": "ext-1"},
        workflow_state={"workflows/wf-1": "draft",
                        "workflows/wf-2": "draft"},
        workflow_chains={
            "workflows/wf-1": ("draft", "submitted", "approved"),
            "workflows/wf-2": ("draft", "submitted", "approved")},
        workflow_action_targets={
            "workflows/wf-1": {"submit": "submitted",
                               "approve": "approved"},
            "workflows/wf-2": {"submit": "submitted",
                               "approve": "approved"}},
        identity_of={"cred-1": "ext-1"},
    )


def _identity_hypotheses(view: RelationshipView):
    hypotheses = DifferentialGenerator().generate(view)
    identity = [
        h for h in hypotheses
        if h.family == FAMILY_WORKFLOW_IDENTITY]
    assert identity, "workflow surface must yield identity hypotheses"
    return identity


def test_workflow_identity_declares_structured_preconditions() -> None:
    hyp = _identity_hypotheses(_workflow_view())[0]
    kinds = {p.kind for p in hyp.prerequisites}
    assert PreconditionKind.IDENTITY in kinds
    assert PreconditionKind.OWNERSHIP in kinds
    transitions = [
        p for p in hyp.prerequisites
        if p.kind is PreconditionKind.WORKFLOW_TRANSITION]
    assert transitions
    # ESTABLISHABLE, because the surface's own chain shows a way to
    # reach the required source state; never OBSERVED at generation.
    assert transitions[0].status is PreconditionStatus.ESTABLISHABLE
    assert all(
        p.status is not PreconditionStatus.OBSERVED
        for p in hyp.prerequisites)


def test_transition_inferred_without_state_description() -> None:
    """Without the surface's own chain, the source state cannot be
    claimed establishable: it stays INFERRED."""
    view = _workflow_view()
    view.workflow_chains = {}
    hyp = _identity_hypotheses(view)[0]
    transitions = [
        p for p in hyp.prerequisites
        if p.kind is PreconditionKind.WORKFLOW_TRANSITION]
    assert transitions
    assert transitions[0].status is PreconditionStatus.INFERRED


def test_generated_preconditions_start_unverified() -> None:
    hypotheses = DifferentialGenerator().generate(_workflow_view())
    ledger = PrerequisiteLedger.from_hypotheses(hypotheses)
    for hyp in hypotheses:
        if not hyp.prerequisites:
            assert ledger.verdict_gate(hyp.hypothesis_id) == "clear"
            continue
        assert ledger.unverified(hyp.hypothesis_id) == (
            hyp.prerequisites)
        assert ledger.verdict_gate(hyp.hypothesis_id) == "unverified"


def test_unverified_gates_confirmation_unattainable_never_negative(
) -> None:
    hyp = _identity_hypotheses(_workflow_view())[0]
    ledger = PrerequisiteLedger.from_hypotheses([hyp])
    target = next(
        p.target for p in hyp.prerequisites
        if p.kind is PreconditionKind.WORKFLOW_TRANSITION)
    # Inferred is not verified: the gate holds confirmation open for
    # evidence, not a finding and not a secure negative.
    assert ledger.verdict_gate(hyp.hypothesis_id) == "unverified"
    for precond in hyp.prerequisites:
        ledger.verify(hyp.hypothesis_id, precond.target, "obs-1")
    assert ledger.verdict_gate(hyp.hypothesis_id) == "clear"
    # Unattainable blocks execution and never yields a verdict.
    ledger.mark_unattainable(
        hyp.hypothesis_id, target, via="forbidden to investigator")
    assert ledger.verdict_gate(hyp.hypothesis_id) == "blocked"
