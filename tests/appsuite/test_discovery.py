"""L8 §2/§5: engine-over-appsuite discovery regression tests.

Red-first coverage for the failure the generation-2 DEV block exposed:
a surface whose hypothesis space contains no pristine-state family
(e.g. only IDENTITY_BOUNDARY or only PRICE_INTEGRITY) previously
stalled — the first propose() call returned the empty pristine band,
the orchestrator saw no pending experiments and no unresolved
hypotheses, and ended as objectives_complete before the deferred
(stage-2) band was ever emitted. The fix lets the proposer emit the
deferred band immediately when the pristine band is empty.

Runs against live loopback appsuite instances (same pattern as the L6
blind-discovery tests). The engine never imports the appsuite; these
tests do, from the outside.
"""
from __future__ import annotations

from webpent.egaie import discovery_runner as dr
from webpent.appsuite.corpus import SuiteEntry, open_instance

RECON_ORIGIN = "differential:recon:"


def _run(entry: SuiteEntry, strategy: str = "adaptive",
         budget: int = 16):
    with open_instance(entry) as target:
        port = dr._build_port(target, entry.seed)
        state = dr._seed_state(target, entry.instance_id)
        state = dr._build_orchestrator(port, strategy).run(
            state, max_rounds=budget)
    return state


def test_boundary_only_surface_reaches_stage_two() -> None:
    # docvault defective: IDENTITY_BOUNDARY hypotheses only (no
    # pristine family) — previously produced zero hypotheses.
    state = _run(SuiteEntry("docvault", "defective"))
    recon = [r for r in state.hypotheses
             if r.origin.startswith(RECON_ORIGIN)]
    assert recon, "boundary-only surface stalled before stage 2"
    assert any(r.family == "IDENTITY_BOUNDARY" for r in recon)


def test_price_only_surface_reaches_stage_two() -> None:
    # market defective: PRICE_INTEGRITY in the deferred band.
    state = _run(SuiteEntry("market", "defective"))
    recon = [r for r in state.hypotheses
             if r.origin.startswith(RECON_ORIGIN)]
    assert recon, "price-family surface stalled before stage 2"
    assert any(r.family == "PRICE_INTEGRITY" for r in recon)


def test_multi_observation_price_defect_confirmed() -> None:
    # L8 §5 failure evidence: the multi-observation variant honors a
    # client amount for ONE quote bucket only. Single-resource price
    # probing picked a bucket-1 quote, saw the authoritative charge,
    # and reported clean — the defect was never confirmed. The fix
    # probes each family across distinct resources (capped), so a
    # scoped defect is reached.
    state = _run(SuiteEntry("market", "multi_observation"),
                 budget=16)
    confirmed = [h for h in state.hypotheses
                 if h.status.value == "confirmed"
                 and h.family == "PRICE_INTEGRITY"]
    assert confirmed, (
        "scoped price defect never confirmed: probes covered only "
        "one resource")


def test_multi_observation_ownership_defect_confirmed() -> None:
    # Same failure shape on docvault: the write-bit defect is scoped
    # to ONE collection; the mutation probe's single resource sat in
    # the enforced collection, so the run concluded clean.
    state = _run(SuiteEntry("docvault", "multi_observation"),
                 budget=16)
    confirmed = [h for h in state.hypotheses
                 if h.status.value == "confirmed"
                 and h.family == "IDENTITY_BOUNDARY"]
    assert confirmed, (
        "scoped ownership defect never confirmed: probes covered "
        "only one resource")


def test_requisitions_defective_workflow_identity_confirmed() -> None:
    # L9 §4 red-first (requisitions, the new dev case): a two-owner
    # surface offers NO third-party control, so every workflow-identity
    # control is the candidate's OWN workflow. Earlier probes consume
    # a control workflow's pristine source state, and on a
    # forward-only machine that state is unattainable, so the later
    # candidate legs that DO apply cross-owner run against a control
    # refused by the state machine (409 naming the state field). The
    # judge must score that differential on the directly evidenced
    # cross-owner transition (applied flag, owner attribution, and the
    # post-submission re-read), not park it inconclusive, which left
    # the scoped defect a false negative.
    state = _run(SuiteEntry("requisitions", "defective"))
    confirmed = [h for h in state.hypotheses
                 if h.status.value == "confirmed"
                 and h.family == "WORKFLOW_IDENTITY"]
    assert confirmed, (
        "scoped requisitions identity defect never confirmed: the "
        "own-control state refusal parked every differential")


def test_requisitions_secured_and_ambiguous_stay_unflagged() -> None:
    # secured: the sponsor check is enforced everywhere, so nothing
    # confirms. ambiguous: the shared intake pool is DOCUMENTED open,
    # so the accepted cross-owner submissions there must resolve clean
    # through the documented-open scan, never a finding.
    for variant in ("secured", "ambiguous"):
        state = _run(SuiteEntry("requisitions", variant))
        flagged = [h.hypothesis_id for h in state.hypotheses
                   if h.status.value == "confirmed"]
        assert not flagged, (variant, flagged)


def test_requisitions_multi_observation_confirms_scoped_defect() -> None:
    state = _run(SuiteEntry("requisitions", "multi_observation"))
    confirmed = [h for h in state.hypotheses
                 if h.status.value == "confirmed"
                 and h.family == "WORKFLOW_IDENTITY"]
    assert confirmed, "scoped multi-observation defect never confirmed"


# -- L9 §5: the stateful held-out block (ledgerflow, berth) ------
#
# These two apps put the exploitable state BEHIND a prerequisite
# transition: the identity check is skipped only for a transition
# whose source state is the chain's second stage, so the defect
# cannot manifest until the resource's owner has moved the machine
# forward. Without the L9 planner (prerequisite reasoning and
# authorized setup), the candidate leg is state-refused on the
# first pass and the defect stays a false negative (red-first
# baseline asserted in the dedicated L9 matrix script). These tests
# pin the remediated behavior: confirm the defect, never flag the
# secured and documented-clean lookalikes, and never turn a failed
# setup into a negative verdict.

from webpent.egaie.benchmark.strategies import (
    build_strategy_orchestrator,
)
from webpent.egaie.prerequisites import (
    PreconditionStatus,
    UnattainableEffect,
)


def _run_planned(entry: SuiteEntry, budget: int = 16):
    """Run the L9 adaptive investigation (planner wired)."""
    with open_instance(entry) as target:
        port = dr._build_port(target, entry.seed)
        state = dr._seed_state(target, entry.instance_id)
        orch = build_strategy_orchestrator(port, "adaptive")
        state = orch.run(state, max_rounds=budget)
    return state, orch


def _confirmed_families(state):
    return [h for h in state.hypotheses
            if h.status.value == "confirmed"]


def test_ledgerflow_defective_confirms_behind_prerequisite() -> None:
    # ledgerflow defective: the countersign approver check is
    # skipped on ONE ledger, and countersign's source state is the
    # chain's second stage. The candidate leg is state-refused
    # until the planner establishes the approver's initiate as a
    # declared workflow-transition precondition and re-runs the
    # experiment with its own idempotency tokens.
    state, _ = _run_planned(SuiteEntry("ledgerflow", "defective"))
    confirmed = [h for h in _confirmed_families(state)
                 if h.family == "WORKFLOW_IDENTITY"]
    assert confirmed, (
        "ledgerflow identity defect never confirmed: the planner "
        "did not establish the initiate prerequisite before the "
        "re-run")


def test_ledgerflow_secured_stays_unflagged() -> None:
    state, _ = _run_planned(SuiteEntry("ledgerflow", "secured"))
    assert not _confirmed_families(state), (
        "secured ledgerflow flagged")


def test_berth_defective_confirms_behind_prerequisite() -> None:
    # berth defective: the confirm holder check is skipped on ONE
    # berth, and confirm's source window is the second stage of a
    # timestamped window machine — the state is DERIVED from the
    # windows, so the prerequisite here is the holder's hold
    # transition rewriting the next window to start at the clock.
    state, _ = _run_planned(SuiteEntry("berth", "defective"))
    confirmed = [h for h in _confirmed_families(state)
                 if h.family == "WORKFLOW_IDENTITY"]
    assert confirmed, (
        "berth identity defect never confirmed: the planner did "
        "not establish the hold prerequisite before the re-run")


def test_berth_clean_variants_stay_unflagged() -> None:
    # secured and negative_control: the holder check holds
    # everywhere. transition_no_vuln: confirm is open to every
    # identity on every berth and DOCUMENTS it on the wire, so the
    # accepted cross-identity submissions resolve clean through the
    # documented-open scan — a confirmation there is a false
    # positive.
    for variant in ("secured", "transition_no_vuln",
                    "negative_control"):
        state, _ = _run_planned(SuiteEntry("berth", variant))
        flagged = [h.hypothesis_id
                   for h in _confirmed_families(state)]
        assert not flagged, (variant, flagged)


def test_berth_unavailable_prereq_records_failure_never_verdict() -> None:
    # unavailable_prereq: the confirm check is skipped but its
    # prerequisite hold legitimately requires the harbormaster
    # role, which no probe identity holds. L9 §3: the failed setup
    # is recorded and must never become a negative security
    # verdict — the investigation ends inconclusive (proposed or
    # blocked hypotheses only), with the unattainable precondition
    # carrying NEVER_A_VERDICT in the ledger.
    state, orch = _run_planned(SuiteEntry("berth",
                                          "unavailable_prereq"))
    flagged = [h.hypothesis_id for h in _confirmed_families(state)]
    assert not flagged, (
        "unavailable-prerequisite setup failure became a verdict")
    statuses = {h.status.value for h in state.hypotheses}
    assert "confirmed" not in statuses
    assert "falsified" not in statuses or not any(
        h.family == "WORKFLOW_IDENTITY"
        and h.status.value == "falsified"
        for h in state.hypotheses)
    recorded = [
        p for preconds
        in orch.planner.ledger.entries.values()
        for p in preconds
        if p.status is PreconditionStatus.UNATTAINABLE]
    assert recorded, (
        "the unattainable harbormaster prerequisite was never "
        "recorded as blocked")
    assert all(
        p.verdict_effect is UnattainableEffect.NEVER_A_VERDICT
        for p in recorded), (
        "an unattainable precondition must never carry a verdict "
        "effect")
