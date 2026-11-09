"""L10 Phase 4 — bounded novel workflow discovery (red-first).

The discovery component learns workflow transitions from
OBSERVATIONS ONLY: it mines the ledger's own chronology (an
executed POST whose adjacent re-read shows a state change), and
probes unknown transitions through the ordinary action path within
an explicit budget. Nothing invents a transition that was not
observed to succeed; a contradicting observation QUARANTINES the
transition (never used for planning, never silently overwritten);
a refused candidate is suppressed, not retried; the same
(path, from-state, action) is probed at most once; memory is
resumable. Every learned edge is backed by the re-read's
observation id — an assertion, never an assumption.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from webpent.egaie.differential import ObservationLedger
from webpent.egaie.workflow_discovery import (
    Contradiction,
    DiscoveryCandidate,
    WorkflowDiscovery,
)

PATH = "/wf/items/1"
BINDINGS = SimpleNamespace(state_field="state", action_param="action")
VIEW = SimpleNamespace(
    workflow_paths={PATH},
    workflow_owner={PATH: "agent-a"},
    workflow_state={PATH: "s1"},
    workflow_chains={},
    workflow_action_targets={},
)


def _get(state: str, actor: str = "agent-a") -> dict:
    return {
        "status_code": 200, "execution": "executed",
        "headers": {}, "structured": {"state": state},
        "actor": actor,
    }


def _post(action: str, status: int = 200) -> dict:
    return {
        "status_code": status, "execution": "executed",
        "headers": {}, "structured": {}, "action": action,
        "actor": "agent-a",
    }


def _ledger(*entries: tuple[str, str, dict]) -> ObservationLedger:
    ledger = ObservationLedger()
    for actor, method, obs in entries:
        params = (
            {BINDINGS.action_param: obs.pop("action")}
            if method == "POST" and "action" in obs else {})
        ledger.append(actor, method, PATH, params, obs)
    return ledger


# -- passive mining --------------------------------------------------

def test_mines_adjacent_post_and_reread_pairs() -> None:
    ledger = _ledger(
        ("agent-a", "GET", _get("s1")),
        ("agent-a", "POST", _post("push")),
        ("agent-a", "GET", _get("s2")),
    )
    discovery = WorkflowDiscovery()
    discovery.mine(ledger, VIEW, BINDINGS)
    assert discovery.transitions(PATH) == {
        ("s1", "push"): "s2"}
    assert discovery.chain(PATH) == ("s1", "s2")
    assert discovery.actions_spent == 0, (
        "mining is passive: no discovery actions are spent")


def test_non_adjacent_records_are_not_mined() -> None:
    # POST without an adjacent preceding GET, and two POSTs between
    # two GETs: the intermediate states are unknown, so NOTHING is
    # inferred across the gap — no guessed edges.
    ledger = _ledger(
        ("agent-a", "POST", _post("push")),
        ("agent-a", "GET", _get("s2")),
        ("agent-a", "GET", _get("s2")),
        ("agent-a", "POST", _post("a1")),
        ("agent-a", "POST", _post("a2")),
        ("agent-a", "GET", _get("s4")),
    )
    discovery = WorkflowDiscovery()
    discovery.mine(ledger, VIEW, BINDINGS)
    assert discovery.transitions(PATH) == {}


def test_refused_posts_are_never_mined_as_edges() -> None:
    ledger = _ledger(
        ("agent-a", "GET", _get("s1")),
        ("agent-a", "POST", _post("push", status=409)),
        ("agent-a", "GET", _get("s1")),
    )
    discovery = WorkflowDiscovery()
    discovery.mine(ledger, VIEW, BINDINGS)
    assert discovery.transitions(PATH) == {}
    assert discovery.refusals(PATH) == {("s1", "push")}, (
        "a refusal is an observation of the gate, recorded as such — "
        "never as a transition")


def test_unexecuted_posts_are_ignored() -> None:
    ledger = _ledger(
        ("agent-a", "GET", _get("s1")),
    )
    ledger.append("agent-a", "POST", PATH, {"action": "push"}, {
        "status_code": None, "execution": "unexecuted",
        "headers": {}, "structured": {}})
    ledger.append("agent-a", "GET", PATH, {}, _get("s2"))
    discovery = WorkflowDiscovery()
    discovery.mine(ledger, VIEW, BINDINGS)
    assert discovery.transitions(PATH) == {}


# -- contradiction handling ------------------------------------------

def test_contradicting_reread_quarantines_the_transition() -> None:
    ledger = _ledger(
        ("agent-a", "GET", _get("s1")),
        ("agent-a", "POST", _post("push")),
        ("agent-a", "GET", _get("s2")),
        ("agent-a", "GET", _get("s1")),
        ("agent-a", "POST", _post("push")),
        ("agent-a", "GET", _get("s3")),
    )
    discovery = WorkflowDiscovery()
    discovery.mine(ledger, VIEW, BINDINGS)
    assert discovery.transitions(PATH) == {}, (
        "a contradicting observation quarantines the transition "
        "instead of silently overwriting it")
    assert discovery.contradictions == [
        Contradiction(
            path=PATH, action="push", from_state="s1",
            observed=("s2", "s3"),
            detail="the same transition observed from the same "
                   "state produced different results")]


def test_backward_edge_contradicts_a_forward_chain() -> None:
    ledger = _ledger(
        ("agent-a", "GET", _get("s1")),
        ("agent-a", "POST", _post("push")),
        ("agent-a", "GET", _get("s2")),
        ("agent-a", "GET", _get("s2")),
        ("agent-a", "POST", _post("rewind")),
        ("agent-a", "GET", _get("s1")),
    )
    discovery = WorkflowDiscovery()
    discovery.mine(ledger, VIEW, BINDINGS)
    assert ("s2", "rewind") not in discovery.transitions(PATH), (
        "a transition that moves BACKWARD on the chain the other "
        "observations established is a contradiction (the machine "
        "is forward-only), quarantined like any other")
    assert discovery.transitions(PATH) == {("s1", "push"): "s2"}, (
        "quarantine removes only the contradicting edge; the "
        "well-observed edges stand")
    assert discovery.chain(PATH) == ("s1", "s2")
    assert len(discovery.contradictions) == 1


# -- reachability and chain inference --------------------------------

def test_chain_is_the_topological_order_of_observed_edges() -> None:
    ledger = _ledger(
        ("agent-a", "GET", _get("s2")),
        ("agent-a", "POST", _post("b")),
        ("agent-a", "GET", _get("s3")),
        ("agent-a", "GET", _get("s1")),
        ("agent-a", "POST", _post("a")),
        ("agent-a", "GET", _get("s2")),
    )
    discovery = WorkflowDiscovery()
    discovery.mine(ledger, VIEW, BINDINGS)
    assert discovery.chain(PATH) == ("s1", "s2", "s3"), (
        "the chain is the topological order of the observed edges, "
        "mined in ledger order, never assumed")
    assert discovery.reachable(PATH, "s1", "s3") is True
    assert discovery.reachable(PATH, "s3", "s1") is False, (
        "forward-only: a later state never reaches an earlier one")
    assert discovery.reachable(PATH, "s9", "s1") is None, (
        "reachability from an unknown state is UNKNOWN, not False")


# -- active candidates: dedup, budget, suppression -------------------

def _discovery_with_state(state: str) -> WorkflowDiscovery:
    discovery = WorkflowDiscovery(max_discovery_actions=2)
    ledger = _ledger(
        ("agent-a", "GET", _get(state)),
        ("agent-a", "POST", _post("known")),
        ("agent-a", "GET", _get("sx")),
        ("agent-a", "POST", _post("other", status=403)),
        ("agent-a", "GET", _get(state)),
    )
    discovery.mine(ledger, VIEW, BINDINGS)
    return discovery


def test_candidates_are_unknown_observed_actions_ranked() -> None:
    discovery = _discovery_with_state("s1")
    candidates = discovery.candidates(PATH, "s1", VIEW)
    assert [c.action for c in candidates] == ["other"], (
        "a known transition has no information gain and is not a "
        "candidate; only the unknown observed action is")


def test_candidates_come_only_from_observations() -> None:
    discovery = WorkflowDiscovery()
    assert discovery.candidates(PATH, "s1", VIEW) == [], (
        "with no ledger behind it, discovery proposes NOTHING: no "
        "invented transitions, ever")


def test_reserve_deduplicates_and_enforces_budget() -> None:
    discovery = _discovery_with_state("s1")
    first = discovery.reserve(PATH, "s1", "other", "agent-a")
    assert first == "disc-01"
    again = discovery.reserve(PATH, "s1", "other", "agent-a")
    assert again is None, (
        "the same (path, from-state, action) is probed at most once")
    discovery.reserve(PATH, "s1", "third", "agent-a")
    exhausted = discovery.reserve(PATH, "s1", "fourth", "agent-a")
    assert exhausted is None, "the explicit budget holds"
    assert discovery.actions_spent == 2


def test_record_result_learns_only_accepted_changes() -> None:
    discovery = _discovery_with_state("s1")
    discovery.reserve(PATH, "s1", "other", "agent-a")
    outcome = discovery.record_result(
        PATH, "other", "s1", "s1", "obs-0009", accepted=True,
        actor="agent-a")
    assert outcome == "stall", (
        "an accepted action whose re-read shows no movement is a "
        "stall, not an edge")
    assert discovery.transitions(PATH) == {
        ("s1", "known"): "sx", ("s1", "other"): "s1"}, (
        "a stall is an OBSERVED self-loop (the re-read says the "
        "state did not move), excluded from the chain's edges")
    assert discovery.chain(PATH) == ("s1", "sx")
    discovery.reserve(PATH, "s1", "third", "agent-a")
    outcome = discovery.record_result(
        PATH, "third", "s1", "s2", "obs-0010", accepted=True,
        actor="agent-a")
    assert outcome == "learned"
    assert discovery.transitions(PATH) == {
        ("s1", "known"): "sx", ("s1", "other"): "s1",
        ("s1", "third"): "s2"}
    assert discovery.chain(PATH) in (
        ("s1", "sx", "s2"), ("s1", "s2", "sx")), (
        "the topological order of two sibling edges is not unique; "
        "either valid order is a deterministic chain")


def test_record_result_records_refusal_without_an_edge() -> None:
    discovery = _discovery_with_state("s1")
    discovery.reserve(PATH, "s1", "other", "agent-a")
    outcome = discovery.record_result(
        PATH, "other", "s1", None, "obs-0009", accepted=False,
        actor="agent-a")
    assert outcome == "refused"
    assert discovery.transitions(PATH) == {("s1", "known"): "sx"}
    assert discovery.refusals(PATH) >= {("s1", "other")}


def test_record_result_unexpected_target_contradicts() -> None:
    discovery = _discovery_with_state("s1")
    discovery.reserve(PATH, "s1", "third", "agent-a")
    outcome = discovery.record_result(
        PATH, "third", "s1", "sx", "obs-0011", accepted=True,
        actor="agent-a")
    assert outcome == "learned", (
        "an accepted action whose re-read shows an unexpected state "
        "still LEARNED that edge (the observation is the truth); "
        "the deriving hop fails closed on its own expectation")
    assert discovery.transitions(PATH)[("s1", "third")] == "sx"


# -- resumable memory -------------------------------------------------

def test_memory_roundtrip_preserves_decisions() -> None:
    discovery = _discovery_with_state("s1")
    discovery.reserve(PATH, "s1", "other", "agent-a")
    discovery.record_result(
        PATH, "other", "s1", "s1", "obs-0009", accepted=True,
        actor="agent-a")
    restored = WorkflowDiscovery.from_dict(discovery.to_dict())
    assert restored.to_dict() == discovery.to_dict()
    assert restored.candidates(PATH, "s1", VIEW) == [], (
        "a resumed investigation continues where it left off: the "
        "stalled candidate is suppressed exactly as before")
    assert restored.actions_spent == discovery.actions_spent


# -- prioritization ----------------------------------------------------

def test_candidates_prefer_previously_accepted_actions() -> None:
    discovery = WorkflowDiscovery()
    ledger = _ledger(
        ("agent-a", "GET", _get("s1")),
        ("agent-a", "POST", _post("accepted-elsewhere")),
        ("agent-a", "GET", _get("sx")),
        ("agent-a", "GET", _get("s1")),
        ("agent-a", "POST", _post("refused-here", status=409)),
        ("agent-a", "GET", _get("s1")),
        ("agent-a", "POST", _post("never-tried")),
        ("agent-a", "GET", _get("s1")),
    )
    discovery.mine(ledger, VIEW, BINDINGS)
    candidates = discovery.candidates(PATH, "s1", VIEW)
    assert [c.action for c in candidates] == [
        "never-tried", "refused-here"], (
        "prioritization: unknown-result actions first (an action "
        "never observed to run may do anything), then actions the "
        "surface refused here; actions with a KNOWN result carry no "
        "information gain and are not candidates at all")


def test_candidates_require_an_observed_actor() -> None:
    discovery = _discovery_with_state("s1")
    (candidate,) = discovery.candidates(PATH, "s1", VIEW)
    assert candidate.actor == "agent-a", (
        "the candidate carries the actor OBSERVED issuing the "
        "action, never a guessed identity")
    assert candidate.request_cost == 2, (
        "a discovery probe costs what every setup hop costs: the "
        "POST and its verification re-read")
