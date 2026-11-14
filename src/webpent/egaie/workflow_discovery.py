"""L10 Phase 4 — bounded novel workflow discovery.

Phase 3's setup derivation trusts the surface's PUBLISHED workflow
schema (chain and action table). This module covers what the
schema does not publish: an action whose source state the surface
never declared. It learns workflow transitions from OBSERVATIONS
ONLY, in two ways:

Passive mining. The ledger's own chronology is read with NO new
requests: an executed POST whose immediately preceding record on
the same path is a re-read showing state A and whose immediately
following re-read shows state B yields the observed edge (A,
action) -> B. Records that are not adjacent never yield an edge —
the states between them are unknown, so nothing is inferred across
a gap. A refused POST yields a refusal observation (a fact about
the gate), never an edge.

Active probing, bounded. When a derivation needs a transition the
model lacks, the orchestrator may spend an explicit budget of
discovery actions: a candidate (a POST action OBSERVED on the
path, with an OBSERVED actor, whose result from the current state
is unknown) is fired through the ordinary action path with its
verification re-read, costing what every setup hop costs. The same
(path, from-state, action) is probed at most once (duplicate
suppression), and the budget bounds the whole investigation's
discovery spend.

Evidence discipline. An edge enters the model only from an
accepted POST verified by its re-read; the edge carries the
re-read's observation id. An accepted POST whose re-read shows no
movement is an observed self-loop (a stall), excluded from chain
edges. Two observations of the same transition with different
results — or an edge that moves backward on the forward chain the
other observations established — QUARANTINE the transition: it is
removed, recorded as a contradiction, and never used for planning.
Quarantine is never a silent overwrite, and a contradiction never
produces a verdict either way: the affected hypothesis simply
stays unmet until new observations say otherwise.

Prioritization. Candidates are ranked by information gain per
equal cost: actions the surface has refused at the current state
last (the gate may open, but it is evidence-backed resistance),
everything else unknown-result first; actions with a known result
from the current state carry no information gain and are not
candidates at all. Ties break deterministically by action name.
Nothing invents a transition that was not observed to succeed:
with no ledger behind it, discovery proposes nothing.

These are synthetic loopback comparisons over fixture applications:
they support no real-world generalization claim.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from webpent.egaie.differential import (
    ObservationLedger,
    RelationshipView,
    SurfaceBindings,
)


@dataclass(frozen=True)
class DiscoveryCandidate:
    """One observed action proposed for a bounded discovery probe."""

    path: str
    action: str
    actor: str
    from_state: str
    request_cost: int = 2
    rationale: str = ""


@dataclass(frozen=True)
class Contradiction:
    """A transition the observations disagree about, quarantined."""

    path: str
    action: str
    from_state: str
    observed: tuple[str, ...]
    detail: str


@dataclass(frozen=True)
class TransitionObservation:
    """One OBSERVED transition, backed by its verification re-read."""

    path: str
    action: str
    from_state: str
    to_state: str
    observation_id: str
    actor: str


class WorkflowDiscovery:
    """Observation-only workflow transition discovery with an
    explicit action budget, duplicate suppression, contradiction
    quarantine, and resumable memory."""

    def __init__(self, max_discovery_actions: int = 4) -> None:
        self.max_discovery_actions = max_discovery_actions
        # path -> {(from_state, action): TransitionObservation};
        # a self-loop (to_state == from_state) is a stall, not a
        # chain edge.
        self.observations: dict[
            str, dict[tuple[str, str], TransitionObservation]] = {}
        # path -> {(from_state, action)} observed refusals (used
        # only for prioritization, never suppression).
        self.refusal_keys: dict[str, set[tuple[str, str]]] = {}
        # path -> {action: actor}: every POST action OBSERVED on
        # the path (any execution status), with the actor observed
        # issuing it. The candidate inventory.
        self.observed_actions: dict[str, dict[str, str]] = {}
        # (path, from_state, action) keys quarantined by a
        # contradicting observation.
        self.quarantined: set[tuple[str, str, str]] = set()
        self.contradictions: list[Contradiction] = []
        # every (path, from_state, action) ever probed: the
        # duplicate-suppression set.
        self.attempted: set[tuple[str, str, str]] = set()
        self.actions_spent = 0
        self._probe_counter = 0

    # -- passive mining ------------------------------------------------

    def mine(self, ledger: ObservationLedger,
             view: RelationshipView,
             bindings: SurfaceBindings) -> None:
        """Derive transitions from the ledger's chronology without
        spending any discovery actions."""
        for path in view.workflow_paths:
            records = [r for r in ledger.records if r.path == path]
            for record in records:
                if (record.method == "POST"
                        and record.execution == "executed"
                        and isinstance(record.params, dict)):
                    action = record.params.get(
                        bindings.action_param, "")
                    if action:
                        self.observed_actions.setdefault(
                            path, {})[action] = record.actor
            for prev, post, nxt in zip(records, records[1:],
                                       records[2:]):
                if not self._is_transition_post(post, bindings):
                    continue
                from_state = self._reread_state(prev, bindings)
                to_state = self._reread_state(nxt, bindings)
                if from_state is None or to_state is None:
                    continue
                action = (post.params or {}).get(
                    bindings.action_param, "")
                if not action:
                    continue
                if (post.status_code is not None
                        and 200 <= post.status_code < 300):
                    if from_state != to_state:
                        self._learn(
                            path, action, from_state, to_state,
                            post.record_id, post.actor)
                else:
                    self.refusal_keys.setdefault(
                        path, set()).add((from_state, action))

    @staticmethod
    def _is_transition_post(record: Any,
                            bindings: SurfaceBindings) -> bool:
        return (record.method == "POST"
                and record.execution == "executed"
                and isinstance(record.params, dict)
                and bindings.action_param in record.params)

    @staticmethod
    def _reread_state(record: Any,
                      bindings: SurfaceBindings) -> str | None:
        if record.execution != "executed":
            return None
        structured = record.structured
        if not isinstance(structured, dict):
            return None
        state = structured.get(bindings.state_field)
        return state if isinstance(state, str) else None

    # -- model ----------------------------------------------------------

    def _learn(self, path: str, action: str, from_state: str,
               to_state: str, observation_id: str,
               actor: str) -> str:
        """Record an observed transition. Returns 'learned' or
        'contradiction'."""
        key = (from_state, action)
        existing = self.observations.get(path, {}).get(key)
        if existing is not None and existing.to_state != to_state:
            return self._quarantine(
                path, action, from_state,
                (existing.to_state, to_state),
                "the same transition observed from the same state "
                "produced different results")
        chain = self.chain(path)
        if chain and from_state in chain and to_state in chain:
            if chain.index(to_state) < chain.index(from_state):
                return self._quarantine(
                    path, action, from_state,
                    (from_state, to_state),
                    "a transition that moves backward on the "
                    "forward chain the other observations "
                    "established")
        self.observations.setdefault(path, {})[key] = (
            TransitionObservation(
                path=path, action=action, from_state=from_state,
                to_state=to_state, observation_id=observation_id,
                actor=actor))
        return "learned"

    def _quarantine(self, path: str, action: str,
                    from_state: str, observed: tuple[str, ...],
                    detail: str) -> str:
        self.observations.get(path, {}).pop(
            (from_state, action), None)
        self.quarantined.add((path, from_state, action))
        if not any(
                c.path == path and c.action == action
                and c.from_state == from_state
                for c in self.contradictions):
            self.contradictions.append(Contradiction(
                path=path, action=action, from_state=from_state,
                observed=observed, detail=detail))
        return "contradiction"

    def transitions(self, path: str) -> dict[
            tuple[str, str], str]:
        """Observed (from_state, action) -> to_state on the path
        (stall self-loops included, quarantined keys excluded)."""
        return {
            key: obs.to_state
            for key, obs in self.observations.get(path, {}).items()
            if (path,) + key not in self.quarantined}

    def refusals(self, path: str) -> set[tuple[str, str]]:
        return set(self.refusal_keys.get(path, ()))

    def _planning_edges(self, path: str) -> dict[
            tuple[str, str], str]:
        return {
            key: obs.to_state
            for key, obs in self.observations.get(path, {}).items()
            if obs.to_state != obs.from_state
            and (path,) + key not in self.quarantined}

    def chain(self, path: str) -> tuple[str, ...] | None:
        """The forward chain as the topological order of the
        observed edges (stalls excluded), or None when no edges
        are known or they are not orderable."""
        edges = self._planning_edges(path)
        if not edges:
            return None
        nodes: set[str] = set()
        for (frm, _action), to in edges.items():
            nodes.add(frm)
            nodes.add(to)
        # Kahn topological sort. The observed model is
        # forward-only; a cycle among current edges cannot be
        # planned on, so the chain is declared unordered (None).
        order: list[str] = []
        indegree = {n: 0 for n in nodes}
        adjacency: dict[str, list[str]] = {n: [] for n in nodes}
        for (frm, _action), to in edges.items():
            adjacency[frm].append(to)
            indegree[to] += 1
        ready = sorted(n for n, d in indegree.items() if d == 0)
        while ready:
            node = ready.pop(0)
            order.append(node)
            for nxt in adjacency[node]:
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    ready.append(nxt)
                    ready.sort()
        if len(order) != len(nodes):
            return None
        return tuple(order)

    def reachable(self, path: str, frm: str,
                  to: str) -> bool | None:
        """Whether `to` is reachable from `frm` over observed edges:
        True, False, or None (unknown states — never a False
        negative)."""
        edges = self._planning_edges(path)
        nodes: set[str] = set()
        for (source, _action), dest in edges.items():
            nodes.add(source)
            nodes.add(dest)
        if frm not in nodes or to not in nodes:
            return None
        seen: set[str] = set()
        frontier = [frm]
        while frontier:
            node = frontier.pop()
            if node == to:
                return True
            if node in seen:
                continue
            seen.add(node)
            frontier.extend(
                dest for (source, _a), dest in edges.items()
                if source == node)
        return False

    # -- active probing ---------------------------------------------------

    def candidates(self, path: str, current_state: str,
                   view: RelationshipView) -> list[
            DiscoveryCandidate]:
        """Observed actions on the path whose result from the
        current state is unknown, ranked by information gain per
        equal cost. With no observations behind it, this proposes
        NOTHING: no invented transitions, ever."""
        inventory = self.observed_actions.get(path, {})
        if not inventory:
            return []
        known = self.transitions(path)
        refusals = self.refusal_keys.get(path, set())
        ranked: list[tuple[int, str, DiscoveryCandidate]] = []
        for action, actor in sorted(inventory.items()):
            if (current_state, action) in known:
                continue  # known result: no information gain
            refused_here = (current_state, action) in refusals
            ranked.append((
                1 if refused_here else 0, action,
                DiscoveryCandidate(
                    path=path, action=action, actor=actor,
                    from_state=current_state,
                    rationale=(
                        "the surface refused this action at the "
                        "current state; the gate may open from "
                        "another state"
                        if refused_here else
                        "an observed action whose result from the "
                        "current state is unknown"))))
        ranked.sort(key=lambda item: (item[0], item[1]))
        return [candidate for _rank, _action, candidate in ranked]

    def reserve(self, path: str, from_state: str, action: str,
                actor: str) -> str | None:
        """Claim one bounded discovery probe for the key. Returns a
        fresh action id, or None when the key was already probed
        (duplicate suppression) or the explicit budget is spent."""
        key = (path, from_state, action)
        if key in self.attempted:
            return None
        if self.actions_spent >= self.max_discovery_actions:
            return None
        self.attempted.add(key)
        self.actions_spent += 1
        self._probe_counter += 1
        return f"disc-{self._probe_counter:02d}"

    def record_result(self, path: str, action: str,
                      from_state: str, observed_state: str | None,
                      observation_id: str, accepted: bool,
                      actor: str) -> str:
        """Record one probe's outcome: 'learned' (an accepted POST
        whose re-read shows a state), 'stall' (accepted, re-read
        shows no movement), 'refused' (the surface said no — an
        observation of the gate, never an edge), or
        'contradiction'."""
        if not accepted:
            self.refusal_keys.setdefault(
                path, set()).add((from_state, action))
            return "refused"
        if observed_state is None:
            return "refused"
        if observed_state == from_state:
            self.observations.setdefault(path, {})[
                (from_state, action)] = TransitionObservation(
                    path=path, action=action,
                    from_state=from_state,
                    to_state=observed_state,
                    observation_id=observation_id, actor=actor)
            return "stall"
        return self._learn(
            path, action, from_state, observed_state,
            observation_id, actor)

    # -- resumable memory -------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_discovery_actions": self.max_discovery_actions,
            "observations": {
                path: {
                    f"{frm}\x00{action}": {
                        "path": obs.path, "action": obs.action,
                        "from_state": obs.from_state,
                        "to_state": obs.to_state,
                        "observation_id": obs.observation_id,
                        "actor": obs.actor}
                    for (frm, action), obs in table.items()}
                for path, table in self.observations.items()},
            "refusals": {
                path: sorted(
                    f"{frm}\x00{action}"
                    for frm, action in keys)
                for path, keys in self.refusal_keys.items()},
            "observed_actions": {
                path: dict(actions) for path, actions
                in self.observed_actions.items()},
            "quarantined": sorted(
                f"{p}\x00{f}\x00{a}"
                for p, f, a in self.quarantined),
            "contradictions": [
                {"path": c.path, "action": c.action,
                 "from_state": c.from_state,
                 "observed": list(c.observed),
                 "detail": c.detail}
                for c in self.contradictions],
            "attempted": sorted(
                f"{p}\x00{f}\x00{a}"
                for p, f, a in self.attempted),
            "actions_spent": self.actions_spent,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkflowDiscovery:
        discovery = cls(
            max_discovery_actions=data["max_discovery_actions"])
        for path, table in data["observations"].items():
            for key, obs in table.items():
                frm, action = key.split("\x00")
                discovery.observations.setdefault(path, {})[
                    (frm, action)] = TransitionObservation(**obs)
        for path, keys in data["refusals"].items():
            discovery.refusal_keys[path] = {
                tuple(k.split("\x00")) for k in keys}
        for path, actions in data["observed_actions"].items():
            discovery.observed_actions[path] = dict(actions)
        discovery.quarantined = {
            tuple(k.split("\x00"))
            for k in data["quarantined"]}
        discovery.contradictions = [
            Contradiction(**c) for c in data["contradictions"]]
        discovery.attempted = {
            tuple(k.split("\x00")) for k in data["attempted"]}
        discovery.actions_spent = data["actions_spent"]
        discovery._probe_counter = len(discovery.attempted)
        return discovery
