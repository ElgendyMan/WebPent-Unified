"""UM-DR-52 W1 — the Behavioral & Business-Logic Reasoning layer.

future plan.md §3, layered on the live v0.49.0 system as a projection
over the SKG (the same ApplicationModel the brain already builds) —
never a parallel source of truth:

* **A1 — State Transition Discovery**: the state machine (states,
  transitions, preconditions, resource state before/after) is
  EXTRACTED from observed evidence, and the five live-security-model
  questions are answered BY MEASUREMENT with evidence refs — every
  unobserved fact is answered "unknown (not observed)", never
  invented.
* **A2 — InvariantHypothesis mining**: every spec carries its reason
  for belief, its preconditions and its discriminating experiment; a
  premise the model cannot support means NO spec (fail-open
  forbidden). Specs are projected onto the canonical pool through the
  legal hypothesis_adapter path — they are hypotheses like any other,
  subject to the strategist, CausalGuard and ProofBundle.
* **A3 — Behavioral Hypothesis Synthesis**: the brain-gated ranking
  consumes behavioral evidence (transition density → expected
  information gain, contradiction backing → confidence,
  invariant-backed write surface → impact) so the OFF/ON delta
  appears in ORDER and in OUTCOMES — a pool-only delta is a FAILURE
  verdict by law (window §6 G5).

Authority isolation (§0.1/§0.6, tested): this module performs no
I/O, grants nothing, confirms nothing, constructs no Finding, and
never touches CausalGuard/ProofBundle/Replay. Inference is labelled
inference and never evidence — every answer/spec names its basis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from uuid import NAMESPACE_URL, uuid5

logger = logging.getLogger(__name__)

__all__ = [
    "StateMachineSpec",
    "TransitionRecord",
    "MeasuredAnswer",
    "InvariantSpec",
    "BehavioralRankingEvidence",
    "extract_state_machine",
    "answer_five_questions",
    "mine_invariant_hypotheses",
    "invariant_hypotheses",
    "behavioral_ranking_evidence",
]

# Bounded everywhere, like every SKG consumer (skg.py caps: 64
# workflows / 256 transitions; we never exceed the builder's caps).
_MAX_MACHINES = 32
_MAX_TRANSITIONS_PER_MACHINE = 64
_MAX_INVARIANT_SPECS = 24
_MAX_REFS = 12
_MAX_ANSWERS = 160  # 5 questions × 32 machines, hard ceiling

# behavioral term weights (declared constants, regression-tested —
# not tuned magic numbers: each is the smallest lift that flips a
# boundary case in the approved fixture while remaining a no-op when
# the evidence is absent). PUBLIC — brain_engine imports them so the
# formula's behavioral terms and the evidence builder share one SSOT.
DENSITY_EIG_WEIGHT = 0.3         # eig += (1-eig) × weight × density
CONTRADICTION_CONFIDENCE = 0.25  # confidence += per contradiction kind
CONTRADICTION_CAP = 0.5
INVARIANT_IMPACT = 0.1           # impact += weight when invariant-backed


# ---------------------------------------------------------------------------
# A1 — the extracted state machine
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TransitionRecord:
    """One observed workflow transition, exactly as the SKG stores it."""

    workflow_key: str
    transition_key: str
    endpoint: str
    method: str
    from_state: str
    to_state: str
    authorization_boundary: str   # "" / "unknown" when not observed
    destructive: bool
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class StateMachineSpec:
    """The measured state machine of one workflow.

    ``entry_states`` = states with no observed inbound transition —
    a MEASURED derivation, not a declared guess (a cycle or a
    fragment yields an empty/ambiguous entry set and the answers say
    so instead of inventing one).
    """

    workflow_key: str
    states: tuple[str, ...]
    transitions: tuple[TransitionRecord, ...]
    entry_states: tuple[str, ...]
    measured: bool                 # True when ≥1 transition was observed


def _transition_sort_key(t: TransitionRecord) -> tuple[str, str, str]:
    return (t.from_state, t.to_state, t.transition_key or t.endpoint)


def extract_state_machine(model: Any) -> list[StateMachineSpec]:
    """Extract per-workflow state machines from the SKG, deterministically.

    Source of truth: the TRANSITIONS relations and STATE entities the
    builder wrote from ``workflow_observations`` (skg.py §5) — the
    same records ``workflow_skip_candidates`` reads. Nothing is
    inferred here that the graph does not carry.
    """
    states_by_wf: dict[str, set[str]] = {}
    for entity in model.entities.values():
        if str(entity.kind) != "state":
            continue
        meta = entity.metadata or {}
        wf = str(meta.get("workflow_key") or "").strip()
        st = str(meta.get("state") or entity.label or "").strip()
        if wf and st:
            states_by_wf.setdefault(wf, set()).add(st)

    transitions_by_wf: dict[str, list[TransitionRecord]] = {}
    for relation in model.relations:
        if str(relation.kind) != "transitions":
            continue
        meta = relation.metadata or {}
        wf = str(meta.get("workflow_key") or "").strip()
        if not wf:
            continue
        source = model.entities.get(relation.source_id)
        target = model.entities.get(relation.target_id)
        from_state = str((source.metadata or {}).get("state") or "") if source else ""
        to_state = str((target.metadata or {}).get("state") or "") if target else ""
        if not (from_state and to_state):
            continue
        try:
            refs = tuple(str(r) for r in (relation.ref_list() or []))
        except Exception:  # noqa: BLE001 — defensive ref read
            refs = ()
        transitions_by_wf.setdefault(wf, []).append(TransitionRecord(
            workflow_key=wf,
            transition_key=str(meta.get("transition_key") or ""),
            endpoint=str(meta.get("endpoint") or ""),
            method=str(meta.get("method") or ""),
            from_state=from_state,
            to_state=to_state,
            authorization_boundary=(
                str(meta.get("authorization_boundary") or "unknown").strip()
                or "unknown"
            ),
            destructive=bool(meta.get("destructive")),
            evidence_refs=refs[:_MAX_REFS],
        ))

    machines: list[StateMachineSpec] = []
    for wf in sorted(set(states_by_wf) | set(transitions_by_wf))[:_MAX_MACHINES]:
        transitions = sorted(
            transitions_by_wf.get(wf, [])[:_MAX_TRANSITIONS_PER_MACHINE],
            key=_transition_sort_key,
        )
        states = tuple(sorted(states_by_wf.get(wf, set())))
        inbound = {t.to_state for t in transitions}
        entry = tuple(s for s in states if s not in inbound)
        machines.append(StateMachineSpec(
            workflow_key=wf,
            states=states,
            transitions=tuple(transitions),
            entry_states=entry,
            measured=bool(transitions),
        ))
    return machines


# ---------------------------------------------------------------------------
# A1 — the five live-security-model questions, answered by measurement
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MeasuredAnswer:
    """One measured answer: the answer, its basis, its evidence refs.

    ``measured=False`` means the model cannot answer the question —
    the answer says "unknown (not observed)" instead of a guess.
    """

    question_id: str
    question: str
    answer: str
    basis: str
    evidence_refs: tuple[str, ...]
    measured: bool


def _endpoint_roles(model: Any) -> dict[str, set[str]]:
    """endpoint entity id → role labels granted via PERMITS relations."""
    roles: dict[str, set[str]] = {}
    for relation in model.relations:
        if str(relation.kind) != "permits":
            continue
        source = model.entities.get(relation.source_id)
        target = model.entities.get(relation.target_id)
        if source is None or target is None:
            continue
        if str(target.kind) != "endpoint":
            continue
        label = str(source.label or (source.metadata or {}).get("role") or "")
        if label:
            roles.setdefault(str(relation.target_id), set()).add(label)
    return roles


def _endpoint_ownership(model: Any) -> dict[str, str]:
    """endpoint path → resource label when an owner-MODIFIES was observed."""
    ownership: dict[str, str] = {}
    for relation in model.relations:
        if str(relation.kind) != "modifies":
            continue
        meta = relation.metadata or {}
        if str(meta.get("attribute") or "").lower() != "owner":
            continue
        source = model.entities.get(relation.source_id)
        target = model.entities.get(relation.target_id)
        if source is None:
            continue
        path = str((source.metadata or {}).get("path") or "")
        resource = ""
        if target is not None:
            resource = str(target.label or (target.metadata or {}).get("path") or "")
        if path and resource:
            ownership[path] = resource
    return ownership


def _endpoint_id_by_path(model: Any) -> dict[str, str]:
    paths: dict[str, str] = {}
    for entity_id, entity in model.entities.items():
        if str(entity.kind) != "endpoint":
            continue
        path = str((entity.metadata or {}).get("path") or "")
        if path and path not in paths:
            paths[path] = entity_id
    return paths


def answer_five_questions(
    machines: list[StateMachineSpec],
    model: Any,
) -> list[MeasuredAnswer]:
    """The five live-security-model questions, per workflow, measured.

    1. Which state does the resource enter the workflow in?
    2. Which transitions are possible from each state?
    3. What preconditions guard each transition?
    4. Which principals may trigger each transition?
    5. What changes about the resource after each transition?
    """
    roles_by_endpoint = _endpoint_roles(model)
    ownership_by_path = _endpoint_ownership(model)
    endpoint_id_by_path = _endpoint_id_by_path(model)

    answers: list[MeasuredAnswer] = []
    for machine in machines:
        wf = machine.workflow_key
        refs_union: list[str] = []
        for t in machine.transitions:
            for r in t.evidence_refs:
                if r not in refs_union:
                    refs_union.append(r)

        # Q1 — entry state (measured: no observed inbound transition)
        if not machine.transitions:
            answers.append(MeasuredAnswer(
                f"{wf}:Q1",
                "which state does the resource enter the workflow in?",
                "unknown (not observed — no transitions recorded)",
                "no workflow_observations for this workflow",
                (), False,
            ))
        elif machine.entry_states:
            answers.append(MeasuredAnswer(
                f"{wf}:Q1",
                "which state does the resource enter the workflow in?",
                " → ".join(machine.entry_states),
                "states with no observed inbound transition",
                tuple(refs_union[:_MAX_REFS]), True,
            ))
        else:
            answers.append(MeasuredAnswer(
                f"{wf}:Q1",
                "which state does the resource enter the workflow in?",
                "unknown (not observed — every observed state has an "
                "inbound transition; no entry state derivable)",
                "measured in-degree over all observed transitions",
                tuple(refs_union[:_MAX_REFS]), True,
            ))

        # Q2 — adjacency from each state
        adjacency = "; ".join(
            f"{t.from_state} → {t.to_state} (via {t.method or '?'} {t.endpoint or '?'})"
            for t in machine.transitions
        ) or "no transitions observed"
        answers.append(MeasuredAnswer(
            f"{wf}:Q2",
            "which transitions are possible from each state?",
            adjacency,
            "observed TRANSITIONS relations grouped by from_state",
            tuple(refs_union[:_MAX_REFS]), bool(machine.transitions),
        ))

        # Q3 — preconditions per transition
        preconds = "; ".join(
            f"{t.method or '?'} {t.endpoint or '?'}: "
            + (
                f"authorization_boundary={t.authorization_boundary}"
                + (", destructive" if t.destructive else "")
                if t.authorization_boundary != "unknown"
                else "authorization_boundary=unknown (not observed)"
                + (", destructive" if t.destructive else "")
            )
            for t in machine.transitions
        ) or "no transitions observed"
        answers.append(MeasuredAnswer(
            f"{wf}:Q3",
            "what preconditions guard each transition?",
            preconds,
            "authorization_boundary + destructive flag as observed on "
            "each transition record",
            tuple(refs_union[:_MAX_REFS]), bool(machine.transitions),
        ))

        # Q4 — permitted principals per transition
        principal_parts: list[str] = []
        for t in machine.transitions:
            eid = endpoint_id_by_path.get(t.endpoint, "")
            roles = sorted(roles_by_endpoint.get(eid, set()))
            if roles:
                principal_parts.append(
                    f"{t.endpoint or '?'}: roles {', '.join(roles)}")
            else:
                principal_parts.append(
                    f"{t.endpoint or '?'}: unknown (no authorization "
                    "marker observed on this endpoint)")
        answers.append(MeasuredAnswer(
            f"{wf}:Q4",
            "which principals may trigger each transition?",
            "; ".join(principal_parts) or "no transitions observed",
            "PERMITS relations on the trigger endpoint; 'unknown' when "
            "no marker was observed — never guessed",
            tuple(refs_union[:_MAX_REFS]), bool(machine.transitions),
        ))

        # Q5 — resource state before/after (+ ownership evidence)
        change_parts: list[str] = []
        for t in machine.transitions:
            owner = ownership_by_path.get(t.endpoint)
            if owner:
                change_parts.append(
                    f"{t.from_state} → {t.to_state} and the resource's "
                    f"recorded owner may change via {owner} "
                    f"(ownership_change evidence on {t.endpoint})")
            else:
                change_parts.append(
                    f"{t.from_state} → {t.to_state} (no ownership-change "
                    f"evidence observed on {t.endpoint})")
        answers.append(MeasuredAnswer(
            f"{wf}:Q5",
            "what changes about the resource after each transition?",
            "; ".join(change_parts) or "no transitions observed",
            "observed from_state/to_state pairs; ownership attribution "
            "only from recorded ownership_change evidence",
            tuple(refs_union[:_MAX_REFS]), bool(machine.transitions),
        ))
        if len(answers) >= _MAX_ANSWERS:
            break
    return answers


# ---------------------------------------------------------------------------
# A2 — invariant hypothesis mining (reason for belief + preconditions
# + discriminating experiment; NO spec when the premise is unsupported)
# ---------------------------------------------------------------------------

_INVARIANT_VULN_CLASS = {
    "sequence_invariant": "auth_bypass",
    "ownership_invariant": "idor",
    "role_gate_invariant": "privilege_differential",
}


@dataclass(frozen=True)
class InvariantSpec:
    """A mined invariant hypothesis spec (A2), fully attributed."""

    invariant_id: str
    kind: str                      # sequence / ownership / role_gate
    statement: str                 # the CLAIM
    reason_for_belief: str         # WHY the model believes it (evidence)
    preconditions: tuple[str, ...]
    discriminating_experiment: str
    evidence_refs: tuple[str, ...]
    vuln_class: str
    target_path: str


def _observed_transition_support(
    machine: StateMachineSpec,
    skipped_states: list[str],
) -> bool:
    """Premise check: every skipped intermediate state must have BOTH
    an observed inbound and an observed outbound transition — else the
    "skip" is just a linear path fragment and the model has no grounds
    for a sequence invariant (NO SPEC, fail-open forbidden)."""
    if not skipped_states:
        return False
    inbound = {t.to_state for t in machine.transitions}
    outbound = {t.from_state for t in machine.transitions}
    return all(s in inbound and s in outbound for s in skipped_states)


def _direct_transition(
    machine: StateMachineSpec,
    from_state: str,
    to_state: str,
) -> TransitionRecord | None:
    for t in machine.transitions:
        if t.from_state == from_state and t.to_state == to_state:
            return t
    return None


def mine_invariant_hypotheses(model: Any) -> list[InvariantSpec]:
    """Mine invariant hypothesis specs from the SKG (deterministic).

    Same candidate signals as ``researcher.brain.mine_invariants``
    (sequence / ownership / role gate — one SSOT of candidate
    signals), enriched with the research-entity triple the future
    plan §2 demands: reason for belief, preconditions, discriminating
    experiment. A spec whose premise the model cannot support (no
    evidence refs, or a skipped state with no observed transitions on
    both sides) is NOT emitted — a missing spec is correct; an
    unsupported one would be fail-open.
    """
    from webpent.appmodel.skg_queries import workflow_skip_candidates

    machines = extract_state_machine(model)
    specs: list[InvariantSpec] = []

    # -- sequence invariants: observed skips through intermediates ----
    for machine in machines:
        for skip in workflow_skip_candidates(model, machine.workflow_key):
            direct = _direct_transition(
                machine, skip["from_state"], skip["to_state"])
            if direct is None:
                continue  # no direct transition observed — no premise
            if not _observed_transition_support(
                    machine, list(skip.get("skipped_states") or [])):
                continue  # unsupported premise — NO spec (§3 A2 law)
            refs = tuple(direct.evidence_refs)
            if not refs:
                continue  # a spec without evidence would be fail-open
            skipped = ", ".join(skip.get("skipped_states") or [])
            specs.append(InvariantSpec(
                invariant_id=(
                    f"umdr52w1:sequence:{machine.workflow_key}:"
                    f"{skip['from_state']}->{skip['to_state']}"
                ),
                kind="sequence_invariant",
                statement=(
                    f"workflow {machine.workflow_key}: state {skipped} "
                    f"must not be bypassed between {skip['from_state']} "
                    f"and {skip['to_state']}"
                ),
                reason_for_belief=(
                    f"the intermediate state {skipped} is observed "
                    f"(inbound and outbound transitions recorded) while "
                    f"the direct {skip['from_state']}→{skip['to_state']} "
                    f"transition {direct.transition_key or direct.endpoint} "
                    f"was also observed — the model saw both paths"
                ),
                preconditions=(
                    f"resource is in state {skip['from_state']}",
                    f"trigger endpoint {direct.endpoint or '?'} accepts "
                    f"{direct.method or 'POST'}",
                    (
                        f"actor holds the {direct.authorization_boundary} "
                        "boundary on the direct transition"
                        if direct.authorization_boundary != "unknown"
                        else "actor identity unverified on the direct "
                             "transition (authorization_boundary unobserved)"
                    ),
                ),
                discriminating_experiment=(
                    "guarded differential: replay the direct "
                    f"{skip['from_state']}→{skip['to_state']} transition "
                    "as an actor holding the sanctioned boundary and as "
                    "one who does not; negative control replays the "
                    "sanctioned path through the intermediate state; a "
                    "bypass confirms the invariant violation, an "
                    "enforcement refusal refutes it"
                ),
                evidence_refs=refs[:_MAX_REFS],
                vuln_class=_INVARIANT_VULN_CLASS["sequence_invariant"],
                target_path=direct.endpoint,
            ))
            if len(specs) >= _MAX_INVARIANT_SPECS:
                return specs

    # -- ownership invariants: observed owner relations ----------------
    for relation in model.relations:
        if str(relation.kind) != "owns":
            continue
        target = model.entities.get(relation.target_id)
        if target is None or str(target.kind) != "resource":
            continue
        try:
            refs = tuple(str(r) for r in (relation.ref_list() or []))
        except Exception:  # noqa: BLE001 — defensive ref read
            refs = ()
        if not refs:
            continue  # no evidence — NO spec
        source = model.entities.get(relation.source_id)
        owner = str(source.label or "") if source else ""
        specs.append(InvariantSpec(
            invariant_id=f"umdr52w1:ownership:{relation.id}",
            kind="ownership_invariant",
            statement=(
                f"resource {target.label} has a single recorded owner "
                f"({owner}); writes must not change it without the "
                "owner's authority"
            ),
            reason_for_belief=(
                f"the owns relation {relation.id} was observed with "
                f"evidence {', '.join(refs[:3])}"
            ),
            preconditions=(
                f"resource {target.label} exists",
                "actor identity is established by the session profile",
            ),
            discriminating_experiment=(
                "guarded differential: attempt an owner-attributed "
                "write vs the same write as a foreign principal; the "
                "negative control replays the owner's own write"
            ),
            evidence_refs=refs[:_MAX_REFS],
            vuln_class=_INVARIANT_VULN_CLASS["ownership_invariant"],
            target_path=str((target.metadata or {}).get("path") or ""),
        ))
        if len(specs) >= _MAX_INVARIANT_SPECS:
            return specs

    # -- role-gate invariants: observed role permits on write ops ------
    write_ops = {"write", "update", "patch", "delete", "remove", "create",
                 "post", "put"}
    for relation in model.relations:
        if str(relation.kind) != "permits":
            continue
        operation = str((relation.metadata or {}).get("operation") or "").lower()
        if operation not in write_ops:
            continue
        target = model.entities.get(relation.target_id)
        if target is None or str(target.kind) != "endpoint":
            continue
        try:
            refs = tuple(str(r) for r in (relation.ref_list() or []))
        except Exception:  # noqa: BLE001 — defensive ref read
            refs = ()
        if not refs:
            continue  # no evidence — NO spec
        source = model.entities.get(relation.source_id)
        role = str(source.label or "") if source else ""
        path = str((target.metadata or {}).get("path") or "")
        specs.append(InvariantSpec(
            invariant_id=f"umdr52w1:role_gate:{relation.id}",
            kind="role_gate_invariant",
            statement=(
                f"write operation {operation} on {path} requires role "
                f"{role}"
            ),
            reason_for_belief=(
                f"the permits relation {relation.id} was observed with "
                f"evidence {', '.join(refs[:3])}"
            ),
            preconditions=(
                f"endpoint {path} accepts {operation}",
                f"role {role} is the sanctioned principal",
            ),
            discriminating_experiment=(
                "guarded differential: perform the write as the "
                "sanctioned role vs a lesser/foreign role; negative "
                "control repeats the sanctioned write"
            ),
            evidence_refs=refs[:_MAX_REFS],
            vuln_class=_INVARIANT_VULN_CLASS["role_gate_invariant"],
            target_path=path,
        ))
        if len(specs) >= _MAX_INVARIANT_SPECS:
            return specs

    return specs


def invariant_hypotheses(
    specs: list[InvariantSpec],
    target_url: str,
) -> list[Any]:
    """Project invariant specs onto the canonical pool (A2 emission).

    The ONLY path this layer uses to reach the pool is
    ``hypothesis_adapter.canonical_hypothesis`` — the emitted
    hypotheses carry no confirmation authority: they enter the
    strategist's ranking like every other hypothesis and can become
    findings only through the ordinary CausalGuard/ProofBundle route.
    ``deterministic_match`` stays False — an invariant violation is
    NOT a path signature; it needs the live differential.
    """
    from webpent.production.hypothesis_adapter import canonical_hypothesis

    out: list[Any] = []
    for spec in specs:
        blob = uuid5(NAMESPACE_URL, f"webpent:umdr52w1:{spec.invariant_id}")
        out.append(canonical_hypothesis(
            id=blob,
            statement=(
                f"Invariant hypothesis: {spec.statement} — verify with "
                f"the declared discriminating experiment"
            ),
            vuln_class=spec.vuln_class,
            origin="researcher_brain",
            origin_detail=(
                f"UM-DR-52 W1 behavioral invariant; invariant_id="
                f"{spec.invariant_id}; refs={len(spec.evidence_refs)}"
            ),
            target_url=target_url,
            expected_behavior=(
                "the invariant holds: the sanctioned path enforces its "
                "preconditions and the bypass attempt is refused"
            ),
            negative_control=spec.discriminating_experiment,
            deterministic_match=False,
            info_gain=min(
                0.9, 0.3 + 0.2 * max(1, len(spec.evidence_refs))),
            evidence_contract={
                "evidence_refs": list(spec.evidence_refs)[:8],
                "appmodel_hint": {"kind": "behavioral_invariant"},
                "invariant_spec": {
                    "invariant_id": spec.invariant_id,
                    "kind": spec.kind,
                    "reason_for_belief": spec.reason_for_belief,
                    "preconditions": list(spec.preconditions),
                    "discriminating_experiment":
                        spec.discriminating_experiment,
                    "target_path": spec.target_path,
                },
            },
        ))
    return out


# ---------------------------------------------------------------------------
# A3 — behavioral ranking evidence (the synthesis the formula consumes)
# ---------------------------------------------------------------------------

@dataclass
class BehavioralRankingEvidence:
    """Per-campaign behavioral evidence, keyed by endpoint path.

    Deterministic: same model ⇒ same evidence. Empty dicts (no
    behavioral signals) make every consumer term a NO-OP — the
    presence of this object never changes a score by itself.
    """

    transition_density: dict[str, float] = field(default_factory=dict)
    contradiction_backing: dict[str, float] = field(default_factory=dict)
    invariant_backed: dict[str, float] = field(default_factory=dict)
    machine_count: int = 0
    invariant_count: int = 0
    contradiction_count: int = 0
    answer_count: int = 0
    invariant_specs: tuple[InvariantSpec, ...] = ()

    def as_summary(self) -> dict[str, Any]:
        return {
            "machine_count": self.machine_count,
            "transition_endpoints": len(self.transition_density),
            "contradiction_backed_paths": len(self.contradiction_backing),
            "invariant_backed_paths": len(self.invariant_backed),
            "invariant_specs": self.invariant_count,
            "contradictions": self.contradiction_count,
            "measured_answers": self.answer_count,
            "influence_contract": (
                "UM-DR-52 W1: behavioral evidence shifts EIG "
                "(transition density), confidence (contradiction "
                "backing) and impact (invariant-backed write surface) "
                "inside the W3 formula — advisory only; never "
                "authorizes, never confirms, never bypasses CausalGuard"
            ),
        }

    def backing_for(self, target_url: str) -> tuple[float, float, float]:
        """(density, contradiction, invariant) for one target URL.

        Substring/endswith match over the sorted keys (paths are
        shorter than the full URL); MAX over all matches — monotone
        and deterministic, never list-order dependent.
        """
        return (
            self._match(self.transition_density, target_url),
            self._match(self.contradiction_backing, target_url),
            self._match(self.invariant_backed, target_url),
        )

    @staticmethod
    def _match(bucket: dict[str, float], target_url: str) -> float:
        if not bucket or not target_url:
            return 0.0
        best = 0.0
        for key in sorted(bucket):
            if key and (key in target_url or target_url.endswith(key)):
                best = max(best, float(bucket[key]))
        return best


def behavioral_ranking_evidence(model: Any) -> BehavioralRankingEvidence:
    """Build the A3 evidence from the SKG (deterministic, bounded).

    * transition density — observed transitions per trigger endpoint,
      normalised 0.2 + 0.8 × (count / max): an endpoint that drives
      more of the workflow carries more expected information.
    * contradiction backing — recorded evidence-vs-evidence conflicts
      (researcher.brain.detect_contradictions, ``mark=False`` — read
      only) back the confidence of hypotheses targeting the involved
      endpoints.
    * invariant backing — mined invariant specs (A2) mark their
      target endpoint as an invariant-guarded WRITE surface.
    """
    evidence = BehavioralRankingEvidence()
    machines = extract_state_machine(model)
    evidence.machine_count = len(machines)

    counts: dict[str, int] = {}
    for machine in machines:
        for t in machine.transitions:
            if t.endpoint:
                counts[t.endpoint] = counts.get(t.endpoint, 0) + 1
    max_count = max(counts.values(), default=0)
    if max_count > 0:
        evidence.transition_density = {
            path: 0.2 + 0.8 * (count / max_count)
            for path, count in sorted(counts.items())
        }

    try:
        from webpent.researcher.brain import detect_contradictions
        contradictions = detect_contradictions(model, mark=False)
        evidence.contradiction_count = len(contradictions)
        for contradiction in contradictions:
            for entity_id in contradiction.get("entity_ids", []) or []:
                ent = model.entities.get(str(entity_id))
                if ent is None or str(ent.kind) != "endpoint":
                    continue
                path = str((ent.metadata or {}).get("path") or "")
                if not path:
                    continue
                bumped = evidence.contradiction_backing.get(path, 0.0) \
                    + CONTRADICTION_CONFIDENCE
                evidence.contradiction_backing[path] = min(
                    CONTRADICTION_CAP, bumped)
    except Exception as exc:  # noqa: BLE001 — advisory read-only
        logger.debug("behavioral: contradiction evidence unavailable: %s", exc)

    specs = mine_invariant_hypotheses(model)
    evidence.invariant_specs = tuple(specs)
    evidence.invariant_count = len(specs)
    for spec in specs:
        if spec.target_path:
            evidence.invariant_backed[spec.target_path] = 1.0

    evidence.answer_count = len(answer_five_questions(machines, model))
    return evidence
