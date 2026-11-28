"""UM-DR-52 W1 — the Behavioral & Business-Logic Reasoning layer.

Contract under test (future plan.md §3):

* A1 — State Transition Discovery: the state machine (states,
  transitions, preconditions, resource state before/after) is
  EXTRACTED from evidence, and the five live-security-model
  questions are answered BY MEASUREMENT with evidence refs —
  unobserved facts answer "unknown (not observed)", never invented;
* A2 — InvariantHypothesis mining: every spec carries its reason for
  belief, its preconditions and its discriminating experiment; a
  premise the model cannot support means NO spec (fail-open
  forbidden); emission goes through the canonical adapter path and
  carries no confirmation authority;
* A3 — Behavioral Hypothesis Synthesis: the brain-gated ranking
  consumes behavioral evidence (transition density → EIG,
  contradiction backing → confidence, invariant-backed write surface
  → impact) so the OFF/ON delta appears in ORDER and in OUTCOMES —
  pool-only is a failure verdict by law (§6 G5);
* authority isolation — the layer performs no I/O, grants nothing,
  confirms nothing, never bypasses CausalGuard/ProofBundle/Replay.

The approved lab is the SKG fixture (tests.test_umdr46_phase_a_skg):
the order-approval workflow with the planted pending→approved skip
that bypasses the observed review state.
"""

from __future__ import annotations

import inspect
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from tests.test_umdr46_phase_a_skg import BASE, _lab_state

FASTTRACK = f"{BASE}/api/orders/123/fasttrack"
SKIP_SPEC_ID = "umdr52w1:sequence:order-approval:pending->approved"


def _settings() -> Any:
    from webpent.config.settings import get_settings
    return get_settings()


def _mk(hid: str, vc: str, conf: float, target: str, ig: float | None = None):
    from webpent.production.hypothesis_adapter import canonical_hypothesis
    return canonical_hypothesis(
        id=uuid5(NAMESPACE_URL, f"umdr52w1t:{hid}"),
        statement=f"W1 fixture hypothesis {hid}",
        vuln_class=vc,
        origin="heuristic",
        origin_detail="umdr52 w1 test",
        target_url=target,
        expected_behavior="sanctioned path enforces its preconditions",
        negative_control="replay through the sanctioned intermediate state",
        deterministic_match=False,
        confidence_score=conf,
        info_gain=ig,
    )


def _pool_for_fixture() -> list:
    """The three-hypothesis ranking pool: a low-confidence behavioral
    case on the planted skip, a plain IDOR read, an ownership change."""
    return [
        _mk("lowconf-skip", "auth_bypass", 0.2, FASTTRACK),
        _mk("plain-admin-read", "idor", 0.5, f"{BASE}/api/admin/invoices/900"),
        _mk("transfer", "idor", 0.55, f"{BASE}/api/orders/789/transfer"),
    ]


# ---------------------------------------------------------------------------
# A1 — state transition discovery
# ---------------------------------------------------------------------------

class TestA1StateMachine:
    def test_state_machine_extracted_from_evidence(self) -> None:
        from webpent.researcher.behavioral_layer import extract_state_machine
        state = _lab_state()
        from webpent.appmodel.skg import build_security_knowledge_graph
        model = build_security_knowledge_graph(state)
        machines = extract_state_machine(model)
        assert len(machines) == 1
        m = machines[0]
        assert m.workflow_key == "order-approval"
        assert m.states == ("approved", "pending", "review")
        assert m.measured is True
        keys = {t.transition_key for t in m.transitions}
        assert keys == {"submit", "approve", "fasttrack"}
        # every transition is evidence-ref'd — nothing enters the
        # machine without its observation record
        for t in m.transitions:
            assert t.evidence_refs, f"{t.transition_key} carries no evidence"
        # entry state = measured in-degree zero
        assert m.entry_states == ("pending",)

    def test_skip_transition_recorded_with_its_boundary(self) -> None:
        from webpent.researcher.behavioral_layer import extract_state_machine
        from webpent.appmodel.skg import build_security_knowledge_graph
        m = extract_state_machine(build_security_knowledge_graph(_lab_state()))[0]
        direct = [t for t in m.transitions if t.transition_key == "fasttrack"]
        assert len(direct) == 1
        t = direct[0]
        assert (t.from_state, t.to_state) == ("pending", "approved")
        assert t.authorization_boundary == "unknown"
        assert t.evidence_refs == ("wf-3",)

    def test_five_questions_answered_by_measurement(self) -> None:
        from webpent.researcher.behavioral_layer import (
            answer_five_questions,
            extract_state_machine,
        )
        from webpent.appmodel.skg import build_security_knowledge_graph
        model = build_security_knowledge_graph(_lab_state())
        answers = answer_five_questions(extract_state_machine(model), model)
        assert len(answers) == 5
        by_q = {a.question_id.split(":")[-1]: a for a in answers}
        # Q1: entry state is measured, not declared
        assert by_q["Q1"].measured is True
        assert by_q["Q1"].answer == "pending"
        # Q2: the adjacency includes the planted skip
        assert "pending → approved (via POST /api/orders/123/fasttrack)" \
            in by_q["Q2"].answer
        assert by_q["Q2"].measured is True
        # Q3: the unobserved boundary says UNKNOWN — never invented
        assert "authorization_boundary=unknown (not observed)" in by_q["Q3"].answer
        assert "authorization_boundary=role_scoped" in by_q["Q3"].answer
        # Q4: no authz marker on the workflow endpoints → unknown
        assert ("unknown (no authorization marker observed on this endpoint)"
                in by_q["Q4"].answer)
        # Q5: the state change is the measured from→to pair
        assert "pending → approved" in by_q["Q5"].answer
        # every answer names its basis and its evidence refs
        for a in answers:
            assert a.basis
            assert a.evidence_refs, f"{a.question_id} carries no evidence"

    def test_answers_deterministic(self) -> None:
        from webpent.researcher.behavioral_layer import (
            answer_five_questions,
            extract_state_machine,
        )
        from webpent.appmodel.skg import build_security_knowledge_graph
        model = build_security_knowledge_graph(_lab_state())
        first = answer_five_questions(extract_state_machine(model), model)
        second = answer_five_questions(extract_state_machine(model), model)
        assert [a.__dict__ for a in first] == [a.__dict__ for a in second]


# ---------------------------------------------------------------------------
# A2 — invariant mining: reason for belief + preconditions + experiment
# ---------------------------------------------------------------------------

class TestA2Invariants:
    def _specs(self) -> list:
        from webpent.researcher.behavioral_layer import mine_invariant_hypotheses
        from webpent.appmodel.skg import build_security_knowledge_graph
        return mine_invariant_hypotheses(
            build_security_knowledge_graph(_lab_state()))

    def test_sequence_spec_carries_the_research_triple(self) -> None:
        specs = self._specs()
        seq = [s for s in specs if s.kind == "sequence_invariant"]
        assert len(seq) == 1
        s = seq[0]
        assert s.invariant_id == SKIP_SPEC_ID
        assert "review" in s.statement and "pending" in s.statement
        # the reason for belief cites BOTH observed paths
        assert "observed" in s.reason_for_belief
        assert s.preconditions and all(s.preconditions)
        assert "differential" in s.discriminating_experiment
        assert s.evidence_refs == ("wf-3",)
        assert s.vuln_class == "auth_bypass"
        assert s.target_path == "/api/orders/123/fasttrack"

    def test_ownership_spec_mined_from_observed_relation(self) -> None:
        specs = self._specs()
        own = [s for s in specs if s.kind == "ownership_invariant"]
        assert len(own) == 1
        s = own[0]
        assert s.vuln_class == "idor"
        assert "orders" in s.statement
        assert s.evidence_refs  # belief backed by evidence, always
        assert "differential" in s.discriminating_experiment

    def test_unsupported_promise_yields_no_spec(self) -> None:
        # the premise check is a pure function of the extracted
        # machine: an intermediate state without BOTH an observed
        # inbound and outbound transition supports NO spec
        from webpent.researcher.behavioral_layer import (
            StateMachineSpec,
            TransitionRecord,
            _observed_transition_support,
        )
        machine = StateMachineSpec(
            workflow_key="wf",
            states=("a", "b"),
            transitions=(
                TransitionRecord(
                    "wf", "t1", "/x", "POST", "a", "b", "unknown",
                    False, ("r-1",)),
            ),
            entry_states=("a",),
            measured=True,
        )
        assert _observed_transition_support(machine, ["b"]) is False
        assert _observed_transition_support(machine, ["ghost"]) is False

    def test_empty_model_mines_nothing(self) -> None:
        # fail-closed: no evidence ⇒ no specs, no behavioral signals —
        # the layer never invents a hypothesis from nothing
        from webpent.researcher.behavioral_layer import (
            behavioral_ranking_evidence,
            mine_invariant_hypotheses,
        )
        from webpent.appmodel.skg import build_security_knowledge_graph
        model = build_security_knowledge_graph({"crawled_data": {}})
        assert mine_invariant_hypotheses(model) == []
        ev = behavioral_ranking_evidence(model)
        assert ev.invariant_count == 0
        assert not ev.transition_density
        assert not ev.contradiction_backing

    def test_emission_uses_the_canonical_path(self) -> None:
        from webpent.researcher.behavioral_layer import invariant_hypotheses
        hyps = invariant_hypotheses(self._specs(), BASE)
        assert len(hyps) == 2
        for h in hyps:
            assert str(h.origin) == "researcher_brain"
            assert h.deterministic_match is False
            contract = h.evidence_contract
            assert contract["appmodel_hint"] == {"kind": "behavioral_invariant"}
            spec = contract["invariant_spec"]
            assert spec["reason_for_belief"] and spec["preconditions"]
            assert h.negative_control == spec["discriminating_experiment"]


# ---------------------------------------------------------------------------
# A3 — the ranking consumes behavioral evidence: ORDER + OUTCOMES
# ---------------------------------------------------------------------------

class TestA3OrderDelta:
    def test_behavioral_terms_change_the_rank_order(self, monkeypatch) -> None:
        from webpent.shared.prioritization import rank_open_hypotheses
        state = _lab_state()
        pool = _pool_for_fixture()
        settings = _settings()
        monkeypatch.setattr(settings, "enable_brain_engine", False)
        ranked_off = [str(h.id) for h, _s in rank_open_hypotheses(pool, state)]
        monkeypatch.setattr(settings, "enable_brain_engine", True)
        ranked_on = [str(h.id) for h, _s in rank_open_hypotheses(pool, state)]
        assert ranked_off != ranked_on, "OFF/ON order delta is REQUIRED (G5)"
        # the low-confidence behavioral case rises to rank 1 in ON:
        # the skip endpoint drives the workflow, is contradiction-
        # backed and invariant-backed — the evidence lifts it
        lowconf = next(h for h in pool if h.target_url == FASTTRACK
                       and h.confidence_score == 0.2)
        assert ranked_on[0] == str(lowconf.id)

    def test_off_ranking_never_touches_the_brain_path(self, monkeypatch) -> None:
        import webpent.production.brain_engine as be
        from webpent.shared.prioritization import rank_open_hypotheses

        def _boom(*_a: Any, **_k: Any) -> Any:
            raise AssertionError("the OFF ranking entered the brain path")

        monkeypatch.setattr(_settings(), "enable_brain_engine", False)
        monkeypatch.setattr(be, "build_brain_context", _boom)
        monkeypatch.setattr(be, "rank_with_brain", _boom)
        ranked = rank_open_hypotheses(_pool_for_fixture(), _lab_state())
        assert len(ranked) == 3

    def test_no_behavioral_signals_means_no_op(self, monkeypatch) -> None:
        # a model without workflow/contradiction/invariant signals:
        # the behavioral object exists but every formula term is a
        # no-op — identical scores with and without it
        from webpent.production.brain_engine import (
            BrainPriorityContext,
            brain_priority,
            estimate_priority_inputs,
        )
        state = {"crawled_data": {"openapi_routes": [
            {"method": "GET", "path": "/api/plain"},
        ]}}
        ctx = BrainPriorityContext()
        from webpent.appmodel.skg import build_security_knowledge_graph
        model = build_security_knowledge_graph(state)
        ctx.model = model
        ctx.built = True
        from webpent.researcher.behavioral_layer import (
            behavioral_ranking_evidence,
        )
        ctx.behavioral = behavioral_ranking_evidence(model)
        assert not ctx.behavioral.transition_density
        assert not ctx.behavioral.contradiction_backing
        assert not ctx.behavioral.invariant_backed
        from webpent.production.hypothesis_adapter import canonical_hypothesis
        h = canonical_hypothesis(
            id=uuid5(NAMESPACE_URL, "umdr52w1t:plain"),
            statement="plain endpoint read", vuln_class="idor",
            origin="heuristic", origin_detail="t",
            target_url=f"{BASE}/api/plain", expected_behavior="x",
            negative_control="y", deterministic_match=False,
            confidence_score=0.4,
        )
        inputs_with = estimate_priority_inputs(h, ctx)
        ctx_none = BrainPriorityContext(model=model, built=True, behavioral=None)
        inputs_without = estimate_priority_inputs(h, ctx_none)
        assert inputs_with == inputs_without
        assert brain_priority(h, ctx) == brain_priority(h, ctx_none)


class TestA3Outcomes:
    def test_outcome_flips_across_a_decision_boundary(self, monkeypatch) -> None:
        """The measured OUTCOME delta: the SAME hypothesis abandons on
        the legacy scale and survives (DEFER) on the brain scale —
        the behavioral evidence carried it across the boundary."""
        from webpent.shared.prioritization import (
            PrioritizationAction,
            rank_open_hypotheses,
            recommend_action,
        )
        state = _lab_state()
        h = _mk("boundary-skip", "auth_bypass", 0.05, FASTTRACK, ig=0.1)
        settings = _settings()
        monkeypatch.setattr(settings, "enable_brain_engine", True)
        ranked = rank_open_hypotheses([h], state)
        priority = ranked[0][1]
        act_off, score_off, rule_off = recommend_action(h, state)
        act_on, score_on, rule_on = recommend_action(
            h, state, priority_score=priority)
        assert act_off == PrioritizationAction.ABANDON, (
            f"fixture drifted: legacy action {act_off} score {score_off}")
        assert act_on == PrioritizationAction.DEFER
        assert "brain-priority-mapped" in rule_on
        assert "brain-priority-mapped" not in rule_off

    def test_idor_guard_holds_even_in_brain_mode(self, monkeypatch) -> None:
        from webpent.shared.prioritization import (
            PrioritizationAction,
            rank_open_hypotheses,
            recommend_action,
        )
        state = _lab_state()
        h = _mk("idor-skip", "idor", 0.2, FASTTRACK, ig=0.1)
        settings = _settings()
        monkeypatch.setattr(settings, "enable_brain_engine", True)
        ranked = rank_open_hypotheses([h], state)
        priority = ranked[0][1]
        act_on, _s, rule_on = recommend_action(h, state, priority_score=priority)
        assert act_on == PrioritizationAction.DEFER
        assert "IDOR/BAC promotion guard" in rule_on

    def test_decision_map_monotone_and_bounded(self) -> None:
        from webpent.shared.prioritization import _brain_decision_score
        assert _brain_decision_score(0.0) == 0.0
        k = 0.15
        assert abs(_brain_decision_score(k) - 0.5) < 1e-9
        assert _brain_decision_score(1e6) < 1.0
        grid = [0.001, 0.01, 0.05, 0.1, 0.15, 0.3, 1.0, 10.0]
        scores = [_brain_decision_score(p) for p in grid]
        assert scores == sorted(scores), "map must be monotone"
        assert all(0.0 <= s < 1.0 for s in scores)

    def test_legacy_path_byte_comparable(self, monkeypatch) -> None:
        # no priority_score ⇒ the legacy weighted score and rule text,
        # unchanged — the OFF arm never sees the map
        from webpent.shared.prioritization import recommend_action
        state = _lab_state()
        h = _mk("boundary-skip", "auth_bypass", 0.05, FASTTRACK, ig=0.1)
        act, score, rule = recommend_action(h, state)
        assert act.value == "abandon"
        assert "brain-priority-mapped" not in rule
        assert rule.startswith("score=")


class TestA3AuthorityIsolation:
    def test_behavioral_layer_has_no_confirmation_authority(self) -> None:
        # structural: the module constructs no Finding, imports no
        # verifier gate, calls no promotion — advisory by construction.
        # (Prose mentions in docstrings are the NEGATIVE declaration;
        # these patterns are the authority-USAGE checks.)
        import webpent.researcher.behavioral_layer as bl
        src = inspect.getsource(bl)
        assert "Finding(" not in src
        assert "promote_confirmed" not in src
        assert "guarded_causal" not in src
        assert "verify_finding" not in src
        assert "from webpent.models.findings" not in src
        assert "from webpent.guard" not in src
        assert "from webpent.validation" not in src
        # the public surface is advisory-only by name and count
        assert set(bl.__all__) == {
            "StateMachineSpec", "TransitionRecord", "MeasuredAnswer",
            "InvariantSpec", "BehavioralRankingEvidence",
            "extract_state_machine", "answer_five_questions",
            "mine_invariant_hypotheses", "invariant_hypotheses",
            "behavioral_ranking_evidence",
        }

    def test_node_summary_records_the_behavioral_channel(
        self, monkeypatch,
    ) -> None:
        from webpent.production.brain_engine import brain_engine_node
        monkeypatch.setattr(_settings(), "enable_brain_engine", True)
        summary = brain_engine_node(_lab_state())["brain_engine"]
        behavioral = summary.get("behavioral") or {}
        assert behavioral.get("machine_count") == 1
        assert behavioral.get("measured_answers") == 5
        assert behavioral.get("invariant_specs") == 2
        assert behavioral.get("contradictions") >= 1
        assert "never bypasses CausalGuard" in behavioral["influence_contract"]

    def test_node_emits_invariant_hypotheses_into_the_pool(
        self, monkeypatch,
    ) -> None:
        from webpent.production.brain_engine import brain_engine_node
        monkeypatch.setattr(_settings(), "enable_brain_engine", True)
        hyps = brain_engine_node(_lab_state())["hypotheses"]
        invariant_hyps = [
            h for h in hyps
            if (h.evidence_contract or {}).get("appmodel_hint")
            == {"kind": "behavioral_invariant"}
        ]
        assert len(invariant_hyps) == 2
        for h in invariant_hyps:
            assert str(h.origin) == "researcher_brain"
            assert h.deterministic_match is False
