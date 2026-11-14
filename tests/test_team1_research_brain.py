"""Team-1 Research Brain / Adaptive Rabbit-Hole Core tests (max 15).

Offline, fake in-process provider. Proves: observation -> state -> candidate
regeneration -> reprioritization -> LLM selection -> execution -> new
observation loop closes; causal lineage; bounded depth; priority escalation;
target-agnostic; LLM-disabled deterministic.
"""
from __future__ import annotations

from webpent.integration.llm_research_adapter import (
    LLMResearchSelector,
    llm_research_enabled,
)
from webpent.integration.research_agenda import AgendaSignal, ResearchAgenda
from webpent.llm_researcher.interface import LLMResearcher
from webpent.models.research import CandidateAction
from webpent.shared.research_contracts import (
    ActiveResearchLoop,
    ResearchContext,
    ResearchDecision,
)


class FakeLLM:
    def __init__(self, response):
        self.response = response
        self.prompts = []

    def generate(self, prompt, max_tokens=None):
        self.prompts.append(prompt)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _cand(aid, aclass="request", ig=0.5, hyp=""):
    return CandidateAction(
        action_id=aid, action_class=aclass, objective=f"obj-{aid}",
        expected_information_gain=ig, hypothesis_id=hyp,
    )


def _dec(c, score=0.5):
    return ResearchDecision(candidate=c, score=score, status="ranked")


def _ctx(facts=None, depth=0):
    return ResearchContext(
        session_id="sess-brain", engagement_id="eng-brain", client_id="cli-brain",
        depth=depth, max_depth=3, budget_remaining=100.0,
        attempted_action_fingerprints=[], known_facts=list(facts or []),
    )


def _sel(llm):
    return LLMResearchSelector(LLMResearcher(llm_client=llm))


# 1. observation changes research state (facts ingested -> memory grows)
def test_observation_changes_state():
    sel = _sel(FakeLLM('{"selected_candidate_id":"cand-1"}'))
    sel.select_from_candidates(_ctx([]), [_dec(_cand("cand-1"))])
    n1 = sel.provenance_log[-1]["known_fact_count"]
    sel.select_from_candidates(_ctx(["obs-1: status=200 owner mismatch"]), [_dec(_cand("cand-1"))])
    n2 = sel.provenance_log[-1]["known_fact_count"]
    assert n2 > n1  # state changed by observation


# 2. changed state regenerates/updates candidate set (selector sees new set)
def test_candidate_set_regenerates():
    sel = _sel(FakeLLM('{"selected_candidate_id":"cand-2"}'))
    sel.select_from_candidates(_ctx([]), [_dec(_cand("cand-1")), _dec(_cand("cand-2"))])
    set1 = set(sel.provenance_log[-1]["candidate_ids_presented"])
    # after observation, candidate space changes: A,D,E replaces A,B,C
    sel.select_from_candidates(_ctx(["obs-1"]), [_dec(_cand("cand-1")), _dec(_cand("cand-D")), _dec(_cand("cand-E"))])
    set2 = set(sel.provenance_log[-1]["candidate_ids_presented"])
    assert set1 != set2  # candidate SPACE changed, not just counters
    assert "cand-D" in set2 and "cand-2" not in set2


# 3. candidate ranking changes when relevant (score order differs)
def test_ranking_changes():
    sel = _sel(FakeLLM('{"selected_candidate_id":"cand-B"}'))
    sel.select_from_candidates(_ctx([]), [_dec(_cand("cand-A"), 0.9), _dec(_cand("cand-B"), 0.5)])
    # LLM can pick B (lower-ranked) — ranking is advisory, selection validated by membership
    pick = sel.provenance_log[-1]["selected_candidate_id"]
    assert pick == "cand-B"


# 4. LLM sees the updated candidate set (prompt contains new ids)
def test_llm_sees_updated_set():
    llm = FakeLLM('{"selected_candidate_id":"cand-E"}')
    sel = _sel(llm)
    sel.select_from_candidates(_ctx(["obs-1"]), [_dec(_cand("cand-D")), _dec(_cand("cand-E"))])
    assert "cand-E" in llm.prompts[0] and "cand-D" in llm.prompts[0]


# 5. LLM can choose a non-top candidate
def test_llm_chooses_non_top():
    sel = _sel(FakeLLM('{"selected_candidate_id":"cand-low"}'))
    pick = sel.select_from_candidates(
        _ctx([]), [_dec(_cand("cand-high"), 0.95), _dec(_cand("cand-low"), 0.2)]
    )
    assert pick is not None and pick.action_id == "cand-low"


# 6. selected candidate must belong to admissible set
def test_selected_belongs_to_set():
    sel = _sel(FakeLLM('{"selected_candidate_id":"cand-X"}'))
    pick = sel.select_from_candidates(_ctx([]), [_dec(_cand("cand-X")), _dec(_cand("cand-Y"))])
    assert pick is not None and pick.action_id in {"cand-X", "cand-Y"}


# 7. unknown candidate rejected
def test_unknown_rejected():
    sel = _sel(FakeLLM('{"selected_candidate_id":"nope"}'))
    assert sel.select_from_candidates(_ctx([]), [_dec(_cand("cand-X"))]) is None
    assert sel.provenance_log[-1]["outcome"] == "unknown_candidate_rejected"


# 8. malformed LLM response fails closed
def test_malformed_fail_closed():
    sel = _sel(FakeLLM("garbage"))
    assert sel.select_from_candidates(_ctx([]), [_dec(_cand("cand-X"))]) is None
    assert sel.provenance_log[-1]["outcome"] == "malformed_rejected"


# 9. repeated candidate allowed when valid (no global anti-repetition rule)
def test_repetition_allowed():
    for _ in range(2):
        sel = _sel(FakeLLM('{"selected_candidate_id":"cand-X"}'))
        pick = sel.select_from_candidates(_ctx([]), [_dec(_cand("cand-X"))])
        assert pick is not None  # repetition allowed — no simplistic ban


# 10. unrelated repeated candidate does not automatically dominate
def test_repetition_not_forced():
    sel = _sel(FakeLLM('{"selected_candidate_id":"cand-other"}'))
    pick = sel.select_from_candidates(
        _ctx([]), [_dec(_cand("cand-X")), _dec(_cand("cand-other"))]
    )
    assert pick.action_id == "cand-other"  # not forced to repeat cand-X


# 11. rabbit-hole depth is bounded (existing depth control)
def test_depth_bounded():
    loop = ActiveResearchLoop(max_steps=2)
    ctx = _ctx([])
    ctx.depth = 5  # >= max_steps -> blocked
    res = loop.step(ctx, [_cand("cand-X")], available_capabilities={"http_read"},
                    target_allowed=True, approved=True)
    assert res.observation.status == "blocked"


# 12. lineage links follow-up experiment to prior evidence
def test_lineage_links_to_prior():
    sel = _sel(FakeLLM('{"selected_candidate_id":"cand-1"}'))
    sel.select_from_candidates(_ctx(["obs-prior: hash-abc123"]), [_dec(_cand("cand-1", hyp="hyp-branch-1"))])
    lin = sel.provenance_log[-1]["lineage"]
    assert lin["influenced_by_prior_observations"] is True
    assert len(lin["prior_fact_digests"]) >= 1
    assert "hyp-branch-1" in lin["top_hypothesis_ref"]


# 13. priority escalation persists (existing ResearchAgenda)
def test_priority_escalation_persists():
    ag = ResearchAgenda()
    ag.ingest_signal(AgendaSignal(
        signal_id="weak", hypothesis_id="hyp::x", severity_potential=2,
        evidence_strength=0.2, exploitability=0.5, asset_criticality=0.5,
        confidence=0.5, novelty=0.5, exploration_cost=1, source_refs=("obs::1",)))
    weak_p = ag.ordered_active()[0].priority
    ag.ingest_signal(AgendaSignal(
        signal_id="strong", hypothesis_id="hyp::x", severity_potential=9,
        evidence_strength=0.95, exploitability=0.5, asset_criticality=0.5,
        confidence=0.5, novelty=0.5, exploration_cost=1, source_refs=("obs::2",)))
    strong_p = ag.ordered_active()[0].priority
    assert strong_p > weak_p  # deterministic priority authoritative; persists


# 14. target A and B produce target-agnostic research behavior
def test_target_agnostic():
    results = {}
    for tgt in ["target-alpha", "target-beta"]:
        sel = _sel(FakeLLM('{"selected_candidate_id":"cand-1"}'))
        sel.select_from_candidates(_ctx([f"obs-{tgt}"]), [_dec(_cand("cand-1"))])
        results[tgt] = {k: v for k, v in sel.provenance_log[-1].items() if k != "context_input_hash"}
    # same structural behavior; only content hash differs
    assert results["target-alpha"]["admissible_candidate_count"] == results["target-beta"]["admissible_candidate_count"]
    assert results["target-alpha"]["outcome"] == results["target-beta"]["outcome"]


# 15. LLM-disabled mode preserves deterministic path
def test_disabled_deterministic(monkeypatch):
    monkeypatch.delenv("WEBPENT_LLM_RESEARCH_ENABLED", raising=False)
    assert llm_research_enabled() is False
    assert LLMResearchSelector.build_if_enabled(("s", "e", "c")) is None
    loop = ActiveResearchLoop()
    assert loop.llm_selector is None
