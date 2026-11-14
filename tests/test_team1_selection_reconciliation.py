"""Team-1 Selection Bottleneck reconciliation tests (Phase 8).

Verifies accepted generic features (semantic fingerprint, outcome tracker,
redundancy-aware ranking) and rejects forcing heuristics. Fake in-process.
"""
from __future__ import annotations

from webpent.llm_researcher.experiment_outcome_tracker import (
    ExperimentOutcome,
    ExperimentOutcomeTracker,
    InformationValue,
)
from webpent.llm_researcher.semantic_fingerprint import semantic_fingerprint_from_candidate
from webpent.models.research import CandidateAction


def _cand(aid, url_path="/api/x", actor="anonymous", branch="br-1", method="GET"):
    return CandidateAction(
        action_id=aid, action_class="request", objective=f"probe {aid}",
        method=method, target_ref=f"https://t.local{url_path}",
        identity_context=actor, metadata={"branch_id": branch},
    )


# 1. Same URL / different actor -> different fingerprint (legitimate repetition)
def test_same_url_different_actor_different_fp():
    fp1 = semantic_fingerprint_from_candidate(_cand("cand1", actor="anonymous"))
    fp2 = semantic_fingerprint_from_candidate(_cand("cand2", actor="admin"))
    assert fp1 != fp2  # repetition across actors is NOT redundant


# 2. Same URL / same actor -> same fingerprint (redundancy detectable)
def test_same_url_same_actor_same_fp():
    fp1 = semantic_fingerprint_from_candidate(_cand("cand1", actor="anonymous"))
    fp2 = semantic_fingerprint_from_candidate(_cand("cand2", actor="anonymous"))
    assert fp1 == fp2


# 3. Same URL / different parameter -> different fingerprint
def test_same_url_different_param_different_fp():
    fp1 = semantic_fingerprint_from_candidate(_cand("cand1", method="GET"))
    fp2 = semantic_fingerprint_from_candidate(_cand("cand2", method="POST"))
    assert fp1 != fp2


# 4. Different branch / same capability -> different fingerprint
def test_different_branch_different_fp():
    fp1 = semantic_fingerprint_from_candidate(_cand("cand1", branch="br-A"))
    fp2 = semantic_fingerprint_from_candidate(_cand("cand2", branch="br-B"))
    assert fp1 != fp2


# 5. Redundancy factor decreases after execution (but never blocks)
def test_redundancy_factor_decreases_not_blocks():
    t = ExperimentOutcomeTracker()
    fp = semantic_fingerprint_from_candidate(_cand("cand1"))
    f1 = t.semantic_redundancy_factor(fp)
    t.record(ExperimentOutcome(semantic_fingerprint=fp, information_value=InformationValue.LOW, evidence_classes=set()))
    f2 = t.semantic_redundancy_factor(fp)
    assert f2 < f1
    assert f2 > 0  # never zero — repetition remains possible


# 6. Unresolved-questions benefit increases score
def test_unresolved_questions_benefit():
    t = ExperimentOutcomeTracker()
    fp = semantic_fingerprint_from_candidate(_cand("cand1", branch="br-1"))
    b = t.unresolved_questions_benefit(fp, ["who owns resource X?"])
    assert b >= 1.0


# 7. Novel candidate vs redundant high-IG: redundant adjusted but selectable
def test_novel_vs_redundant_selectable():
    t = ExperimentOutcomeTracker()
    fp_redundant = semantic_fingerprint_from_candidate(_cand("cand1"))
    t.record(ExperimentOutcome(semantic_fingerprint=fp_redundant, information_value=InformationValue.LOW, evidence_classes=set()))
    f = t.semantic_redundancy_factor(fp_redundant)
    assert 0 < f < 1.0  # adjusted down, but > 0 (not forbidden)


# 8. No forcing: top candidate NOT always primary (selection_signals rejected)
def test_no_top_candidate_forcing():
    import webpent.llm_researcher as pkg
    assert not hasattr(pkg, "selection_signals")  # rejected module not present


# 9. CausalGuard unchanged (no evidence_context leak path)
def test_causal_guard_unchanged():
    import webpent.cqa_v2.causal_guard as cg
    src = open(cg.__file__).read()
    assert "normalized_context" not in src  # Team-2 leak path reverted


# 10. Secret/context exposure: candidate metadata never reaches prompt
def test_no_secret_in_prompt():
    from webpent.integration.llm_research_adapter import LLMResearchSelector
    from webpent.llm_researcher.interface import LLMResearcher
    from webpent.shared.research_contracts import ResearchContext, ResearchDecision

    class FakeLLM:
        def __init__(self):
            self.prompts = []
        def generate(self, prompt, max_tokens=None):
            self.prompts.append(prompt)
            return '{"selected_candidate_id":"cand-safe"}'

    llm = FakeLLM()
    sel = LLMResearchSelector(LLMResearcher(llm_client=llm))
    c = CandidateAction(
        action_id="cand-safe", action_class="request", objective="probe",
        metadata={"authorization": "Bearer secret-token", "cookie": "session=abc"},
    )
    ctx = ResearchContext(
        session_id="sess-x", engagement_id="eng-x", client_id="cli-x",
        depth=0, max_depth=10, budget_remaining=100.0,
        attempted_action_fingerprints=[], known_facts=[],
    )
    sel.select_from_candidates(ctx, [ResearchDecision(candidate=c, score=0.5, status="ranked")])
    prompt = llm.prompts[0]
    assert "Bearer" not in prompt and "secret-token" not in prompt and "session=abc" not in prompt
