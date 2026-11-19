"""FV Phase 2 item-4 probe: outcome/evidence changes next ranking (real API).

Uses the exact seam smart_campaigns uses: ResearchDecisionEngine.score()
with experiment_outcome_tracker= (semantic redundancy adjustment).
"""
from __future__ import annotations

import json
import os
import sys

TREE = "/home/z/my-project/verify/tree/webpent-goed"
sys.path.insert(0, os.path.join(TREE, "src"))
os.chdir(TREE)
os.environ["WEBPENT_LLM_ENABLED"] = "false"

from webpent.llm_researcher.experiment_outcome_tracker import (  # noqa: E402
    ExperimentOutcome,
    ExperimentOutcomeTracker,
    InformationValue,
)
from webpent.models.research import CandidateAction  # noqa: E402
from webpent.shared.research_contracts import ResearchDecisionEngine  # noqa: E402

EVIDENCE: dict = {}

engine = ResearchDecisionEngine()
tracker = ExperimentOutcomeTracker()


def cand(action_id: str, sig_meta: dict) -> CandidateAction:
    return CandidateAction(
        action_id=action_id,
        action_class="parameter_probe",
        objective="probe the id parameter for reflective content",
        target_ref="http://127.0.0.1:9/item?id=1",
        capability="http_read",
        expected_information_gain=0.7,
        metadata=sig_meta,
    )


c_a = cand(
    "cand-A",
    {
        "request_details": {
            "path": "/item",
            "query": {"id": "1"},
            "caller_identity": "anonymous",
        },
        "branch_id": "b1",
    },
)
c_b = cand(
    "cand-B",
    {
        "request_details": {
            "path": "/order",
            "query": {"ref": "2"},
            "caller_identity": "anonymous",
        },
        "branch_id": "b2",
    },
)
from webpent.llm_researcher.semantic_fingerprint import (  # noqa: E402
    semantic_fingerprint_from_candidate,
)

fp_a = semantic_fingerprint_from_candidate(c_a)
fp_b = semantic_fingerprint_from_candidate(c_b)
assert fp_a and fp_b and fp_a != fp_b, "fingerprints must derive and differ"
EVIDENCE["fingerprint_A"] = fp_a[:80]
EVIDENCE["fingerprint_B"] = fp_b[:80]

# Baseline (no history)
d_a0 = engine.score(c_a)
d_b0 = engine.score(c_b)
EVIDENCE["baseline"] = {
    "A": d_a0.score,
    "B": d_b0.score,
    "A_reasons": list(d_a0.reasons)[:4],
}

# Record 6 redundant (no-new-information) repeats for A's derived fingerprint
for i in range(6):
    tracker.record(
        ExperimentOutcome(
            semantic_fingerprint=fp_a,
            new_facts_count=0,
            new_observation_added=False,
            information_value=InformationValue.REDUNDANT,
            decision_sequence=i + 1,
        )
    )

d_a1 = engine.score(c_a, experiment_outcome_tracker=tracker)
d_b1 = engine.score(c_b, experiment_outcome_tracker=tracker)
EVIDENCE["after_outcomes"] = {
    "A": d_a1.score,
    "B": d_b1.score,
    "A_reasons": list(d_a1.reasons)[:6],
    "A_penalties": list(d_a1.penalties)[:6] if hasattr(d_a1, "penalties") else None,
}
EVIDENCE["redundancy_factor_A"] = tracker.semantic_redundancy_factor(fp_a)
EVIDENCE["redundancy_factor_B"] = tracker.semantic_redundancy_factor(fp_b)

dropped = float(d_a1.score) < float(d_a0.score)
reason_flagged = any("semantic_redundancy" in str(r) for r in (d_a1.reasons or []))
EVIDENCE["A_score_dropped_after_outcomes"] = dropped
EVIDENCE["A_flagged_semantic_redundancy"] = reason_flagged
EVIDENCE["B_unaffected"] = abs(float(d_b1.score) - float(d_b0.score)) < 1e-9

ok = dropped and reason_flagged and EVIDENCE["B_unaffected"]
EVIDENCE["verdict"] = "PASS" if ok else "FAIL"

with open("/home/z/my-project/verify/results/fv_phase2_outcome_ranking.json", "w") as f:
    json.dump(EVIDENCE, f, indent=2, default=str)
print(json.dumps(EVIDENCE, indent=2, default=str))
raise SystemExit(0 if ok else 1)
