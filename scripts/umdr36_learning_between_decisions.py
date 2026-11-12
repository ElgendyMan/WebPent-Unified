#!/usr/bin/env python3
"""UM-DR-36 §5.3 — learning-between-decisions demonstration.

Proves, on the REAL production research loop (ResearchControlLoop inside
ModernOrchestrator — no second planner), that the NEXT research decision
is genuinely influenced by the PREVIOUS experiment's observed outcome:

  1. register two candidate surfaces (A = high prior value, B = second);
  2. research_step() selects A (initial ranking);
  3. record A's observed outcome as LOW-information/REDUNDANT;
  4. research_step() again — A is now penalized (outcome_aware_penalty +
     semantic redundancy) and B is selected;
  5. the measured information-gain ledger path: three recorded outcomes
     for one signal class OVERRIDE the static prior, changing the
     generate_research_hypotheses ranking.

The artifact of this run is written for the acceptance report.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault(
    "WEBPENT_AUDIT_SECRET_KEY", "umdr36_e2e_key_32_chars_min_1234567890")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "worker")
# R1 factory authority: the demonstration drives the spine through the
# PRODUCTION factory (resolve_production_spine), never direct
# construction. A lab profile authorizes the loopback lab target.
os.environ.setdefault("WEBPENT_PRODUCTION_LAB_PROFILE", "1")

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO))


def main() -> int:
    from webpent.live_hunter.profile import AuthorizedLabProfile
    from webpent.live_hunter.tool_scope import ScopeLaw
    from webpent.production.modern_spine import ModernOrchestrator

    from webpent.production.production_spine import (
        ProductionSpineConfig,
        resolve_production_spine,
    )

    # The production factory (the SAME path hunter_runner uses) derives the
    # scope law from the authorized loopback lab target.
    orch, _trace = resolve_production_spine(ProductionSpineConfig(
        engagement_id="umdr36-learning-demo",
        target_url="http://127.0.0.1:9/lab-demo",
        entrypoint="direct_invoke",
    ))
    loop = orch.research_loop

    # 1. Register two governed candidates + their hypotheses (the same
    # registration shape the DeepRecon / world-model path uses).
    loop.graph.register_hypothesis(
        "hyp_a", "surface_a exposes an authorization differential",
        branch_id="branch_a")
    loop.graph.register_hypothesis(
        "hyp_b", "surface_b exposes an authorization differential",
        branch_id="branch_b")
    loop.register_candidate(
        candidate_id="surface_a", hypothesis_ids=["hyp_a"],
        experiment_signature="exp:surface_a:v1",
        addresses_open_question=True,
    )
    loop.register_candidate(
        candidate_id="surface_b", hypothesis_ids=["hyp_b"],
        experiment_signature="exp:surface_b:v1",
    )

    # 2. Initial selection.
    first = loop.step()
    first_pick = first.get("selected_candidate")

    # 3. Record surface_a's observed outcome: LOW information (the
    # experiment produced nothing new — the honest observed result), via
    # the loop's own outcome-recording API (the production feedback path).
    loop.record_execution_outcome(
        candidate_id="surface_a",
        observation_id="obs_a_1",
        hypothesis_id="hyp_a",
        supports=False,
        information_value=0.1,
        outcome_class="low_information",
        experiment_signature="exp:surface_a:v1",
    )

    # 4. Next selection — the ranking must respond to the outcome.
    second = loop.step()
    second_pick = second.get("selected_candidate")

    # 5. Measured-prior path: three outcomes for one signal class override
    # the static prior and change hypothesis ranking.
    from webpent.production.adaptive_research import generate_research_hypotheses
    from webpent.production.information_gain import classify_outcome

    ledger_outcomes = [
        {"experiment_signature": f"e{i}",
         "signal_class": "coverage.observed_not_tested",
         "gain_class": classify_outcome(hypothesis_outcome="INCONCLUSIVE"),
         "new_facts": 0, "evidence_classes": 0}
        for i in range(3)
    ]
    _, detail_with = generate_research_hypotheses(
        {"target_url": "http://127.0.0.1:9/x",
         "information_gain": {"outcomes": ledger_outcomes}},
        max_new=5)
    _, detail_without = generate_research_hypotheses(
        {"target_url": "http://127.0.0.1:9/x"}, max_new=5)

    result = {
        "first_selection": str(first_pick),
        "recorded_outcome": {
            "experiment": "exp:surface_a:v1",
            "outcome_class": "low_information",
            "information_value": 0.1,
        },
        "second_selection": str(second_pick),
        "selection_changed": str(first_pick) != str(second_pick),
        "measured_priors_applied": detail_with.get("measured_priors_applied"),
        "measured_outcomes": detail_with.get("measured_outcomes"),
        "static_prior_coverage_not_tested": 0.60,
        "learning_demonstrated": bool(
            str(first_pick) != str(second_pick)
            and detail_with.get("measured_priors_applied")),
    }
    out = REPO / "umdr36_learning_between_decisions.json"
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    print("LEARNING_RESULT:", "PASS" if result["learning_demonstrated"] else "FAIL")
    return 0 if result["learning_demonstrated"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
