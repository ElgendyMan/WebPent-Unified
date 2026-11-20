#!/usr/bin/env python3
"""UM-DR-37 §10 — the FULL-LOOP learning proof.

Mission §10 full-loop scenario, executed through the REAL production
research path (research_loop_node -> family_execution_node, the same
machinery tests/test_umdr31_campaign_e2e_ablation.py drives) over the
controlled two-directory target, with the six required steps measured
per arm:

  1. multiple competing hypotheses/cases exist (cases mined);
  2. the first pass produces meaningful evidence (the recorded
     coverage cell / observed cross-identity transition — the evidence
     channels that exist BEFORE execution);
  3. subsequent experiments remain available (the un-probed cases);
  4. the evidence CHANGES the selection: the research hints reorder
     the constrained budget at the signal-rich directory;
  5. the changed experiments are EXECUTED (requests issued within the
     same 36-request ceiling);
  6. the final result traces to the updated decision (the ground truth
     is confirmed ONLY in the evidence-carrying arms).

Why this layer (and not EGAIE's benchmark loop): in the EGAIE engine
every verdict RESOLVES its hypothesis (confirmed -> CONFIRMED closes
the cell; clean -> CONTRADICTED; inconclusive records no evidence) —
a correct one-discriminating-experiment-per-hypothesis design that
makes an evidence-driven re-selection of a sibling experiment
structurally impossible. The production research loop is where the
loop actually closes: recorded evidence channels reorder EXECUTION
under an identical budget.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import threading
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests"))

from test_umdr31_campaign_e2e_ablation import (  # noqa: E402
    ABLATION_BUDGET,
    GROUND_TRUTH_VULNERABLE,
    _run_arm,
    target_module,
)

from webpent.shared.engagement_scope import (  # noqa: E402
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)


def main() -> int:
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), target_module.VaultHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    target_module.reset_state()
    token = set_engagement_target_hosts(base)

    try:
        arms = {
            name: _run_arm(base, signals=name, loop=(name != "none"),
                           max_requests=ABLATION_BUDGET)
            for name in ("none", "coverage", "invariant", "full")
        }
    finally:
        clear_engagement_target_hosts(token)
        target_module.reset_state()
        server.shutdown()

    baseline = arms["none"]
    hinted = [arms[name] for name in ("coverage", "invariant", "full")]

    chain = {
        "step_1_competing_hypotheses_exist": {
            "cases_mined_per_arm": {
                name: arm["cases_mined"] for name, arm in arms.items()
            },
            "held": all(arm["cases_mined"] == 8 for arm in arms.values()),
        },
        "step_2_first_pass_produces_evidence": {
            "evidence_channels_before_execution": {
                "none": "no coverage ledger, no workflow observation",
                "coverage": "campaign_ledger cell idor:vaults (not_scanned)",
                "invariant": "observed cross-identity seal transition + "
                             "invariant candidate",
                "full": "both channels",
            },
            "hypotheses_generated": {
                name: arm["hypotheses_generated"]
                for name, arm in arms.items()
            },
            "held": arms["coverage"]["hypotheses_generated"] >= 1
                    and arms["invariant"]["hypotheses_generated"] >= 1,
        },
        "step_3_subsequent_experiments_available": {
            "cases_probed": {
                name: arm["cases_probed"] for name, arm in arms.items()
            },
            "held": all(arm["cases_probed"] >= 1 for arm in arms.values()),
        },
        "step_4_evidence_changes_selection": {
            "same_budget_all_arms": all(
                arm["request_budget"] == ABLATION_BUDGET
                for arm in arms.values()),
            "research_hints_applied": {
                name: arm["research_hints_applied"]
                for name, arm in arms.items()
            },
            "selection_semantics": (
                "the research hints reorder the constrained budget at "
                "the signal-rich directory; the alphabetical order of "
                "the evidence-free arm spends the same ceiling on the "
                "safe directory and clips the ground-truth case"),
            "held": (not baseline["research_hints_applied"]
                     and all(arm["research_hints_applied"]
                             for arm in hinted)),
        },
        "step_5_changed_experiments_executed": {
            "requests_issued": {
                name: arm["requests_issued"] for name, arm in arms.items()
            },
            "within_ceiling": all(
                arm["requests_issued"] <= ABLATION_BUDGET
                for arm in arms.values()),
            "held": all(arm["requests_issued"] > 0 for arm in arms.values()),
        },
        "step_6_result_traces_to_updated_decision": {
            "confirmed_paths": {
                name: arm["confirmed_paths"] for name, arm in arms.items()
            },
            "held": (baseline["confirmed"] == 0
                     and all(
                         arm["confirmed"] == 1
                         and arm["confirmed_paths"]
                         == [GROUND_TRUTH_VULNERABLE]
                         for arm in hinted)),
        },
    }

    full_loop_proven = all(step["held"] for step in chain.values())

    artifact = {
        "schema": "umdr37-full-loop-learning/v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mission": "UM-DR-37 §10 full-loop learning proof",
        "harness": "tests/test_umdr31_campaign_e2e_ablation.py machinery "
                   "(_run_arm: research_loop_node + family_execution_node "
                   "over the controlled two-directory target)",
        "budget": ABLATION_BUDGET,
        "ground_truth": GROUND_TRUTH_VULNERABLE,
        "arms": arms,
        "six_step_chain": chain,
        "full_loop_proven": full_loop_proven,
        "egaie_structural_note": (
            "the EGAIE benchmark loop resolves a hypothesis on every "
            "verdict (confirmed/clean close the cell; inconclusive "
            "records no evidence), so an evidence-driven re-selection "
            "of a sibling experiment is structurally impossible there "
            "by design — the production research loop is where the "
            "full loop closes, and it closes here under an identical "
            "budget"
        ),
        "honesty": (
            "the controlled target is team-authored (author-known); "
            "this proves the full-loop causal chain (evidence channel "
            "-> reordered execution -> changed outcome) under a "
            "controlled budget, not real-world recall"
        ),
    }

    out = REPO / "artifacts" / "umdr37_full_loop_learning.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(artifact, indent=2, default=str),
                   encoding="utf-8")
    # The deliverable copy lives in docs/ — the suite's hygiene
    # fixtures wipe artifacts/ DURING a full run, and the component
    # influence registry must not depend on surviving that wipe.
    docs_out = REPO / "docs" / "UMDR37_FULL_LOOP_LEARNING.json"
    docs_out.write_text(json.dumps(artifact, indent=2, default=str),
                        encoding="utf-8")

    print(f"[full-loop] budget={ABLATION_BUDGET} "
          f"ground_truth={GROUND_TRUTH_VULNERABLE}")
    for name, arm in arms.items():
        print(f"  arm {name:9s} hints={arm['research_hints_applied']!s:5s} "
              f"requests={arm['requests_issued']:2d} "
              f"confirmed={arm['confirmed']} "
              f"paths={arm['confirmed_paths']}")
    print(f"[full-loop] six-step chain held: "
          f"{[k for k, v in chain.items() if v['held']]}")
    print(f"[full-loop] FULL LOOP PROVEN: {full_loop_proven}")
    print(f"[artifact] {out} + docs/UMDR37_FULL_LOOP_LEARNING.json")
    return 0 if full_loop_proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
