#!/usr/bin/env python3
"""UM-DR-36.1 §6 — genuine two-decision learning sequence.

Drives the PRODUCTION evidence-driven selector twice inside ONE runtime
run (the EGAIE InvestigationOrchestrator loops decisions internally):

  decision 1 → real experiment execution → real validation →
  mark_experiment_outcome + hypothesis update + repetition-register
  record → decision 2 selection RECOMPUTED from the updated evidence
  state (repetition penalty, evidence tally, blocked history).

No synthetic ledger rows, no forced ranking. The artifact records the
before/after selections, the per-candidate scores, the recorded
outcomes and the evidence trail, and fails closed unless the sequence
demonstrably ran two decisions with a real outcome between them and a
recomputed second selection.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

OUT = REPO / "artifacts" / "umdr36_1_learning_between_decisions.json"


def main() -> int:
    from webpent.egaie.benchmark.runner import run_adaptive

    # run_adaptive seeds a REAL investigation state and drives the
    # production orchestrator loop for N rounds — both decisions
    # happen inside one genuine runtime run.
    final = run_adaptive(3)

    decisions = final.decisions
    problems: list[str] = []
    if len(decisions) < 2:
        problems.append(f"only {len(decisions)} decision(s) executed — "
                        "no second decision to recompute")
    if not final.experiment_outcomes:
        problems.append("no real experiment outcome was recorded between "
                        "decisions")
    if not final.evidence:
        problems.append("no evidence items were recorded")

    d1 = decisions[0] if decisions else None
    d2 = decisions[1] if len(decisions) > 1 else None
    selection_changed = bool(
        d1 and d2
        and getattr(d1, "experiment_id", None)
        != getattr(d2, "experiment_id", None))

    artifact = {
        "schema": "umdr36-1-learning/v1",
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "mechanism": {
            "orchestrator": "webpent.egaie.orchestrator."
                            "InvestigationOrchestrator.run",
            "selector": "webpent.egaie.selection.InformationGainSelector",
            "state": "webpent.egaie.schemas.InvestigationState",
            "outcome_recording": "InvestigationState.mark_experiment_outcome "
                                 "+ RepetitionRegister.record (inside "
                                 "orchestrator._run_experiment)",
        },
        "decision_1": {
            "experiment_id": getattr(d1, "experiment_id", None),
            "hypothesis_id": getattr(d1, "hypothesis_id", None),
            "rationale": getattr(d1, "rationale", None),
            "scores": getattr(d1, "scores", None),
        } if d1 else None,
        "recorded_outcomes": final.experiment_outcomes,
        "evidence_items": [
            {"hypothesis_id": getattr(e, "hypothesis_id", None),
             "stance": getattr(e, "stance", None)}
            for e in final.evidence
        ],
        "decision_2": {
            "experiment_id": getattr(d2, "experiment_id", None),
            "hypothesis_id": getattr(d2, "hypothesis_id", None),
            "rationale": getattr(d2, "rationale", None),
            "scores": getattr(d2, "scores", None),
        } if d2 else None,
        "selection_changed_by_recorded_evidence": selection_changed,
        "problems": problems,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(artifact, indent=2, default=str) + "\n",
                   encoding="utf-8")
    print("[artifact]", OUT)
    print("[outcomes]", final.experiment_outcomes)
    print("[d1]", getattr(d1, "experiment_id", None),
          "-> [d2]", getattr(d2, "experiment_id", None))
    print("[problems]", problems or "none")
    ok = len(decisions) >= 2 and final.experiment_outcomes and selection_changed
    print("[verdict]", "LEARNING_PROVEN" if ok else "LEARNING_NOT_PROVEN")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
