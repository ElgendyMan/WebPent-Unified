"""Phase-10 diagnostic: dump the planner's own reasoning on one DEV
instance — every event (declared / parked / setup_failed / verified),
the transition needs it derived, and the hop records — to attribute
a miss to a reasoning stage."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from webpent.appsuite import corpus
from webpent.egaie import discovery_runner as dr
from webpent.egaie.planner import PlannerConfig, StatefulPlanner
from webpent.egaie.workflow_discovery import WorkflowDiscovery

INSTANCE = sys.argv[1] if len(sys.argv) > 1 else "pm-181"
BUDGET = int(sys.argv[2]) if len(sys.argv) > 2 else 16

entry = next(e for e in corpus.l10_dev_block()
             if e.instance_id == INSTANCE)

with corpus.open_instance(entry) as target:
    port = dr._build_port(target, entry.seed)
    state = dr._seed_state(target, entry.instance_id)
    orch = dr._build_orchestrator(port, "adaptive")
    planner = StatefulPlanner(PlannerConfig(),
                              discovery=WorkflowDiscovery())
    orch.planner = planner
    result = orch.run(state, max_rounds=BUDGET)

    print("== planner events ==")
    for ev in planner.events:
        print(json.dumps({"kind": ev.kind,
                          "hyp": ev.hypothesis_id,
                          "target": ev.target,
                          "detail": ev.detail}))

    print("\n== hypotheses ==")
    for h in result.hypotheses:
        v = getattr(h, "verdict", None) or {}
        print(json.dumps({
            "hypothesis_id": h.hypothesis_id,
            "family": h.family,
            "status": h.status.value,
            "verdict": v.get("verdict"),
            "disposition": v.get("disposition"),
            "reason": v.get("reason"),
        }))

    print("\n== unattainable ledger entries ==")
    for hyp_id, entry_ in planner.ledger.entries.items():
        for t, rec in (entry_.targets.items()
                       if hasattr(entry_, "targets") else []):
            print(json.dumps({"hyp": hyp_id, "target": t,
                              "rec": str(rec)}))

    print("\n== tally ==")
    print(json.dumps(planner.tally(), indent=2, default=str))
