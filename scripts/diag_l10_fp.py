"""Phase-10 diagnostic: dump the confirmed experiments' probe
evidence on one DEV instance to attribute a suspected false
positive to its surface observation (never to fixture knowledge)."""
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
from scripts.l7_failure_analysis import confirmed_entries

INSTANCE = sys.argv[1] if len(sys.argv) > 1 else "cs-171"
BUDGET = int(sys.argv[2]) if len(sys.argv) > 2 else 16

entry = next(e for e in corpus.l10_dev_block()
             if e.instance_id == INSTANCE)

with corpus.open_instance(entry) as target:
    port = dr._build_port(target, entry.seed)
    state = dr._seed_state(target, entry.instance_id)
    orch = dr._build_orchestrator(port, "adaptive")
    orch.planner = StatefulPlanner(PlannerConfig(),
                                   discovery=WorkflowDiscovery())
    result = orch.run(state, max_rounds=BUDGET)

    print("== confirmed entries ==")
    confirmed = confirmed_entries(result, port)
    for ent in confirmed:
        print(json.dumps(ent))

    for ent in confirmed:
        exp = next((e for e in result.experiments
                    if e.hypothesis_id == ent["hypothesis_id"]), None)
        if exp is None:
            continue
        print(f"\n== {exp.experiment_id} ({ent['family']}) "
              f"verdict={getattr(exp, 'verdict', '?')} ==")
        plan = port.plan_for(exp.signature)
        for step in plan.steps:
            print(json.dumps({
                "label": step.label, "method": step.method,
                "path": step.path, "actor": step.actor,
                "params": dict(step.params or {})}))
        obs = next((o for o in reversed(result.observations)
                    if o.get("experiment_id") == exp.experiment_id),
                   None)
        if obs is None:
            continue
        for role in ("baseline", "candidate", "control"):
            comp = obs.get(role) or {}
            for step in comp.get("steps") or ():
                rec = {
                    "role": role,
                    "label": step.get("label"),
                    "method": step.get("method"),
                    "path": step.get("path"),
                    "actor": step.get("actor"),
                    "status": step.get("status"),
                }
                st = step.get("structured")
                if isinstance(st, dict):
                    rec["state"] = st.get(port.bindings.state_field)
                    rec["applied"] = st.get(
                        port.bindings.applied_field)
                    rec["owner"] = st.get(port.bindings.owner_field)
                    rec["tby"] = st.get(
                        port.bindings.transitioned_by_field)
                print(json.dumps(rec))
