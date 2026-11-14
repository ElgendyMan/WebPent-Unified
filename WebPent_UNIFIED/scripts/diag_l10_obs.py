"""Dump the candidate/control composites of the WORKFLOW_IDENTITY
experiments on cs-171 to see why the 409 tally-gate refusal is not
classified as a state-machine refusal."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from webpent.appsuite import corpus
from webpent.egaie import discovery_runner as dr
from webpent.egaie.planner import PlannerConfig, StatefulPlanner
from webpent.egaie.workflow_discovery import WorkflowDiscovery

entry = next(e for e in corpus.l10_dev_block()
             if e.instance_id == "cs-171")

with corpus.open_instance(entry) as target:
    port = dr._build_port(target, entry.seed)
    state = dr._seed_state(target, entry.instance_id)
    orch = dr._build_orchestrator(port, "adaptive")
    orch.planner = StatefulPlanner(PlannerConfig(),
                                   discovery=WorkflowDiscovery())
    result = orch.run(state, max_rounds=16)

for obs in result.observations:
    exp_id = obs["experiment_id"]
    exp = next(e for e in result.experiments
               if e.experiment_id == exp_id)
    if exp.family != "WORKFLOW_IDENTITY":
        continue
    print(f"\n===== {exp_id} =====")
    for role in ("baseline", "candidate", "control"):
        comp = obs[role] or {}
        print(f"--- {role} ---")
        print(json.dumps(comp, indent=1, default=str)[:3000])
