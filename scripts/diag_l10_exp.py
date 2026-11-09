"""Phase-10 diagnostic: dump every experiment's verdict, disposition
and judge reason on one DEV instance, plus the pool-survey plan's
executed steps, to attribute a miss to a reasoning stage."""
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

    for exp in result.experiments:
        verdict = getattr(exp, "verdict", None)
        print(json.dumps({
            "experiment_id": exp.experiment_id,
            "hypothesis_id": exp.hypothesis_id,
            "family": getattr(exp, "family", "?"),
            "verdict": verdict,
        }))
    print("\n== observations ==")
    for obs in result.observations:
        exp_id = obs.get("experiment_id")
        comp = obs.get("candidate") or {}
        steps = comp.get("steps") or []
        rec = {"experiment_id": exp_id, "candidate_steps": len(steps)}
        for role in ("baseline", "candidate", "control"):
            c = obs.get(role) or {}
            rec[role] = [
                {"label": s.get("label"), "method": s.get("method"),
                 "path": s.get("path"), "actor": s.get("actor"),
                 "status": s.get("status_code"),
                 "state": (s.get("structured") or {}).get("state"),
                 "applied": (s.get("structured") or {}).get("applied"),
                 "owner": (s.get("structured") or {}).get("owner"),
                 "tby": (s.get("structured") or {}).get(
                     "transitioned_by"),
                 "pool": (s.get("structured") or {}).get("desk")}
                for s in (c.get("steps") or [])]
        print(json.dumps(rec))
