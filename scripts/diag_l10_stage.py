"""Phase-10 diagnostic: which reasoning stage drops the L10
identity probes? Wraps the validation port and the orchestrator's
remediation to trace one strategy-B run end-to-end on each DEV app."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from webpent.appsuite import corpus
from webpent.egaie import discovery_runner as dr
from webpent.egaie import orchestrator as orch_mod
from webpent.egaie.differential import (
    DISPOSITION_ACTION_BLOCKED,
    VERDICT_INCONCLUSIVE,
)
from webpent.egaie.planner import PlannerConfig, StatefulPlanner
from webpent.egaie.workflow_discovery import WorkflowDiscovery

INSTANCE = sys.argv[1] if len(sys.argv) > 1 else "cs-171"
BUDGET = int(sys.argv[2]) if len(sys.argv) > 2 else 16

entry = next(e for e in corpus.l10_dev_block()
             if e.instance_id == INSTANCE)

events: list[dict] = []

class TracedValidator:
    def __init__(self, inner):
        self.inner = inner

    def validate(self, baseline, candidate, control):
        causal = self.inner.validate(baseline, candidate, control)
        events.append({
            "kind": "validate",
            "verdict": causal.get("verdict"),
            "disposition": causal.get("disposition"),
            "reason": (causal.get("reason") or "")[:160],
        })
        return causal

    def __getattr__(self, name):
        return getattr(self.inner, name)

orig_remediate = orch_mod.InvestigationOrchestrator._remediate

def traced_remediate(self, experiment):
    events.append({
        "kind": "remediate-enter",
        "experiment": experiment.experiment_id,
        "family": experiment.family,
    })
    result = orig_remediate(self, experiment)
    events.append({
        "kind": "remediate-exit",
        "experiment": experiment.experiment_id,
        "returned_setup": result is not None,
    })
    return result

orch_mod.InvestigationOrchestrator._remediate = traced_remediate

with corpus.open_instance(entry) as target:
    port = dr._build_port(target, entry.seed)
    state = dr._seed_state(target, entry.instance_id)
    orch = dr._build_orchestrator(port, "adaptive")
    orch.validation_port = TracedValidator(orch.validation_port)
    orch.planner = StatefulPlanner(PlannerConfig(),
                                   discovery=WorkflowDiscovery())
    result = orch.run(state, max_rounds=BUDGET)

for ev in events:
    print(json.dumps(ev))

print("\n--- proposals by round ---")
for rec in result.proposal_log:
    fams = {}
    for exp_id in rec["experiment_ids"]:
        exp = next(e for e in result.experiments
                   if e.experiment_id == exp_id)
        fams[exp.family] = fams.get(exp.family, 0) + 1
    print(f"round {rec['round']}: {len(rec['experiment_ids'])} "
          f"proposals {fams}")

print("\n--- experiments: family / hypothesis / outcome ---")
for exp in result.experiments:
    out = result.experiment_outcomes.get(exp.experiment_id)
    print(f"{exp.experiment_id:28s} {exp.family:22s} "
          f"hyp={exp.hypothesis_id or '-':10s} outcome={out}")

print("\n--- hypothesis statuses ---")
for h in result.hypotheses:
    print(f"{h.hypothesis_id:28s} {h.family:22s} {h.status.value}")

print("\n--- planner tally ---")
print(json.dumps(orch.planner.ledger.tally(), indent=2))
print("\n--- discovery tally ---")
print(json.dumps(
    orch.planner.discovery.tally() if orch.planner.discovery
    else {}, indent=2))
