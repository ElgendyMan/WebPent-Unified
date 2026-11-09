"""Phase-10 diagnostic: run the l10-planner strategy once per L10
DEV entry (both apps, all four variants) and report confirmed
findings plus the deduplicated score, so a suspected false positive
is attributed to the variant and probed path it appeared on."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from l7_failure_analysis import confirmed_entries  # noqa: E402
from l8_discovery_matrix import score_unique  # noqa: E402

from webpent.appsuite import corpus  # noqa: E402
from webpent.egaie import discovery_runner as dr  # noqa: E402
from webpent.egaie.planner import PlannerConfig, StatefulPlanner  # noqa: E402
from webpent.egaie.workflow_discovery import WorkflowDiscovery  # noqa: E402

BUDGET = int(sys.argv[1]) if len(sys.argv) > 1 else 16

for entry in corpus.l10_dev_block():
    with corpus.open_instance(entry) as target:
        port = dr._build_port(target, entry.seed)
        state = dr._seed_state(target, entry.instance_id)
        orch = dr._build_orchestrator(port, "adaptive")
        orch.planner = StatefulPlanner(
            PlannerConfig(), discovery=WorkflowDiscovery())
        result = orch.run(state, max_rounds=BUDGET)
    confirmed = confirmed_entries(result, port)
    score = score_unique(entry, confirmed)
    print(json.dumps({
        "entry": f"{entry.app}/{entry.variant}/{entry.instance_id}",
        "score": score,
    }))
