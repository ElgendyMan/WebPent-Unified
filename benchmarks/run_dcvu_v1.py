from __future__ import annotations

import json
from pathlib import Path

from webpent.dcvu import (
    AutonomousDcvCampaign,
    attach_metrics,
    build_default_fixtures,
    build_ground_truth_registry,
)


def main() -> None:
    fixtures = build_default_fixtures()
    registry = build_ground_truth_registry(fixtures)
    run, traces = AutonomousDcvCampaign().run(fixtures, registry)
    attach_metrics(run)
    report = {
        "report_id": "dcvu-v1-autonomous-bug-hunter-capability",
        "scope": "local_disposable_in_process_fixtures_only",
        "qualification_claim": False,
        "official_isolated_p10_runs_authorized": False,
        "governance": run.governance,
        "targets": [
            {
                "target_id": target.target_id,
                "version": target.version,
                "source_digest": target.source_digest,
                "local_only": target.local_only,
                "disposable": target.disposable,
            }
            for target in run.targets
        ],
        "campaign": {
            "run_id": run.run_id,
            "target_count": len(run.targets),
            "case_count": len(run.cases),
            "evaluation_count": len(run.evaluations),
            "traces": [trace.__dict__ for trace in traces],
        },
        "metrics": [metric.__dict__ for metric in run.metrics],
        "verdict_counts": {
            verdict.value: sum(item.verdict is verdict for item in run.evaluations)
            for verdict in {item.verdict for item in run.evaluations}
        },
        "limitations": [
            "Fixture-backed offline evidence is not field detection quality.",
            "Synthetic identities are not real credentials and no login was performed.",
            (
                "No network, external target, state mutation, finding creation, or qualification "
                "effect occurred."
            ),
            (
                "Metrics are engineering validation results and do not qualify P10, P9, VIP, or "
                "bug bounty access."
            ),
        ],
    }
    output = Path(__file__).parents[1] / "reports" / "evaluation" / "dcvu_v1_capability_report.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
