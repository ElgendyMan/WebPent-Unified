"""Offline ABHC v3 benchmark with conservative six-class accounting.

The runner reads a previously recorded artifact only.  It never contacts a
network target and never manufactures observations, findings, or metrics.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CLASSES = (
    "idor",
    "privilege_escalation",
    "business_logic",
    "information_disclosure",
    "authentication_boundary",
    "workflow_state_boundary",
)


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("source_artifact_must_be_object")
    return data


def _case_entries(source: dict[str, Any]) -> list[dict[str, Any]]:
    containers: tuple[dict[str, Any], ...] = (source,)
    evaluation = source.get("evaluation")
    if isinstance(evaluation, dict):
        containers = (source, evaluation)
    for container in containers:
        for key in ("cases", "results", "scenarios", "case_results"):
            value = container.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _class_of(case: dict[str, Any]) -> str:
    value = (
        case.get("class")
        or case.get("vulnerability_class")
        or case.get("category")
        or case.get("type")
    )
    normalized = str(value).lower().replace(" ", "_") if value else ""
    aliases = {
        "business_logic_authorization": "business_logic",
        "workflow": "workflow_state_boundary",
        "state_boundary": "workflow_state_boundary",
    }
    return aliases.get(normalized, normalized)


def _is_complete(case: dict[str, Any]) -> bool:
    explicit_flags = ("causal_signal", "negative_control", "proof_bundle", "replay_status")
    if all(bool(case.get(flag)) for flag in explicit_flags):
        return True
    return (
        case.get("validation_outcome") == "confirmed"
        and case.get("ground_truth_outcome") == "confirmed"
        and case.get("proof_complete") is True
        and bool(case.get("ground_truth_source"))
        and case.get("hypothesis_generated") is True
    )


def build_report(source_path: Path) -> dict[str, Any]:
    source = _load(source_path)
    entries = _case_entries(source)
    complete_classes: set[str] = set()
    recorded_case_ids: list[str] = []
    for case in entries:
        category = _class_of(case)
        if category in CLASSES and _is_complete(case):
            complete_classes.add(category)
            recorded_case_ids.append(str(case.get("case_id", case.get("id", "unlabelled"))))
    classes: list[dict[str, Any]] = []
    for category in CLASSES:
        if category in complete_classes:
            classes.append(
                {
                    "class": category,
                    "status": "SCORABLE_FROM_RECORDED_ARTIFACT",
                    "scorable": True,
                    "case_count": sum(
                        1 for case in entries if _class_of(case) == category and _is_complete(case)
                    ),
                    "reason": (
                        "complete recorded causal/control/proof/replay evidence "
                        "or equivalent sealed historical fields found"
                    ),
                }
            )
        else:
            classes.append(
                {
                    "class": category,
                    "status": "BLOCKED",
                    "scorable": False,
                    "case_count": 0,
                    "reason": (
                        "no complete recorded causal candidate/control/proof/replay "
                        "evidence for this class"
                    ),
                }
            )
    return {
        "benchmark_id": "ABHC-v3-six-class-controlled-offline",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_artifact": str(source_path),
        "source_artifact_read_only": True,
        "classes": classes,
        "recorded_complete_case_ids": sorted(set(recorded_case_ids)),
        "execution": {
            "offline": True,
            "requests_sent": 0,
            "credentials_used": False,
            "mutations_performed": False,
            "external_targets_contacted": False,
        },
        "metrics": {
            "registered_class_count": len(CLASSES),
            "scorable_class_count": sum(item["scorable"] for item in classes),
            "blocked_class_count": sum(not item["scorable"] for item in classes),
            "precision": None,
            "recall": None,
            "f1": None,
            "real_world_detection_rate": None,
            "research_depth": None,
            "adaptive_efficiency": None,
            "reason_unavailable": (
                "recorded artifact does not establish an independent ABHC ground truth "
                "and multi-run denominator"
            ),
        },
        "governance": {
            "official_isolated_p10_runs_authorized": False,
            "p10_status": "NOT_QUALIFIED",
            "p9_status": "NOT_QUALIFIED",
            "vip_status": "NOT_QUALIFIED",
            "bug_bounty_status": "BLOCKED",
            "qualification_effect": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-artifact",
        type=Path,
        default=Path("reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(args.source_artifact)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report["metrics"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
